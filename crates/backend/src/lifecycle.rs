use std::process::ExitCode;
use std::time::Duration;

use coauth_templates::Templates;
use futures_util::future::BoxFuture;
#[cfg(unix)]
use futures_util::future::Either;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::handlers::ActivityTracker;

/// A helper to manage the lifecycle of the service, including handling graceful
/// shutdowns and configuration reloads.
///
/// It will listen for SIGTERM and SIGINT signals, and will trigger a soft
/// shutdown on the first signal, and a hard shutdown on the second signal or
/// after a timeout.
///
/// Users of this manager should use the `soft_shutdown_token` to react to a
/// soft shutdown, which should gracefully finish requests and close
/// connections, and the `hard_shutdown_token` to react to a hard shutdown,
/// which should drop all connections and finish all requests.
///
/// They should also use the `task_tracker` to make it track things running, so
/// that it knows when the soft shutdown is over and worked.
///
/// It also integrates with [`sd_notify`] to notify the service manager of the
/// state of the service (Unix only).
pub struct LifecycleManager {
    hard_shutdown_token: CancellationToken,
    soft_shutdown_token: CancellationToken,
    task_tracker: TaskTracker,
    #[cfg(unix)]
    sigterm: tokio::signal::unix::Signal,
    #[cfg(unix)]
    sigint: tokio::signal::unix::Signal,
    #[cfg(unix)]
    sighup: tokio::signal::unix::Signal,
    /// Grace period after the first shutdown signal before the hard shutdown
    /// token is fired.
    timeout: Duration,
    /// Additional grace period after the hard shutdown is fired, used to drain
    /// the task tracker before we log a warning and return from `run`.
    hard_timeout: Duration,
    /// Bound on how long `join_all(reload_handlers)` may run before we
    /// log a warning and continue accepting traffic.
    reload_timeout: Duration,
    reload_handlers: Vec<Box<dyn Fn() -> BoxFuture<'static, ()>>>,
}

/// Represents a thing that can be reloaded with a SIGHUP
pub trait Reloadable: Clone + Send {
    fn reload(&self) -> impl Future<Output = ()> + Send;
}

impl Reloadable for ActivityTracker {
    async fn reload(&self) {
        self.flush().await;
    }
}

impl Reloadable for Templates {
    async fn reload(&self) {
        if let Err(err) = self.reload().await {
            tracing::error!(
                error = &err as &dyn std::error::Error,
                "Failed to reload templates"
            );
        }
    }
}

/// A wrapper around [`sd_notify::notify`] that logs any errors (no-op on
/// non-Unix)
#[cfg(unix)]
fn notify(states: &[sd_notify::NotifyState]) {
    if let Err(e) = sd_notify::notify(states) {
        tracing::error!(
            error = &e as &dyn std::error::Error,
            "Failed to notify service manager"
        );
    }
}

impl LifecycleManager {
    /// Create a new shutdown manager, installing the signal handlers
    ///
    /// # Errors
    ///
    /// Returns an error if the signal handler could not be installed
    pub fn new() -> Result<Self, std::io::Error> {
        let hard_shutdown_token = CancellationToken::new();
        let soft_shutdown_token = hard_shutdown_token.child_token();
        let timeout = Duration::from_mins(1);
        let hard_timeout = Duration::from_secs(30);
        let reload_timeout = Duration::from_secs(30);
        let task_tracker = TaskTracker::new();

        #[cfg(unix)]
        let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        #[cfg(unix)]
        let sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        #[cfg(unix)]
        let sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

        #[cfg(unix)]
        notify(&[sd_notify::NotifyState::MainPid(std::process::id())]);

        Ok(Self {
            hard_shutdown_token,
            soft_shutdown_token,
            task_tracker,
            #[cfg(unix)]
            sigterm,
            #[cfg(unix)]
            sigint,
            #[cfg(unix)]
            sighup,
            timeout,
            hard_timeout,
            reload_timeout,
            reload_handlers: Vec::new(),
        })
    }

    /// Override the grace period after the first shutdown signal before the
    /// hard shutdown token fires. Default: 60s.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the grace period after the hard shutdown token fires before
    /// `run` returns. Default: 30s.
    #[must_use]
    pub fn with_hard_timeout(mut self, timeout: Duration) -> Self {
        self.hard_timeout = timeout;
        self
    }

    /// Override the reload handler timeout. If a single SIGHUP reload handler
    /// takes longer than this, `run` logs a warning and resumes serving.
    /// Default: 30s.
    #[must_use]
    pub fn with_reload_timeout(mut self, timeout: Duration) -> Self {
        self.reload_timeout = timeout;
        self
    }

    /// Add a handler to be called when the server gets a SIGHUP
    pub fn register_reloadable(&mut self, reloadable: &(impl Reloadable + 'static)) {
        let reloadable = reloadable.clone();
        self.reload_handlers.push(Box::new(move || {
            let reloadable = reloadable.clone();
            Box::pin(async move { reloadable.reload().await })
        }));
    }

    /// Get a reference to the task tracker
    #[must_use]
    pub fn task_tracker(&self) -> &TaskTracker {
        &self.task_tracker
    }

    /// Get a cancellation token that can be used to react to a hard shutdown
    #[must_use]
    pub fn hard_shutdown_token(&self) -> CancellationToken {
        self.hard_shutdown_token.clone()
    }

    /// Get a cancellation token that can be used to react to a soft shutdown
    #[must_use]
    pub fn soft_shutdown_token(&self) -> CancellationToken {
        self.soft_shutdown_token.clone()
    }

    /// Run until we finish completely shutting down.
    pub async fn run(self) -> ExitCode {
        #[cfg(unix)]
        let mut state = self;
        #[cfg(not(unix))]
        let state = self;

        #[cfg(unix)]
        notify(&[sd_notify::NotifyState::Ready]);

        // This will be `Some` if we have the watchdog enabled, and `None` if not
        #[cfg(unix)]
        let mut watchdog_interval = {
            if let Some(watchdog_duration) = sd_notify::watchdog_enabled() {
                Some(tokio::time::interval(watchdog_duration / 2))
            } else {
                None
            }
        };

        // Wait for a first shutdown signal and trigger the soft shutdown.
        // Each branch breaks, so this is structurally a loop with one
        // execution; the `loop` shape lets us conditionally compile
        // branches under `#[cfg(unix)]` while keeping a single value
        // assignment.
        #[allow(clippy::never_loop)]
        let likely_crashed = loop {
            #[cfg(unix)]
            {
                // This makes a Future that will either yield the watchdog tick if enabled, or a
                // pending Future if not
                let watchdog_tick = if let Some(watchdog_interval) = &mut watchdog_interval {
                    Either::Left(watchdog_interval.tick())
                } else {
                    Either::Right(futures_util::future::pending())
                };

                tokio::select! {
                    () = state.soft_shutdown_token.cancelled() => {
                        tracing::warn!("Another task triggered a shutdown, it likely crashed! Shutting down");
                        break true;
                    },

                    _ = state.sigterm.recv() => {
                        tracing::info!("Shutdown signal received (SIGTERM), shutting down");
                        break false;
                    },

                    _ = state.sigint.recv() => {
                        tracing::info!("Shutdown signal received (SIGINT), shutting down");
                        break false;
                    },

                    _ = watchdog_tick => {
                        notify(&[
                            sd_notify::NotifyState::Watchdog,
                        ]);
                    },

                    _ = state.sighup.recv() => {
                        tracing::info!("Reload signal received (SIGHUP), reloading");

                        notify(&[
                            sd_notify::NotifyState::Reloading,
                            sd_notify::NotifyState::monotonic_usec_now()
                                .expect("Failed to read monotonic clock")
                        ]);

                        // Reload handlers run concurrently. A single blocked
                        // handler must not stall signal processing; if the set
                        // does not finish within `reload_timeout`, we log and
                        // return to serving traffic.
                        let reload_fut = futures_util::future::join_all(
                            state.reload_handlers
                                .iter()
                                .map(|handler| handler()),
                        );
                        if tokio::time::timeout(state.reload_timeout, reload_fut)
                            .await
                            .is_err()
                        {
                            tracing::warn!(
                                timeout_secs = state.reload_timeout.as_secs(),
                                "Reload handlers did not finish in time, proceeding"
                            );
                        }

                        notify(&[sd_notify::NotifyState::Ready]);

                        tracing::info!("Reloading done");
                    },
                }
            }

            #[cfg(not(unix))]
            {
                tokio::select! {
                    () = state.soft_shutdown_token.cancelled() => {
                        tracing::warn!("Another task triggered a shutdown, it likely crashed! Shutting down");
                        break true;
                    },

                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("Shutdown signal received (Ctrl+C), shutting down");
                        break false;
                    },
                }
            }
        };

        #[cfg(unix)]
        notify(&[sd_notify::NotifyState::Stopping]);

        state.soft_shutdown_token.cancel();
        state.task_tracker.close();

        // Start the timeout
        let timeout = tokio::time::sleep(state.timeout);

        #[cfg(unix)]
        tokio::select! {
            _ = state.sigterm.recv() => {
                tracing::warn!("Second shutdown signal received (SIGTERM), abort");
            },
            _ = state.sigint.recv() => {
                tracing::warn!("Second shutdown signal received (SIGINT), abort");
            },
            () = timeout => {
                tracing::warn!("Shutdown timeout reached, abort");
            },
            () = state.task_tracker.wait() => {
                // This is the "happy path", we have gracefully shutdown
            },
        }

        #[cfg(not(unix))]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::warn!("Second shutdown signal received (Ctrl+C), abort");
            },
            () = timeout => {
                tracing::warn!("Shutdown timeout reached, abort");
            },
            () = state.task_tracker.wait() => {
                // This is the "happy path", we have gracefully shutdown
            },
        }

        state.hard_shutdown_token().cancel();

        // Give remaining tasks a bounded grace period before forcing exit.
        if tokio::time::timeout(state.hard_timeout, state.task_tracker().wait())
            .await
            .is_err()
        {
            tracing::warn!(
                timeout_secs = state.hard_timeout.as_secs(),
                "Task tracker did not drain in time, proceeding with exit"
            );
        }

        tracing::info!("All tasks are done, exitting");

        if likely_crashed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    }
}
