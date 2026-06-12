use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram};
use rand_core::RngCore;
use tokio_postgres::{Client, NoTls, Notification};

use super::shared::{MAX_SLEEP_DURATION, MIN_SLEEP_DURATION};
use super::tracker::JobTracker;
use super::{JobContext, QueueRunnerError};
use crate::{METER, State};

pub(super) struct ListenerRuntime {
    pub(super) client: Client,
    pub(super) notifications: tokio::sync::mpsc::UnboundedReceiver<Notification>,
}

pub(super) async fn connect_listener(state: &State) -> Result<ListenerRuntime, QueueRunnerError> {
    let (client, mut connection) = tokio_postgres::connect(state.database_url(), NoTls)
        .await
        .map_err(QueueRunnerError::SetupListener)?;

    let (notification_tx, notifications) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        while let Some(message) = std::future::poll_fn(|cx| connection.poll_message(cx)).await {
            match message {
                Ok(tokio_postgres::AsyncMessage::Notification(notification)) => {
                    let _ = notification_tx.send(notification);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(error = %error, "PostgreSQL notification connection error");
                    break;
                }
            }
        }

        tracing::warn!("PostgreSQL notification connection closed");
    });

    for channel in ["queue_leader_stepdown", "queue_available"] {
        Client::execute(&client, &format!("LISTEN {channel}"), &[])
            .await
            .map_err(QueueRunnerError::SetupListener)?;
    }

    Ok(ListenerRuntime {
        client,
        notifications,
    })
}

pub(super) struct WorkerMetrics {
    pub(super) wakeups: Counter<u64>,
    pub(super) tick_time: Histogram<u64>,
}

pub(super) fn build_worker_metrics() -> WorkerMetrics {
    let wakeups = METER
        .u64_counter("job.worker.wakeups")
        .with_description("Counts how many time the worker has been woken up, for which reason")
        .build();

    for reason in ["sleep", "task", "notification"] {
        wakeups.add(0, &[KeyValue::new("reason", reason)]);
    }

    let tick_time = METER
        .u64_histogram("job.worker.tick_duration")
        .with_description(
            "How much time the worker took to tick, including performing leader duties",
        )
        .build();

    WorkerMetrics { wakeups, tick_time }
}

pub(super) async fn wait_until_wakeup(
    state: &State,
    cancellation_token: &tokio_util::sync::CancellationToken,
    tracker: &mut JobTracker,
    notifications: &mut tokio::sync::mpsc::UnboundedReceiver<Notification>,
    wakeups: &Counter<u64>,
) {
    let mut rng = state.rng();
    let jitter_ms = (rng.next_u64()
        % (MAX_SLEEP_DURATION.as_millis() as u64 - MIN_SLEEP_DURATION.as_millis() as u64))
        + MIN_SLEEP_DURATION.as_millis() as u64;
    let sleep_duration = std::time::Duration::from_millis(jitter_ms);
    let wakeup_sleep = tokio::time::sleep(sleep_duration);

    tokio::select! {
        () = cancellation_token.cancelled() => {
            tracing::debug!("Woke up from cancellation");
        },

        () = wakeup_sleep => {
            tracing::debug!("Woke up from sleep");
            wakeups.add(1, &[KeyValue::new("reason", "sleep")]);
        },

        () = tracker.collect_next_job(), if tracker.has_jobs() => {
            tracing::debug!("Joined job task");
            wakeups.add(1, &[KeyValue::new("reason", "task")]);
        },

        notification = notifications.recv() => {
            wakeups.add(1, &[KeyValue::new("reason", "notification")]);
            match notification {
                Some(notification) => {
                    tracing::debug!(
                        notification.channel = notification.channel(),
                        notification.payload = notification.payload(),
                        "Woke up from notification"
                    );
                },
                None => {
                    tracing::error!("Notification channel closed unexpectedly");
                }
            }
        },
    }
}

pub(super) fn spawn_reserved_jobs(
    tracker: &mut JobTracker,
    state: &State,
    cancellation_token: &tokio_util::sync::CancellationToken,
    jobs: impl IntoIterator<Item = coauth_data::queue::Job>,
) {
    for job in jobs {
        let context = build_context(cancellation_token, &job);
        tracker.spawn_job(state.clone(), context, job.payload);
    }
}

fn build_context(
    cancellation_token: &tokio_util::sync::CancellationToken,
    job: &coauth_data::queue::Job,
) -> JobContext {
    JobContext {
        id: job.id,
        metadata: job.metadata.clone(),
        queue_name: job.queue_name.clone(),
        attempt: job.attempt,
        start: tokio::time::Instant::now(),
        cancellation_token: cancellation_token.child_token(),
    }
}
