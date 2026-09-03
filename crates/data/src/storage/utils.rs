//! Wrappers and useful type aliases

/// A wrapper which is used to map the error type of a repository to another
pub struct MapErr<R, F> {
    pub(crate) inner: R,
    pub(crate) mapper: F,
    _private: (),
}

impl<R, F> MapErr<R, F> {
    /// Create a new [`MapErr`] wrapper from an inner repository and a mapper
    /// function
    #[must_use]
    pub fn new(inner: R, mapper: F) -> Self {
        Self {
            inner,
            mapper,
            _private: (),
        }
    }
}

/// Declare a repository port trait together with the two forwarding
/// implementations every one of them needs: [`Box<R>`], which is what makes
/// `BoxRepository` object-safe, and [`MapErr`], which re-types the backend
/// error into the caller's error without the caller knowing the backend.
///
/// Both forwarders have to repeat every method signature verbatim, so writing
/// the trait by hand next to the macro meant maintaining each signature twice.
/// The trait is therefore declared *inside* the macro: the signature below is
/// the single source, and the forwarders are derived from it.
///
/// Every port is `Send + Sync` and carries an associated `Error`, so those are
/// supplied by the macro rather than repeated at each of the 45 call sites.
///
/// # Methods with a default body
///
/// A method that already has a body cannot be forwarded — there is nothing to
/// forward *to* — so those go in a trailing `defaults { … }` section and are
/// spliced into the trait verbatim. The wrappers inherit the default, which
/// dispatches back through the wrapper's own methods, so a body that delegates
/// to another trait method still reaches the backend exactly once.
///
/// The section is separate rather than a tail inside the trait because a `#[…]`
/// attribute would otherwise be ambiguous between "another declaration" and
/// "the first default method", and it is spliced as untouched tokens rather
/// than reassembled from captured fragments because `#[async_trait]` rewrites
/// `self` inside a body and cannot do so when the signature comes from the
/// macro while the body comes from the call site.
#[macro_export]
macro_rules! repository_impl {
    (
        $(#[$tmeta:meta])*
        pub trait $repo_trait:ident {
            $(#[$emeta:meta])*
            type Error;

            $(
                $(#[$mmeta:meta])*
                async fn $method:ident (
                    &mut self
                    $(, $arg:ident: $arg_ty:ty )*
                    $(,)?
                ) -> Result<$ret_ty:ty, Self::Error>;
            )*

        }

        $( defaults { $($default:tt)* } )?
    ) => {
        $(#[$tmeta])*
        #[::async_trait::async_trait]
        pub trait $repo_trait: ::std::marker::Send + ::std::marker::Sync {
            $(#[$emeta])*
            type Error;

            $(
                $(#[$mmeta])*
                async fn $method (
                    &mut self $(, $arg: $arg_ty)*
                ) -> Result<$ret_ty, Self::Error>;
            )*

            $( $($default)* )?
        }

        #[::async_trait::async_trait]
        impl<R: ?Sized> $repo_trait for ::std::boxed::Box<R>
        where
            R: $repo_trait,
        {
            type Error = <R as $repo_trait>::Error;

            $(
                async fn $method (&mut self $(, $arg: $arg_ty)*) -> Result<$ret_ty, Self::Error> {
                    (**self).$method ( $($arg),* ).await
                }
            )*
        }

        #[::async_trait::async_trait]
        impl<R, F, E> $repo_trait for $crate::MapErr<R, F>
        where
            R: $repo_trait,
            F: FnMut(<R as $repo_trait>::Error) -> E + ::std::marker::Send + ::std::marker::Sync,
        {
            type Error = E;

            $(
                async fn $method (&mut self $(, $arg: $arg_ty)*) -> Result<$ret_ty, Self::Error> {
                    self.inner.$method ( $($arg),* ).await.map_err(&mut self.mapper)
                }
            )*
        }
    };
}
