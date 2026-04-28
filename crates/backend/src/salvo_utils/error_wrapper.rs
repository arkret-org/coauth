use salvo::prelude::*;

use super::InternalError;

/// A simple wrapper around an error that implements Salvo's [`Scribe`] trait.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ErrorWrapper<T>(#[from] pub T);

impl<T> Scribe for ErrorWrapper<T>
where
    T: std::error::Error + Send + Sync + 'static,
{
    fn render(self, res: &mut Response) {
        InternalError::from(self.0).render(res);
    }
}
