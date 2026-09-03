use coauth_data::{Clock, User};
use rand_core::RngCore;
use url::Url;

use crate::repository_impl;

repository_impl! {
    /// A [`UserTermsRepository`] helps interacting with the terms of service agreed
    /// by a [`User`]
    pub trait UserTermsRepository {
        /// The error type returned by the repository
        type Error;

        /// Accept the terms of service by a [`User`]
        ///
        /// # Parameters
        ///
        /// * `rng`: A random number generator used to generate IDs
        /// * `clock`: The clock used to generate timestamps
        /// * `user`: The [`User`] accepting the terms
        /// * `terms_url`: The URL of the terms of service the user is accepting
        ///
        /// # Errors
        ///
        /// Returns [`Self::Error`] if the underlying repository fails
        async fn accept_terms(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            user: &User,
            terms_url: Url,
        ) -> Result<(), Self::Error>;
    }
}
