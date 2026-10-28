//! Entropy-preserving bridge between the JOSE and RustCrypto RNG generations.

use signature::rand_core::{CryptoRng, RngCore};

/// Adapt an existing infallible cryptographic RNG without reseeding it.
pub struct CryptoRngCompat<'a, R: ?Sized> {
    inner: &'a mut R,
}

impl<'a, R: ?Sized> CryptoRngCompat<'a, R> {
    /// Borrow the existing random source for an operation in the new generation.
    pub fn new(inner: &'a mut R) -> Self {
        Self { inner }
    }
}

impl<R: RngCore + ?Sized> rand_core_10::TryRng for CryptoRngCompat<'_, R> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.inner.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.inner.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.fill_bytes(dst);
        Ok(())
    }
}

impl<R: RngCore + CryptoRng + ?Sized> rand_core_10::TryCryptoRng for CryptoRngCompat<'_, R> {}
