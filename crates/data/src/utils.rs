use rand_chacha::rand_core::CryptoRngCore;

use crate::clock::Clock;

/// Type-erased clock suitable for passing through async boundaries.
pub type BoxClock = Box<dyn Clock + Send>;

/// Type-erased cryptographic RNG for contexts that need runtime polymorphism.
pub type BoxRng = Box<dyn CryptoRngCore + Send>;
