//! Wrappers and utilities related to the
//! [`Zeroize`](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html) crate.

#[cfg(feature = "zeroize")]
use zeroize;

#[cfg(feature = "zeroize")]
#[doc(hidden)]
use zeroize::Zeroizing as ZeroizingCfgChoice;

#[cfg(not(feature = "zeroize"))]
#[doc(hidden)]
type ZeroizingCfgChoice<T> = NotZeroizing<T>;

/// Configuration abstraction type definition for
/// [`zeroize::Zeroizing`](https://docs.rs/zeroize/latest/zeroize/struct.Zeroizing.html).
///
/// Depending on whether or the Cargo feature `zeroize` is enabled, this is either an alias to the
/// real [`zeroize::Zeroizing`](https://docs.rs/zeroize/latest/zeroize/struct.Zeroizing.html) or to
/// the trivial, API compatible [`NotZeroizing`] substitute.
pub type Zeroizing<T> = ZeroizingCfgChoice<T>;

/// Transparent, trivial substitute for
/// [`zeroize::Zeroizing`](https://docs.rs/zeroize/latest/zeroize/struct.Zeroizing.html) for use if
/// the `zeroize` feature is disabled.
///
/// See the [`Zeroizing`] configuration abstracting type definition.
#[cfg(any(not(feature = "zeroize"), doc))]
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct NotZeroizing<T>(T);

#[cfg(any(not(feature = "zeroize"), doc))]
impl<T> core::ops::Deref for NotZeroizing<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(any(not(feature = "zeroize"), doc))]
impl<T> core::ops::DerefMut for NotZeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(any(not(feature = "zeroize"), doc))]
impl<T> From<T> for NotZeroizing<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

#[cfg(feature = "zeroize")]
pub use zeroize::Zeroize;

#[cfg(not(feature = "zeroize"))]
pub trait Zeroize {
    fn zeroize(&mut self);
}

#[cfg(not(feature = "zeroize"))]
impl<T> Zeroize for T {
    fn zeroize(&mut self) {}
}

#[cfg(feature = "zeroize")]
pub use zeroize::ZeroizeOnDrop;

#[cfg(not(feature = "zeroize"))]
pub trait ZeroizeOnDrop {}
