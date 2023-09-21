extern crate alloc;
use super::interface;
use super::utils;
use alloc::sync::Arc;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::marker;

pub trait Lock<T>: marker::Send + marker::Sync + From<T> {
    type Guard<'a>: Deref<Target = T> + DerefMut
    where
        Self: 'a;

    fn lock(&self) -> Self::Guard<'_>;
}

pub trait RwLock<T>: marker::Send + marker::Sync + From<T> {
    type ReadGuard<'a>: Deref<Target = T>
    where
        Self: 'a;
    type WriteGuard<'a>: Deref<Target = T> + DerefMut
    where
        Self: 'a;

    fn read(&self) -> Self::ReadGuard<'_>;
    fn write(&self) -> Self::WriteGuard<'_>;
}

pub trait SyncTypes {
    type Lock<T>: Lock<T>;
    type RwLock<T>: RwLock<T>;
}

pub struct PinArcLock<ST: SyncTypes, T> {
    lock: Pin<Arc<ST::Lock<T>>>,
}

impl<ST: SyncTypes, T> PinArcLock<ST, T> {
    pub fn lock<'a>(&'_ self) -> PinArcLockGuard<'a, ST, T>
    where
        <ST as SyncTypes>::Lock<T>: 'a,
    {
        PinArcLockGuard::new(self.lock.clone())
    }

    pub fn try_new(value: T) -> Result<Self, interface::TpmErr> {
        let p = utils::arc_try_new(ST::Lock::from(value))?;
        Ok(Self {
            lock: unsafe { Pin::new_unchecked(p) },
        })
    }
}

impl<ST: SyncTypes, T> Clone for PinArcLock<ST, T> {
    fn clone(&self) -> Self {
        Self {
            lock: self.lock.clone(),
        }
    }
}

pub struct PinArcLockGuard<'a, ST: SyncTypes, T>
where
    <ST as SyncTypes>::Lock<T>: 'a,
{
    guard: <ST::Lock<T> as Lock<T>>::Guard<'a>,
    _lock: Pin<Arc<ST::Lock<T>>>,
}

impl<'a, ST: SyncTypes, T> PinArcLockGuard<'a, ST, T>
where
    <ST as SyncTypes>::Lock<T>: 'a,
{
    fn new(lock: Pin<Arc<ST::Lock<T>>>) -> Self {
        let lockp = &*lock as *const <ST as SyncTypes>::Lock<T>;
        let guard = unsafe { (*lockp).lock() };
        Self { guard, _lock: lock }
    }
}

impl<'a, ST: SyncTypes, T> Deref for PinArcLockGuard<'a, ST, T>
where
    <ST as SyncTypes>::Lock<T>: 'a,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.guard.deref()
    }
}

impl<'a, ST: SyncTypes, T> DerefMut for PinArcLockGuard<'a, ST, T>
where
    <ST as SyncTypes>::Lock<T>: 'a,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.deref_mut()
    }
}
