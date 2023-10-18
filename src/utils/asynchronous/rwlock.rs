//! Implementation of [`AsyncRwLock`]

extern crate alloc;
use super::semaphore;
use crate::interface;
use crate::sync_types;
use alloc::sync;
use core::{future, marker, ops, pin, task};

/// A Read-Write Lock which can be waited asynchronously for.
///
/// The locking operations [`read()`](Self::read) and [`write()`](Self::write)
/// return futures which can subsequently get polled to eventually obtain the
/// lock.
///
/// [`AsyncRwLock`] follows the common Read-Write Lock semantics: locking for
/// writes is mutually exclusive, with either locking type whereas any number of
/// read lockings can be granted at a time.
pub struct AsyncRwLock<ST: sync_types::SyncTypes, T> {
    sem: sync::Arc<semaphore::AsyncSemaphore<ST, T>>,
}

impl<ST: sync_types::SyncTypes, T> AsyncRwLock<ST, T> {
    /// Instantiate a new [`AsyncRwLock`]
    ///
    /// # Arguments:
    ///
    /// * `data` - the data to wrap in the the lock.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn new(data: T) -> Result<Self, interface::TpmErr> {
        Ok(Self {
            sem: semaphore::AsyncSemaphore::new(0, data)?,
        })
    }

    /// Asynchronous, non-exclusive locking for read semantics.
    ///
    /// Instantiate a [`AsyncRwLockReadFuture`] for taking the lock
    /// asynchronously for read semantics.
    ///
    /// The returned future will not become ready as long as an exlusive write
    /// locking, i.e. an [`AsyncRwLockWriteGuard`] is active, or some waiter
    /// for an exclusive write locking is ahead in line.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn read(&self) -> Result<AsyncRwLockReadFuture<ST, T>, interface::TpmErr> {
        let sem_trivial_lease_fut = self.sem.acquire_leases(0).map_err(|e| match e {
            semaphore::AsyncSemaphoreError::RequestExceedsSemaphoreCapacity => unreachable!(),
            semaphore::AsyncSemaphoreError::TpmErr(e) => e,
        })?;
        Ok(AsyncRwLockReadFuture {
            sem_trivial_lease_fut,
        })
    }

    /// Asynchronous, exclusive locking for write semantics.
    ///
    /// Instantiate a [`AsyncRwLockWriteFuture`] for taking the lock
    /// asynchronously for write semantics.
    ///
    /// The returned future will not become ready as long as some locking of any
    /// type, i.e. an [`AsyncRwLockWriteGuard`] or [`AsyncRwLockReadGuard`]
    /// is active, or some other waiter is ahead in line.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn write(&self) -> Result<AsyncRwLockWriteFuture<ST, T>, interface::TpmErr> {
        let sem_exclusive_all_fut = self.sem.acquire_exclusive_all()?;
        Ok(AsyncRwLockWriteFuture {
            sem_exclusive_all_fut,
        })
    }

    /// Try to synchronously acquire lock non-exclusively for read semantics.
    ///
    /// The operation will only succeed and return a [`AsyncRwLockReadGuard`] if
    /// no exclusive locking is active or waited for to become available.
    /// Otherwise [`None`] will get returned.
    pub fn try_read(&self) -> Option<AsyncRwLockReadGuard<ST, T>> {
        self.sem
            .try_acquire_leases(0)
            .unwrap()
            .map(|sem_trivial_lease_guard| AsyncRwLockReadGuard {
                sem_trivial_lease_guard,
            })
    }

    /// Try to synchronously acquire lock exclusively for write semantics.
    ///
    /// The operation will only succeed and return a [`AsyncRwLockWriteGuard`]
    /// if no locking is active or waited for to become available.
    /// Otherwise [`None`] will get returned.
    pub fn try_write(&self) -> Option<AsyncRwLockWriteGuard<ST, T>> {
        self.sem
            .try_acquire_exclusive_all()
            .map(|sem_exclusive_all_guard| AsyncRwLockWriteGuard {
                sem_exclusive_all_guard,
            })
    }
}

/// Asynchronous wait for non-exclusive locking of an [`AsyncRwLock`].
///
/// To be obtained through [`AsyncRwLock::read()`].
///
/// # Note on lifetime management
///
/// An [`AsyncRwLockReadFuture`] instance will only maintain a weak
/// reference (i.e. a [`Weak`](sync::Weak)) to the associated [`AsyncRwLock`]
/// instance and thus, would not hinder its deallocation. In case the lock gets
/// dropped before the future had a chance to acquire it, its `poll()` would
/// return [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct AsyncRwLockReadFuture<ST: sync_types::SyncTypes, T> {
    sem_trivial_lease_fut: semaphore::AsyncSemaphoreLeasesFuture<ST, T>,
}

impl<ST: sync_types::SyncTypes, T> marker::Unpin for AsyncRwLockReadFuture<ST, T> {}

impl<ST: sync_types::SyncTypes, T> future::Future for AsyncRwLockReadFuture<ST, T> {
    type Output = Result<AsyncRwLockReadGuard<ST, T>, interface::TpmErr>;

    /// Poll for a locking grant of the associated [`AsyncRwLock`].
    ///
    /// Upon future completion, either a [`AsyncRwLockReadGuard`] is returned
    /// or, if the associated [`AsyncRwLock`] had been dropped in the
    /// meanwhile, an error of [`TpmRc::RETRY`](interface::TpmRc::RETRY).
    ///
    /// The future must not get polled any further once completed.
    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        future::Future::poll(pin::Pin::new(&mut self.get_mut().sem_trivial_lease_fut), cx)
            .map_ok(|sem_trivial_lease_guard| AsyncRwLockReadGuard {
                sem_trivial_lease_guard,
            })
            .map_err(|e| match e {
                semaphore::AsyncSemaphoreError::RequestExceedsSemaphoreCapacity => unreachable!(),
                semaphore::AsyncSemaphoreError::TpmErr(e) => e,
            })
    }
}

/// Non-exclusive locking grant on an [`AsyncRwLock`].
pub struct AsyncRwLockReadGuard<ST: sync_types::SyncTypes, T> {
    sem_trivial_lease_guard: semaphore::AsyncSemaphoreLeasesGuard<ST, T>,
}

impl<ST: sync_types::SyncTypes, T> ops::Deref for AsyncRwLockReadGuard<ST, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.sem_trivial_lease_guard
    }
}

/// Asynchronous wait for exclusive locking of an [`AsyncRwLock`].
///
/// To be obtained through [`AsyncRwLock::write()`].
///
/// # Note on lifetime management
///
/// An [`AsyncRwLockWriteFuture`] instance will only maintain a weak
/// reference (i.e. a [`Weak`](sync::Weak)) to the associated [`AsyncRwLock`]
/// instance and thus, would not hinder its deallocation. In case the lock gets
/// dropped before the future had a chance to acquire it, its `poll()` would
/// return [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct AsyncRwLockWriteFuture<ST: sync_types::SyncTypes, T> {
    sem_exclusive_all_fut: semaphore::AsyncSemaphoreExclusiveAllFuture<ST, T>,
}

impl<ST: sync_types::SyncTypes, T> marker::Unpin for AsyncRwLockWriteFuture<ST, T> {}

impl<ST: sync_types::SyncTypes, T> future::Future for AsyncRwLockWriteFuture<ST, T> {
    type Output = Result<AsyncRwLockWriteGuard<ST, T>, interface::TpmErr>;

    /// Poll for a locking grant of the associated [`AsyncRwLock`].
    ///
    /// Upon future completion, either a [`AsyncRwLockWriteGuard`] is returned
    /// or, if the associated [`AsyncRwLock`] had been dropped in the
    /// meanwhile, an error of [`TpmRc::RETRY`](interface::TpmRc::RETRY).
    ///
    /// The future must not get polled any further once completed.
    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        future::Future::poll(pin::Pin::new(&mut self.get_mut().sem_exclusive_all_fut), cx).map_ok(
            |sem_exclusive_all_guard| AsyncRwLockWriteGuard {
                sem_exclusive_all_guard,
            },
        )
    }
}

/// Exclusive locking grant on an [`AsyncRwLock`].
pub struct AsyncRwLockWriteGuard<ST: sync_types::SyncTypes, T> {
    sem_exclusive_all_guard: semaphore::AsyncSemaphoreExclusiveAllGuard<ST, T>,
}

impl<ST: sync_types::SyncTypes, T> ops::Deref for AsyncRwLockWriteGuard<ST, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.sem_exclusive_all_guard
    }
}

impl<ST: sync_types::SyncTypes, T> ops::DerefMut for AsyncRwLockWriteGuard<ST, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sem_exclusive_all_guard
    }
}
