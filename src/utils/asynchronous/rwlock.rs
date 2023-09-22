//! Implementation of [`AsyncRwLock`]

extern crate alloc;
use crate::interface;
use crate::sync_types::{self, Lock as _};
use crate::utils;
use alloc::{collections, sync};
use core::{cell, future, marker, num, ops, pin, task};

/// Internal representation of a waiter enqueued to [`AsyncRwLockQueue`]
struct AsyncRwLockQueueEntry {
    /// Whether or not the waiter seeks to acquire the lock exclusively.
    exclusive: bool,
    /// The waker to invoke once the lock grant becomes available.
    waker: Option<task::Waker>,
    /// The waiter's assigned id.
    waiter_id: num::NonZeroU64,
}

/// Internal queue of waiters waiting for locking grants on an [`AsyncRwLock`].
struct AsyncRwLockQueue {
    /// The actual queue.
    queue: collections::VecDeque<AsyncRwLockQueueEntry>,

    /// Number of granted shared lockings handed out. These must get eventually
    /// returned via [`return_shared_grant()`](Self::return_shared_grant)
    /// each.
    granted_shared_locks: usize,

    /// Whether an active exlusive locking grant is around. It must eventually
    /// get returned via
    /// [`return_exclusive_grant()`](Self::return_exclusive_grant).
    granted_exclusive_lock: bool,

    /// Last waiter id allocated in the course of enqueueing.
    last_waiter_id: u64,
}

impl AsyncRwLockQueue {
    fn new() -> Self {
        Self {
            queue: collections::VecDeque::new(),
            granted_shared_locks: 0,
            granted_exclusive_lock: false,
            last_waiter_id: 0,
        }
    }

    /// Poll the lock on behalf of a waiter.
    ///
    /// Return `true` if the lock has been granted to the waiter, `false`
    /// otherwise.
    fn poll_waiter(&mut self, waiter_id: num::NonZeroU64, waker: task::Waker) -> bool {
        if let Some(waiter) = self
            .queue
            .iter_mut()
            .find(|entry| entry.waiter_id == waiter_id)
        {
            waiter.waker = Some(waker);
            false
        } else {
            true
        }
    }

    /// Cancel an enqueued waiter.
    fn cancel_waiter(&mut self, waiter_id: num::NonZeroU64) {
        match self
            .queue
            .iter()
            .position(|entry| entry.waiter_id == waiter_id)
        {
            Some(index) => {
                let is_exlusive = self.queue[index].exclusive;
                self.queue.remove(index);
                // If it's been an exclusive wait entry at the beginning of the queue, it might
                // have blocked subsequent non-exclusive waiters. Kick them as
                // an optimization to allow them to run.
                if index == 0 && is_exlusive {
                    self.wake_waiters();
                }
            }
            None => {
                // The waiter has previously been removed, which means that it got a lock
                // granted. The fact that the waiter is attempting to cancel itself means that
                // it hasn't noticed yet. Return the grant to the pool.
                if self.granted_exclusive_lock {
                    self.return_exclusive_grant();
                } else {
                    debug_assert_ne!(self.granted_shared_locks, 0);
                    self.return_shared_grant();
                }
            }
        }
    }

    /// Return a shared locking grant.
    fn return_shared_grant(&mut self) {
        debug_assert_ne!(self.granted_shared_locks, 0);
        self.granted_shared_locks -= 1;
        if self.granted_shared_locks == 0 {
            self.wake_waiters();
        }
    }

    /// Return an exlusive locking grant.
    fn return_exclusive_grant(&mut self) {
        debug_assert!(self.granted_exclusive_lock);
        self.granted_exclusive_lock = false;
        self.wake_waiters();
    }

    /// Wake the maximum possible amount of waiters enqueued for the lock.
    fn wake_waiters(&mut self) {
        if self.queue.is_empty() {
            return;
        }

        if self.granted_exclusive_lock {
            return;
        }

        while let Some(mut entry) = self.queue.pop_front() {
            if entry.exclusive {
                if self.granted_shared_locks != 0 {
                    self.queue.push_front(entry);
                    break;
                }
                self.granted_exclusive_lock = true;
                if let Some(waker) = entry.waker.take() {
                    waker.wake();
                }
                break;
            } else {
                self.granted_shared_locks += 1;
                if let Some(waker) = entry.waker.take() {
                    waker.wake();
                }
            }
        }
    }

    /// Try to enqueue a waiter for the lock.
    ///
    /// If the lock is available immediately, `None` will get returned.
    /// Otherwise the waiter will get enqueued and the associated waiter id
    /// returned.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn try_enqueue(
        &mut self,
        exclusive: bool,
    ) -> Result<Option<num::NonZeroU64>, interface::TpmErr> {
        if !self.granted_exclusive_lock && self.queue.is_empty() {
            if exclusive {
                if self.granted_shared_locks == 0 {
                    self.granted_exclusive_lock = true;
                    return Ok(None);
                }
            } else {
                self.granted_shared_locks += 1;
                return Ok(None);
            }
        }

        if self.queue.capacity() <= self.queue.len() {
            self.queue.try_reserve(1).map_err(|_| tpm_err_rc!(MEMORY))?;
        }

        self.last_waiter_id += 1;
        let waiter_id = num::NonZeroU64::new(self.last_waiter_id).unwrap();
        self.queue.push_back(AsyncRwLockQueueEntry {
            exclusive,
            waker: None,
            waiter_id,
        });
        Ok(Some(waiter_id))
    }
}

/// A Read-Write Lock which can be waited asynchronously for.
///
/// The locking operations [`read()`](Self::read) and [`write()`](Self::write)
/// return futures which can be subsequently polled to eventually obtain the
/// lock.
///
/// [`AsyncRwLock`] follows the common Read-Write Lock semantics: locking for
/// writes is mutually exclusive, with either locking type whereas any number of
/// read lockings can be granted at a time.
pub struct AsyncRwLock<ST: sync_types::SyncTypes, T> {
    queue: ST::Lock<AsyncRwLockQueue>,
    data: cell::UnsafeCell<T>,
}

// The very purpose of implementing a lock is getting Sync.
unsafe impl<ST: sync_types::SyncTypes, T> Sync for AsyncRwLock<ST, T> {}

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
    fn new(data: T) -> Result<pin::Pin<sync::Arc<Self>>, interface::TpmErr> {
        let this = utils::arc_try_new(Self {
            queue: ST::Lock::from(AsyncRwLockQueue::new()),
            data: cell::UnsafeCell::new(data),
        })?;
        Ok(unsafe { pin::Pin::new_unchecked(this) })
    }

    /// Asynchronous, non-exclusive locking for read semantics.
    ///
    /// Instantiate a [`AsyncRwLockWaitReadLockFuture`] for taking the lock
    /// asynchronously for read semantics.
    ///
    /// The returned future will not become ready as long as an exlusive write
    /// locking, i.e. an [`AsyncRwLockWriteGuard`] is active, or some waiter
    /// for an exclusive write locking is ahead in line.
    ///
    /// # Arguments:
    ///
    /// * `self` - The lock to acquire.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn read(
        self: pin::Pin<sync::Arc<Self>>,
    ) -> Result<AsyncRwLockWaitReadLockFuture<ST, T>, interface::TpmErr> {
        let mut queue = self.queue.lock();
        let waiter_id = queue.try_enqueue(false)?;
        drop(queue);
        let wait_lock_future = match waiter_id {
            Some(waiter_id) => AsyncRwLockWaitLockFuture::<ST, T, false>::Enqueued {
                lock: WeakAsyncRwLockRef::new(self),
                waiter_id,
            },
            None => AsyncRwLockWaitLockFuture::<ST, T, false>::LockGranted {
                lock: WeakAsyncRwLockRef::new(self),
            },
        };
        Ok(AsyncRwLockWaitReadLockFuture {
            inner: wait_lock_future,
        })
    }

    /// Asynchronous, exclusive locking for write semantics.
    ///
    /// Instantiate a [`AsyncRwLockWaitWriteLockFuture`] for taking the lock
    /// asynchronously for write semantics.
    ///
    /// The returned future will not become ready as long as some locking of any
    /// type, i.e. an [`AsyncRwLockWriteGuard`] or [`AsyncRwLockReadGuard`]
    /// is active, or some other waiter is ahead in line.
    ///
    /// # Arguments:
    ///
    /// * `self` - The lock to acquire.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn write(
        self: pin::Pin<sync::Arc<Self>>,
    ) -> Result<AsyncRwLockWaitWriteLockFuture<ST, T>, interface::TpmErr> {
        let mut queue = self.queue.lock();
        let waiter_id = queue.try_enqueue(true)?;
        drop(queue);
        let wait_lock_future = match waiter_id {
            Some(waiter_id) => AsyncRwLockWaitLockFuture::<ST, T, true>::Enqueued {
                lock: WeakAsyncRwLockRef::new(self),
                waiter_id,
            },
            None => AsyncRwLockWaitLockFuture::<ST, T, true>::LockGranted {
                lock: WeakAsyncRwLockRef::new(self),
            },
        };

        Ok(AsyncRwLockWaitWriteLockFuture {
            inner: wait_lock_future,
        })
    }

    /// Try to synchronously acquire lock non-exclusively for read semantics.
    ///
    /// The operation will only succeed and return a [`AsyncRwLockReadGuard`] if
    /// no exclusive locking is active or waited for to become available.
    /// Otherwise [`None`] will get returned.
    pub fn try_read(self: pin::Pin<sync::Arc<Self>>) -> Option<AsyncRwLockReadGuard<ST, T>> {
        let mut queue = self.queue.lock();
        if queue.granted_exclusive_lock || !queue.queue.is_empty() {
            None
        } else {
            queue.granted_shared_locks += 1;
            drop(queue);
            Some(AsyncRwLockReadGuard {
                guard: AsyncRwLockGuard { lock: self },
            })
        }
    }

    /// Try to synchronously acquire lock exclusively for write semantics.
    ///
    /// The operation will only succeed and return a [`AsyncRwLockWriteGuard`]
    /// if no locking is active or waited for to become available.
    /// Otherwise [`None`] will get returned.
    pub fn try_write(self: pin::Pin<sync::Arc<Self>>) -> Option<AsyncRwLockWriteGuard<ST, T>> {
        let mut queue = self.queue.lock();
        if queue.granted_exclusive_lock
            || queue.granted_shared_locks != 0
            || !queue.queue.is_empty()
        {
            None
        } else {
            queue.granted_exclusive_lock = true;
            drop(queue);
            Some(AsyncRwLockWriteGuard {
                guard: AsyncRwLockGuard { lock: self },
            })
        }
    }
}

/// Internal weak reference to an [`AsyncRwLock`].
///
/// To allow for deallocation of an [`AsyncRwLock`] with waiters still around,
/// the latter maintain only a weak reference to their associated lock.
struct WeakAsyncRwLockRef<ST: sync_types::SyncTypes, T> {
    weak_p: sync::Weak<AsyncRwLock<ST, T>>,
}

impl<ST: sync_types::SyncTypes, T> WeakAsyncRwLockRef<ST, T> {
    /// Downgrade into a weak reference.
    fn new(p: pin::Pin<sync::Arc<AsyncRwLock<ST, T>>>) -> Self {
        Self {
            weak_p: sync::Arc::downgrade(&unsafe {
                // This is safe: the unwrapped pointer gets downgraded
                // immediately and the only way to obtain a referencable
                // pointer again is via Self::upgrade(), which would pin
                // it again.
                pin::Pin::into_inner_unchecked(p)
            }),
        }
    }

    /// Attempt to upgade the weak reference again.
    fn upgrade(&self) -> Option<pin::Pin<sync::Arc<AsyncRwLock<ST, T>>>> {
        self.weak_p.upgrade().map(|p| {
            // This is safe: self.weak_p originated from a pinned pointer.
            unsafe { pin::Pin::new_unchecked(p) }
        })
    }
}

/// Internal [`AsyncRwLock`] waiter implementation common to both,
/// [`AsyncRwLockWaitReadLockFuture`] and [`AsyncRwLockWaitWriteLockFuture`].
enum AsyncRwLockWaitLockFuture<ST: sync_types::SyncTypes, T, const EXCL: bool> {
    /// The lock had been unavailable at enqueueing time and the waiter
    /// got indeed enqueued.
    Enqueued {
        lock: WeakAsyncRwLockRef<ST, T>,
        waiter_id: num::NonZeroU64,
    },
    /// The lock had been available at enqueueing time and its ownership assumed
    /// right away.
    LockGranted { lock: WeakAsyncRwLockRef<ST, T> },
    /// The future is done: the lock had been acquired at some time and polled
    /// out to the user.
    Done,
}

impl<ST: sync_types::SyncTypes, T, const EXCL: bool> marker::Unpin
    for AsyncRwLockWaitLockFuture<ST, T, EXCL>
{
}

impl<ST: sync_types::SyncTypes, T, const EXCL: bool> future::Future
    for AsyncRwLockWaitLockFuture<ST, T, EXCL>
{
    type Output = Result<AsyncRwLockGuard<ST, T, EXCL>, interface::TpmErr>;

    /// Poll the lock for a locking grant.
    ///
    /// Upon future completion, either an instance of the internal
    /// [`AsyncRwLockGuard`] is returned or, if the associated
    /// [`AsyncRwLock`] had been dropped in the meanwhile, an error of
    /// [`TpmRc::RETRY`](interface::TpmRc::RETRY).
    ///
    /// The future must not get polled any further once completed.
    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.get_mut();
        match this {
            Self::Enqueued { lock, waiter_id } => {
                let lock = match lock.upgrade() {
                    Some(lock) => lock,
                    None => {
                        // The lock is gone, indicating some teardown going on. Let the user retry
                        // to get a more definitive answer.
                        return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                    }
                };

                let mut queue = lock.queue.lock();
                if queue.poll_waiter(*waiter_id, cx.waker().clone()) {
                    drop(queue);
                    *this = Self::Done;
                    task::Poll::Ready(Ok(AsyncRwLockGuard { lock }))
                } else {
                    task::Poll::Pending
                }
            }
            Self::LockGranted { lock } => {
                let lock = match lock.upgrade() {
                    Some(lock) => lock,
                    None => {
                        // The lock is gone, indicating some teardown going on. Let the user retry
                        // to get a more definitive answer.
                        return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                    }
                };
                *this = Self::Done;
                task::Poll::Ready(Ok(AsyncRwLockGuard { lock }))
            }
            Self::Done => {
                // The lock had been acquired and handed out already.
                task::Poll::Ready(Err(tpm_err_internal!()))
            }
        }
    }
}

impl<ST: sync_types::SyncTypes, T, const EXCL: bool> Drop
    for AsyncRwLockWaitLockFuture<ST, T, EXCL>
{
    fn drop(&mut self) {
        match self {
            Self::Enqueued { lock, waiter_id } => {
                if let Some(lock) = lock.upgrade() {
                    lock.queue.lock().cancel_waiter(*waiter_id);
                }
            }
            Self::LockGranted { lock } => {
                // The lock had been granted right from the beginning, but the future never got
                // polled for it. Return the grant.
                if let Some(lock) = lock.upgrade() {
                    let mut queue = lock.queue.lock();
                    if EXCL {
                        queue.return_exclusive_grant();
                    } else {
                        queue.return_shared_grant();
                    }
                }
            }
            Self::Done => (),
        }
    }
}

/// Internal [`AsyncRwLock`] lock guard implementation common to both,
/// [`AsyncRwLockReadGuard`] and [`AsyncRwLockWriteGuard`].
struct AsyncRwLockGuard<ST: sync_types::SyncTypes, T, const EXCL: bool> {
    lock: pin::Pin<sync::Arc<AsyncRwLock<ST, T>>>,
}

impl<ST: sync_types::SyncTypes, T, const EXCL: bool> Drop for AsyncRwLockGuard<ST, T, EXCL> {
    fn drop(&mut self) {
        let mut queue = self.lock.queue.lock();
        if EXCL {
            queue.return_exclusive_grant();
        } else {
            queue.return_shared_grant();
        }
    }
}

/// Asynchronous wait for non-exclusive locking of a [`AsyncRwLock`].
///
/// To be obtained through [`AsyncRwLock::read()`].
///
/// # Note on lifetime management
///
/// An [`AsyncRwLockWaitReadLockFuture`] instance will only maintain a weak
/// reference (i.e. a [`Weak`](sync::Weak)) to the associated [`AsyncRwLock`]
/// instance and thus, would not hinder its deallocation. In case the lock gets
/// dropped before the future had a chance to acquire it, its `poll()` would
/// return [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct AsyncRwLockWaitReadLockFuture<ST: sync_types::SyncTypes, T> {
    inner: AsyncRwLockWaitLockFuture<ST, T, false>,
}

impl<ST: sync_types::SyncTypes, T> marker::Unpin for AsyncRwLockWaitReadLockFuture<ST, T> {}

impl<ST: sync_types::SyncTypes, T> future::Future for AsyncRwLockWaitReadLockFuture<ST, T> {
    type Output = Result<AsyncRwLockReadGuard<ST, T>, interface::TpmErr>;

    /// Poll for a locking grant of the associated [`AsyncRwLock`].
    ///
    /// Upon future completion, either a [`AsyncRwLockReadGuard`] is returned
    /// or, if the associated [`AsyncRwLock`] had been dropped in the
    /// meanwhile, an error of [`TpmRc::RETRY`](interface::TpmRc::RETRY).
    ///
    /// The future must not get polled any further once completed.
    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        future::Future::poll(pin::Pin::new(&mut self.as_mut().inner), cx)
            .map(|result| result.map(|guard| AsyncRwLockReadGuard { guard }))
    }
}

/// Non-exclusive locking grant on an [`AsyncRwLock`].
pub struct AsyncRwLockReadGuard<ST: sync_types::SyncTypes, T> {
    guard: AsyncRwLockGuard<ST, T, false>,
}

impl<ST: sync_types::SyncTypes, T> ops::Deref for AsyncRwLockReadGuard<ST, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.guard.lock.data.get() as *const T;
        unsafe { &*p }
    }
}

/// Asynchronous wait for exclusive locking of a [`AsyncRwLock`].
///
/// To be obtained through [`AsyncRwLock::write()`].
///
/// # Note on lifetime management
///
/// An [`AsyncRwLockWaitWriteLockFuture`] instance will only maintain a weak
/// reference (i.e. a [`Weak`](sync::Weak)) to the associated [`AsyncRwLock`]
/// instance and thus, would not hinder its deallocation. In case the lock gets
/// dropped before the future had a chance to acquire it, its `poll()` would
/// return [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct AsyncRwLockWaitWriteLockFuture<ST: sync_types::SyncTypes, T> {
    inner: AsyncRwLockWaitLockFuture<ST, T, true>,
}

impl<ST: sync_types::SyncTypes, T> marker::Unpin for AsyncRwLockWaitWriteLockFuture<ST, T> {}

impl<ST: sync_types::SyncTypes, T> future::Future for AsyncRwLockWaitWriteLockFuture<ST, T> {
    type Output = Result<AsyncRwLockWriteGuard<ST, T>, interface::TpmErr>;

    /// Poll for a locking grant of the associated [`AsyncRwLock`].
    ///
    /// Upon future completion, either a [`AsyncRwLockWriteGuard`] is returned
    /// or, if the associated [`AsyncRwLock`] had been dropped in the
    /// meanwhile, an error of [`TpmRc::RETRY`](interface::TpmRc::RETRY).
    ///
    /// The future must not get polled any further once completed.
    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        future::Future::poll(pin::Pin::new(&mut self.as_mut().inner), cx)
            .map(|result| result.map(|guard| AsyncRwLockWriteGuard { guard }))
    }
}

/// Exclusive locking grant on an [`AsyncRwLock`].
pub struct AsyncRwLockWriteGuard<ST: sync_types::SyncTypes, T> {
    guard: AsyncRwLockGuard<ST, T, true>,
}

impl<ST: sync_types::SyncTypes, T> ops::Deref for AsyncRwLockWriteGuard<ST, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.guard.lock.data.get() as *const T;
        unsafe { &*p }
    }
}

impl<ST: sync_types::SyncTypes, T> ops::DerefMut for AsyncRwLockWriteGuard<ST, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let p = self.guard.lock.data.get();
        unsafe { &mut *p }
    }
}
