//! Implementation of [`AsyncSemaphore`]

extern crate alloc;
use crate::interface;
use crate::sync_types::{self, Lock as _};
use crate::utils;
use alloc::{collections, sync};
use core::{future, marker, num, pin, task};

/// Internal representation of a waiter enqueued to [`AsyncSemaphoreQueue`]
struct AsyncSemaphoreQueueEntry {
    /// The number of leases to acquire.
    leases_requested: usize,
    /// The waker to invoke once the requested number of leases becomes
    /// available.
    waker: Option<task::Waker>,
    /// The waiter's assigned id.
    waiter_id: num::NonZeroU64,
}

/// Internal queue of waiters waiting for lease grants on an
/// [`AsyncSemaphore`].
struct AsyncSemaphoreQueue {
    /// The actual wait queue.
    queue: collections::VecDeque<AsyncSemaphoreQueueEntry>,

    /// Number of active leases handed out. They must eventually get returned
    /// via [`return_granted_leases`](Self::return_granted_leases).
    granted_leases: usize,

    /// Maximum number of leases that can be granted at a time.
    max_leases: usize,

    /// Last waiter id allocated in the course of enqueueing.
    last_waiter_id: u64,
}

impl AsyncSemaphoreQueue {
    fn new(max_leases: usize) -> Self {
        Self {
            queue: collections::VecDeque::new(),
            granted_leases: 0,
            max_leases,
            last_waiter_id: 0,
        }
    }

    /// Poll the semaphore on behalf of a waiter.
    ///
    /// Return `true` if the requested leases have been granted to the waiter,
    /// `false` otherwise.
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
    fn cancel_waiter(&mut self, waiter_id: num::NonZeroU64, leases_requested: usize) {
        match self
            .queue
            .iter()
            .position(|entry| entry.waiter_id == waiter_id)
        {
            Some(index) => {
                self.queue.remove(index);
                if leases_requested > 1 {
                    // This waiter might have blocked subsequent entries waiting
                    // for a smaller number of leases, which might already be
                    // available. Kick those waiters.
                    self.wake_waiters();
                }
            }
            None => {
                // The waiter has previously been removed, which means that it got the requested
                // number of semaphore leases granted. The fact that the waiter is attempting to
                // cancel itself means that it hasn't noticed yet. Return the grants to the
                // pool.
                self.return_granted_leases(leases_requested);
            }
        }
    }

    /// Return granted semaphore leases to the pool.
    ///
    /// Return granted leases back to the pool, making them available to
    /// other waiters again.
    fn return_granted_leases(&mut self, leases: usize) {
        if leases == 0 {
            return;
        }
        debug_assert!(leases <= self.granted_leases);
        self.granted_leases -= leases;
        self.wake_waiters();
    }

    /// Wake the maximum possible amount of waiters waiting on semaphore lease
    /// grants.
    fn wake_waiters(&mut self) {
        if self.granted_leases == self.max_leases {
            return;
        }

        while let Some(mut entry) = self.queue.pop_front() {
            if self.max_leases - self.granted_leases < entry.leases_requested {
                self.queue.push_front(entry);
                break;
            }

            self.granted_leases += entry.leases_requested;
            if let Some(waker) = entry.waker.take() {
                waker.wake();
            }
        }
    }

    /// Try to enqueue a waiter for the semaphore.
    ///
    /// If the requested number of semaphore leases are available immediately,
    /// `None` will get returned.  Otherwise the waiter will get enqueued
    /// and the associated waiter id returned.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn try_enqueue(
        &mut self,
        leases_requested: usize,
    ) -> Result<Option<num::NonZeroU64>, interface::TpmErr> {
        if leases_requested > self.max_leases {
            return Err(tpm_err_internal!());
        } else if leases_requested == 0 {
            return Ok(None);
        } else if self.queue.is_empty() && self.max_leases - self.granted_leases >= leases_requested
        {
            self.granted_leases += leases_requested;
            return Ok(None);
        }

        if self.queue.capacity() <= self.queue.len() {
            self.queue.try_reserve(1).map_err(|_| tpm_err_rc!(MEMORY))?;
        }

        self.last_waiter_id += 1;
        let waiter_id = num::NonZeroU64::new(self.last_waiter_id).unwrap();
        self.queue.push_back(AsyncSemaphoreQueueEntry {
            leases_requested,
            waker: None,
            waiter_id,
        });
        Ok(Some(waiter_id))
    }
}

/// A semaphore which can be waited asynchronously for.
///
/// The acquire operation [`acquire()`](Self::acquire) returns a future which
/// can be subsequently get polled to obtain the requested number of leases.
pub struct AsyncSemaphore<ST: sync_types::SyncTypes> {
    queue: ST::Lock<AsyncSemaphoreQueue>,
}

impl<ST: sync_types::SyncTypes> AsyncSemaphore<ST> {
    /// Instantiate a new [`AsyncSemaphore`].
    ///
    /// # Arguments:
    ///
    /// * `max_leases` - Maximum number of total semaphore leases which can be
    ///   active at a time.
    pub fn new(max_leases: usize) -> Result<pin::Pin<sync::Arc<Self>>, interface::TpmErr> {
        let this = utils::arc_try_new(Self {
            queue: ST::Lock::from(AsyncSemaphoreQueue::new(max_leases)),
        })?;
        Ok(unsafe { pin::Pin::new_unchecked(this) })
    }

    /// Maximum number of total semaphore leases which can be active at a time.
    pub fn max_leases(&self) -> usize {
        self.queue.lock().max_leases
    }

    /// Asynchronous semaphore lease acquisition.
    ///
    /// Instantiate an [`AsyncSemaphoreWaitFuture`] for asynchronous
    /// acquisition of the specified number of leases, `leases_requested`.
    ///
    /// The returned future will only become ready once all previously submitted
    /// requests have been completed and the semaphore has the requested
    /// number of leases available.
    ///
    ///
    /// # Arguments:
    ///
    /// * `self` - The semaphore to acquire leases from.
    /// * `leases_requested` - The number of leases to obtain.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    /// * [`TpmErr::InternalErr`](interface::TpmErr::InternalErr) - The request
    ///   can never be satisfied, because `leases_requested` exceeds the maximum
    ///   number of leases [`self.max_leases()`](Self::max_leases) which can be
    ///   allotted in total.
    pub fn acquire(
        self: pin::Pin<sync::Arc<Self>>,
        leases_requested: usize,
    ) -> Result<AsyncSemaphoreWaitFuture<ST>, interface::TpmErr> {
        let mut queue = self.queue.lock();
        let waiter_id = queue.try_enqueue(leases_requested)?;
        drop(queue);
        match waiter_id {
            Some(waiter_id) => Ok(AsyncSemaphoreWaitFuture {
                private: AsyncSemaphoreWaitFuturePriv::Enqueued {
                    sem: WeakAsyncSemaphoreRef::new(self),
                    waiter_id,
                    leases_requested,
                },
            }),
            None => Ok(AsyncSemaphoreWaitFuture {
                private: AsyncSemaphoreWaitFuturePriv::LeasesGranted {
                    sem: WeakAsyncSemaphoreRef::new(self),
                    leases_granted: leases_requested,
                },
            }),
        }
    }

    /// Try to synchronously acquire leases from a semaphore.
    ///
    /// The operation will only succeed and return a
    /// [`AsyncSemaphoreLeasesGuard`] if the requested number of leases is
    /// available and there is no other waiter ahead in line.
    /// Otherwise [`None`] will get returned.
    ///
    /// # Arguments:
    ///
    /// * `self` - The semaphore to acquire leases from.
    /// * `leases_requested` - The number of leases to obtain.
    ///
    /// # Errors:
    ///
    /// * [`TpmErr::InternalErr`](interface::TpmErr::InternalErr) - The request
    ///   can never be satisfied, because `leases_requested` exceeds the maximum
    ///   number of leases [`self.max_leases()`](Self::max_leases) which can be
    ///   allotted in total.
    pub fn try_acquire(
        self: pin::Pin<sync::Arc<Self>>,
        leases_requested: usize,
    ) -> Result<Option<AsyncSemaphoreLeasesGuard<ST>>, interface::TpmErr> {
        let mut queue = self.queue.lock();
        if queue.max_leases < leases_requested {
            Err(tpm_err_internal!())
        } else if queue.queue.is_empty()
            && queue.max_leases - queue.granted_leases >= leases_requested
        {
            queue.granted_leases += leases_requested;
            drop(queue);
            Ok(Some(AsyncSemaphoreLeasesGuard {
                sem: self,
                leases_granted: leases_requested,
            }))
        } else {
            Ok(None)
        }
    }
}

// A non-Sync semaphore would be quite pointless.
unsafe impl<ST: sync_types::SyncTypes> Sync for AsyncSemaphore<ST> {}

/// Internal weak reference to an [`AsyncSemaphore`].
///
/// To allow for deallocation of an [`AsyncSemaphore`] with waiters still
/// around, the latter maintain only a weak reference to their associated
/// semaphore.
struct WeakAsyncSemaphoreRef<ST: sync_types::SyncTypes> {
    weak_p: sync::Weak<AsyncSemaphore<ST>>,
}

impl<ST: sync_types::SyncTypes> WeakAsyncSemaphoreRef<ST> {
    /// Downgrade into a weak reference.
    fn new(p: pin::Pin<sync::Arc<AsyncSemaphore<ST>>>) -> Self {
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
    fn upgrade(&self) -> Option<pin::Pin<sync::Arc<AsyncSemaphore<ST>>>> {
        self.weak_p.upgrade().map(|p| {
            // This is safe: self.weak_p originated from a pinned pointer.
            unsafe { pin::Pin::new_unchecked(p) }
        })
    }
}

/// Internal [`AsyncSemaphoreWaitFuture`] state.
enum AsyncSemaphoreWaitFuturePriv<ST: sync_types::SyncTypes> {
    /// The requested number of semaphore leases had been unavailable at
    /// enqueueing time and the waiter got indeed enqueued.
    Enqueued {
        sem: WeakAsyncSemaphoreRef<ST>,
        waiter_id: num::NonZeroU64,
        leases_requested: usize,
    },
    /// The requested number of semaphore leases had been available at
    /// enqueueing time and they got granted right away.
    LeasesGranted {
        sem: WeakAsyncSemaphoreRef<ST>,
        leases_granted: usize,
    },
    /// The future is done: the semaphore leases had been acquired at some time
    /// and polled out to the user.
    Done,
}

/// Asynchronous wait for [`AsyncSemaphore`] leases.
///
/// To be obtained through [`AsyncSemaphore::acquire()`].
///
/// # Note on lifetime management
///
/// An [`AsyncSemaphoreWaitFuture`] instance will only maintain a weak
/// reference (i.e. a [`Weak`](sync::Weak)) to the associated [`AsyncSemaphore`]
/// instance and thus, would not hinder its deallocation. In case the semaphore
/// gets dropped before the future had a chance to acquire leases from it, its
/// `poll()` would return [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct AsyncSemaphoreWaitFuture<ST: sync_types::SyncTypes> {
    private: AsyncSemaphoreWaitFuturePriv<ST>,
}

impl<ST: sync_types::SyncTypes> marker::Unpin for AsyncSemaphoreWaitFuture<ST> {}

impl<ST: sync_types::SyncTypes> future::Future for AsyncSemaphoreWaitFuture<ST> {
    type Output = Result<AsyncSemaphoreLeasesGuard<ST>, interface::TpmErr>;

    /// Poll for lease grants from the associated [`AsyncSemaphore`].
    ///
    /// Upon future completion, either a [`AsyncSemaphoreLeasesGuard`] is
    /// returned or, if the associated [`AsyncSemaphore`] had been dropped
    /// in the meanwhile, an error of
    /// [`TpmRc::RETRY`](interface::TpmRc::RETRY).
    ///
    /// The future must not get polled any further once completed.
    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.get_mut();
        match &this.private {
            AsyncSemaphoreWaitFuturePriv::Enqueued {
                sem,
                waiter_id,
                leases_requested,
            } => {
                let sem = match sem.upgrade() {
                    Some(sem) => sem,
                    None => {
                        // The semaphore is gone, indicating some teardown going on. Let the user
                        // retry to get a more definitive answer.
                        return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                    }
                };
                let mut queue = sem.queue.lock();
                if queue.poll_waiter(*waiter_id, cx.waker().clone()) {
                    drop(queue);
                    let leases_granted = *leases_requested;
                    this.private = AsyncSemaphoreWaitFuturePriv::Done;
                    task::Poll::Ready(Ok(AsyncSemaphoreLeasesGuard {
                        sem,
                        leases_granted,
                    }))
                } else {
                    task::Poll::Pending
                }
            }
            AsyncSemaphoreWaitFuturePriv::LeasesGranted {
                sem,
                leases_granted,
            } => {
                let sem = match sem.upgrade() {
                    Some(sem) => sem,
                    None => {
                        // The semaphore is gone, indicating some teardown going on. Let the user
                        // retry to get a more definitive answer.
                        return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                    }
                };
                let leases_granted = *leases_granted;
                this.private = AsyncSemaphoreWaitFuturePriv::Done;
                task::Poll::Ready(Ok(AsyncSemaphoreLeasesGuard {
                    sem,
                    leases_granted,
                }))
            }
            AsyncSemaphoreWaitFuturePriv::Done => {
                // The semaphore leases had been acquired and handed out already.
                task::Poll::Ready(Err(tpm_err_internal!()))
            }
        }
    }
}

impl<ST: sync_types::SyncTypes> Drop for AsyncSemaphoreWaitFuture<ST> {
    fn drop(&mut self) {
        match &self.private {
            AsyncSemaphoreWaitFuturePriv::Enqueued {
                sem,
                waiter_id,
                leases_requested,
            } => {
                if let Some(sem) = sem.upgrade() {
                    sem.queue
                        .lock()
                        .cancel_waiter(*waiter_id, *leases_requested);
                }
            }
            AsyncSemaphoreWaitFuturePriv::LeasesGranted {
                sem,
                leases_granted,
            } => {
                // The semaphore leases had been granted right from the beginning, but the
                // future never got polled for them. Return the grants.
                if let Some(sem) = sem.upgrade() {
                    sem.queue.lock().return_granted_leases(*leases_granted);
                }
            }
            AsyncSemaphoreWaitFuturePriv::Done => (),
        }
    }
}

/// Leases grant acquired from an [`AsyncSemaphore`].
pub struct AsyncSemaphoreLeasesGuard<ST: sync_types::SyncTypes> {
    sem: pin::Pin<sync::Arc<AsyncSemaphore<ST>>>,
    leases_granted: usize,
}

impl<ST: sync_types::SyncTypes> AsyncSemaphoreLeasesGuard<ST> {
    /// The number of leases acquired from the semaphore.
    pub fn leases(&self) -> usize {
        self.leases_granted
    }

    /// Split the leases grant into two.
    ///
    /// The specified number of `leases` gets split off from `self` and wrapped
    /// in a new [`AsyncSemaphoreLeasesGuard`] instance to be returned.
    ///
    /// This is intended for situations where more than one lease need to get
    /// obtained at once, to avoid deadlocks, for example, but then
    /// subsequently get managed independently.
    ///
    /// # Arguments:
    ///
    /// * `self` - The leases grant to split `leases` off from.
    /// * `leases` - The number of leases to split off from `self`.
    ///
    /// # Errors:
    /// * [`TpmErr::InternalErr`](interface::TpmErr::InternalErr) - The number
    ///   of `leases` to split off exceeds the number of leases owned by `self`.
    pub fn split_leases(&mut self, leases: usize) -> Result<Self, interface::TpmErr> {
        if leases > self.leases_granted {
            Err(tpm_err_internal!())
        } else {
            self.leases_granted -= leases;
            Ok(Self {
                sem: self.sem.clone(),
                leases_granted: leases,
            })
        }
    }
}

impl<ST: sync_types::SyncTypes> Drop for AsyncSemaphoreLeasesGuard<ST> {
    fn drop(&mut self) {
        self.sem
            .queue
            .lock()
            .return_granted_leases(self.leases_granted);
    }
}
