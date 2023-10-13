//! Implementation of [`AsyncSemaphore`]

extern crate alloc;
use crate::interface;
use crate::sync_types::{self, Lock as _};
use crate::utils;
use alloc::{collections, sync};
use core::{future, marker, num, pin, task};

/// Error information returned by the [`AsyncSemaphore`] API.
#[derive(Debug)]
pub enum AsyncSemaphoreError {
    /// The requested number of leases exceeds the inquired
    /// [`AsyncSemaphore`]'s total capacity.
    RequestExceedsSemaphoreCapacity,
    /// Generic error.
    TpmErr(interface::TpmErr),
}

/// Number of leases requested respectively granted from an [`AsyncSemaphore`].
enum AsyncSemaphoreLeaseGrantCount {
    /// A specific number of leases.
    Leases { count: usize },
    /// All of an [`AsyncSemaphore`]'s capacity.
    ExclusiveAll,
}

/// Internal representation of a waiter enqueued to [`AsyncSemaphoreQueue`]
struct AsyncSemaphoreQueueEntry {
    /// The number of leases to acquire.
    leases_requested: AsyncSemaphoreLeaseGrantCount,
    /// The waker to invoke once the requested number of leases becomes
    /// available.
    waker: Option<task::Waker>,
    /// The waiter's assigned id.
    waiter_id: num::NonZeroU64,
}

/// Internal queue of waiters waiting for leases grants on an
/// [`AsyncSemaphore`].
struct AsyncSemaphoreQueue {
    /// The actual wait queue.
    queue: collections::VecDeque<AsyncSemaphoreQueueEntry>,

    /// Number of active leases handed out. They must eventually get returned
    /// via [`return_granted_leases`](Self::return_granted_leases).
    ///
    /// For an [`AsyncSemaphoreLeaseGrantCount::ExclusiveAll`] grant, this
    /// will be one more than the total [`max_leases`](Self::max_leases)
    /// capacity. This ensures that there can only ever be one exlusive
    /// owner around at a time, even with a capacity of zero.
    leases_granted: usize,

    /// Maximum number of leases that can be granted at a time.
    max_leases: usize,

    /// Last waiter id allocated in the course of enqueueing.
    last_waiter_id: u64,
}

impl AsyncSemaphoreQueue {
    fn new(max_leases: usize) -> Self {
        Self {
            queue: collections::VecDeque::new(),
            leases_granted: 0,
            max_leases,
            last_waiter_id: 0,
        }
    }

    /// Match a waiter id to an index in the queue.
    fn waiter_position(&self, waiter_id: num::NonZeroU64) -> Option<usize> {
        self.queue
            .iter()
            .position(|entry| entry.waiter_id == waiter_id)
    }

    /// Poll the semaphore on behalf of a waiter.
    ///
    /// Return `true` if the requested leases have been granted to the waiter,
    /// `false` otherwise.
    fn poll_waiter(&mut self, waiter_id: num::NonZeroU64, waker: task::Waker) -> bool {
        if let Some(index) = self.waiter_position(waiter_id) {
            self.queue[index].waker = Some(waker);
            false
        } else {
            true
        }
    }

    /// Cancel an enqueued waiter.
    ///
    /// Cancelling an enqueued waiter might potentially unblock subsequent
    /// waiters in the queue, so they would get woken in the course of
    /// cancelling.
    fn cancel_waiter(
        &mut self,
        waiter_id: num::NonZeroU64,
        leases_requested: AsyncSemaphoreLeaseGrantCount,
    ) {
        match self.waiter_position(waiter_id) {
            Some(index) => {
                self.queue.remove(index);
                match leases_requested {
                    AsyncSemaphoreLeaseGrantCount::Leases { count } => {
                        // This waiter might have blocked subsequent entries waiting
                        // for a smaller number of leases, which might already be
                        // available. Kick those waiters.
                        if count > 1 {
                            self.wake_completed_waiters();
                        }
                    }
                    AsyncSemaphoreLeaseGrantCount::ExclusiveAll => {
                        // This exclusive waiter might have blocked subsequent entries, kick them.
                        self.wake_completed_waiters();
                    }
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

    /// Remove an enqueued waiter from the queue without further action.
    fn remove_waiter(&mut self, waiter_id: num::NonZeroU64) {
        let index = self.waiter_position(waiter_id).unwrap();
        self.queue.remove(index);
    }

    /// Return granted semaphore leases to the pool.
    ///
    /// Return granted leases back to the pool, making them available to
    /// other waiters again.
    fn return_granted_leases(&mut self, leases: AsyncSemaphoreLeaseGrantCount) {
        match leases {
            AsyncSemaphoreLeaseGrantCount::Leases { count } => {
                debug_assert!(count <= self.leases_granted);
                self.leases_granted -= count;
            }
            AsyncSemaphoreLeaseGrantCount::ExclusiveAll => {
                debug_assert!(self.leases_granted > self.max_leases);
                self.leases_granted = 0;
            }
        }
        self.wake_completed_waiters();
    }

    /// Wake the maximum possible amount of waiters waiting on semaphore lease
    /// grants.
    fn wake_completed_waiters(&mut self) {
        let mut i = 0;
        while i < self.queue.len() {
            let entry = &self.queue[i];
            let leases_requested = match entry.leases_requested {
                AsyncSemaphoreLeaseGrantCount::Leases { count } => {
                    if count > self.max_leases {
                        // The semaphore has been shrunken, skip over this
                        // failed, already woken request.
                        i += 1;
                        continue;
                    }
                    if self.max_leases < count + self.leases_granted {
                        break;
                    }
                    count
                }
                AsyncSemaphoreLeaseGrantCount::ExclusiveAll => {
                    if self.leases_granted != 0 {
                        break;
                    }
                    self.max_leases + 1
                }
            };
            let mut entry = self.queue.remove(i).unwrap();
            self.leases_granted += leases_requested;
            if let Some(waker) = entry.waker.take() {
                waker.wake();
            }
        }
    }

    /// Wake all queued waiters bound for failure.
    ///
    /// Shrinking the [`AsyncSemaphore`] capacity might render some pending
    /// requests unsatisfiable. Wake those for them to notice.
    fn wake_failed_wakers(&mut self) {
        let mut failed_some = false;
        for entry in self.queue.iter_mut() {
            match entry.leases_requested {
                AsyncSemaphoreLeaseGrantCount::Leases { count } if self.max_leases < count => {
                    failed_some = true;
                    if let Some(waker) = entry.waker.take() {
                        waker.wake();
                    }
                }
                _ => (),
            }
        }

        // Some now failed waiter might have blocked subsequent entries waiting
        // for a smaller number of leases, which might already be
        // available. Kick those waiters.
        if failed_some {
            self.wake_completed_waiters();
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
    /// * [`AsyncSemaphoreError::RequestExceedsSemaphoreCapacity`] - The number
    ///   of leases requested exceeds the [`AsyncSemaphore`]'s total capacity.
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn try_enqueue(
        &mut self,
        leases_requested: AsyncSemaphoreLeaseGrantCount,
    ) -> Result<Option<num::NonZeroU64>, AsyncSemaphoreError> {
        match leases_requested {
            AsyncSemaphoreLeaseGrantCount::Leases { count } => {
                if count == 0
                    || (self.queue.is_empty() && self.max_leases >= count + self.leases_granted)
                {
                    self.leases_granted += count;
                    return Ok(None);
                } else if count > self.max_leases {
                    return Err(AsyncSemaphoreError::RequestExceedsSemaphoreCapacity);
                }
            }
            AsyncSemaphoreLeaseGrantCount::ExclusiveAll => {
                if self.leases_granted == 0 {
                    debug_assert!(self.queue.is_empty());
                    self.leases_granted = self.max_leases + 1;
                    return Ok(None);
                }
            }
        };

        if self.queue.capacity() <= self.queue.len() {
            self.queue
                .try_reserve(1)
                .map_err(|_| AsyncSemaphoreError::TpmErr(tpm_err_rc!(MEMORY)))?;
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
    pub fn new(max_leases: usize) -> Result<sync::Arc<Self>, interface::TpmErr> {
        utils::arc_try_new(Self {
            queue: ST::Lock::from(AsyncSemaphoreQueue::new(max_leases)),
        })
    }

    /// Maximum number of total semaphore leases which can be active at a time.
    pub fn max_leases(&self) -> usize {
        self.queue.lock().max_leases
    }

    /// Asynchronously acquire semaphore leases.
    ///
    /// Instantiate an [`AsyncSemaphoreLeasesWaitFuture`] for asynchronous
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
    /// * [`AsyncSemaphoreError::RequestExceedsSemaphoreCapacity`] - The number
    ///   of leases requested exceeds the [`AsyncSemaphore`]'s total capacity.
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn acquire(
        self: &sync::Arc<Self>,
        leases_requested: usize,
    ) -> Result<AsyncSemaphoreLeasesWaitFuture<ST>, AsyncSemaphoreError> {
        let mut queue = self.queue.lock();
        let waiter_id = queue.try_enqueue(AsyncSemaphoreLeaseGrantCount::Leases {
            count: leases_requested,
        })?;
        match waiter_id {
            Some(waiter_id) => Ok(AsyncSemaphoreLeasesWaitFuture {
                private: AsyncSemaphoreLeasesWaitFuturePriv::Enqueued {
                    sem: sync::Arc::downgrade(self),
                    waiter_id,
                    leases_requested,
                },
            }),
            None => Ok(AsyncSemaphoreLeasesWaitFuture {
                private: AsyncSemaphoreLeasesWaitFuturePriv::LeasesGranted {
                    sem: sync::Arc::downgrade(self),
                    leases_granted: leases_requested,
                },
            }),
        }
    }

    /// Asynchronously acquire an exclusive grant on all of a semaphore's
    /// capacity.
    ///
    /// Instantiate an [`AsyncSemaphoreExclusiveAllWaitFuture`] for asynchronous
    /// acquisition of an exclusive grant on all of the [`AsyncSemphore`]'s
    /// capacity.
    ///
    /// The returned future will only become ready once all previously submitted
    /// requests have been completed and the resulting guards dropped again.
    ///
    /// # Arguments:
    ///
    /// * `self` - The semaphore to obtain an exclusive grant on all of its
    ///   capacity from.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn acquire_exclusive_all(
        self: &sync::Arc<Self>,
    ) -> Result<AsyncSemaphoreExclusiveAllWaitFuture<ST>, AsyncSemaphoreError> {
        let mut queue = self.queue.lock();
        let waiter_id = queue.try_enqueue(AsyncSemaphoreLeaseGrantCount::ExclusiveAll)?;
        match waiter_id {
            Some(waiter_id) => Ok(AsyncSemaphoreExclusiveAllWaitFuture {
                private: AsyncSemaphoreExclusiveAllWaitFuturePriv::Enqueued {
                    sem: sync::Arc::downgrade(self),
                    waiter_id,
                },
            }),
            None => Ok(AsyncSemaphoreExclusiveAllWaitFuture {
                private: AsyncSemaphoreExclusiveAllWaitFuturePriv::Granted {
                    sem: sync::Arc::downgrade(self),
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
    /// * [`AsyncSemaphoreError::RequestExceedsSemaphoreCapacity`] - The number
    ///   of leases requested exceeds the [`AsyncSemaphore`]'s total capacity.
    pub fn try_acquire(
        self: &sync::Arc<Self>,
        leases_requested: usize,
    ) -> Result<Option<AsyncSemaphoreLeasesGuard<ST>>, AsyncSemaphoreError> {
        let mut queue = self.queue.lock();
        if queue.max_leases < leases_requested {
            Err(AsyncSemaphoreError::RequestExceedsSemaphoreCapacity)
        } else if queue.queue.is_empty()
            && queue.max_leases - queue.leases_granted >= leases_requested
        {
            queue.leases_granted += leases_requested;
            Ok(Some(AsyncSemaphoreLeasesGuard {
                sem: self.clone(),
                leases_granted: leases_requested,
            }))
        } else {
            Ok(None)
        }
    }

    /// Try to synchronously acquire an exclusive grant on all of a semaphore's
    /// capacity.
    ///
    /// The operation will only succeed and return a
    /// [`AsyncSemaphoreExlusiveAllGuard`] if no other grants of any kind are
    /// active. Otherwise [`None`] will get returned.
    ///
    /// # Arguments:
    ///
    /// * `self` - The semaphore to obtain an exclusive grant on all of its
    ///   capacity from.
    pub fn try_acquire_exclusive_all(
        self: &sync::Arc<Self>,
    ) -> Option<AsyncSemaphoreExclusiveAllGuard<ST>> {
        let mut queue = self.queue.lock();
        if queue.leases_granted == 0 {
            debug_assert!(queue.queue.is_empty());
            queue.leases_granted = queue.max_leases + 1;
            Some(AsyncSemaphoreExclusiveAllGuard { sem: self.clone() })
        } else {
            None
        }
    }
}

// A non-Sync semaphore would be quite pointless.
unsafe impl<ST: sync_types::SyncTypes> Sync for AsyncSemaphore<ST> {}

/// Internal [`AsyncSemaphoreLeasesWaitFuture`] state.
enum AsyncSemaphoreLeasesWaitFuturePriv<ST: sync_types::SyncTypes> {
    /// The requested number of semaphore leases had been unavailable at
    /// enqueueing time and the waiter got indeed enqueued.
    Enqueued {
        sem: sync::Weak<AsyncSemaphore<ST>>,
        waiter_id: num::NonZeroU64,
        leases_requested: usize,
    },
    /// The requested number of semaphore leases had been available at
    /// enqueueing time and they got granted right away.
    LeasesGranted {
        sem: sync::Weak<AsyncSemaphore<ST>>,
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
/// An [`AsyncSemaphoreLeasesWaitFuture`] instance will only maintain a weak
/// reference (i.e. a [`Weak`](sync::Weak)) to the associated [`AsyncSemaphore`]
/// instance and thus, would not hinder its deallocation. In case the semaphore
/// gets dropped before the future had a chance to acquire leases from it, its
/// `poll()` would return [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct AsyncSemaphoreLeasesWaitFuture<ST: sync_types::SyncTypes> {
    private: AsyncSemaphoreLeasesWaitFuturePriv<ST>,
}

impl<ST: sync_types::SyncTypes> marker::Unpin for AsyncSemaphoreLeasesWaitFuture<ST> {}

impl<ST: sync_types::SyncTypes> future::Future for AsyncSemaphoreLeasesWaitFuture<ST> {
    type Output = Result<AsyncSemaphoreLeasesGuard<ST>, AsyncSemaphoreError>;

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
            AsyncSemaphoreLeasesWaitFuturePriv::Enqueued {
                sem,
                waiter_id,
                leases_requested,
            } => {
                let sem = match sem.upgrade() {
                    Some(sem) => sem,
                    None => {
                        // The semaphore is gone, indicating some teardown going on. Let the user
                        // retry to get a more definitive answer.
                        return task::Poll::Ready(Err(AsyncSemaphoreError::TpmErr(tpm_err_rc!(
                            RETRY
                        ))));
                    }
                };
                let mut queue = sem.queue.lock();
                if queue.poll_waiter(*waiter_id, cx.waker().clone()) {
                    let leases_granted = *leases_requested;
                    this.private = AsyncSemaphoreLeasesWaitFuturePriv::Done;
                    task::Poll::Ready(Ok(AsyncSemaphoreLeasesGuard {
                        sem,
                        leases_granted,
                    }))
                } else if queue.max_leases < *leases_requested {
                    // The semaphore's capacity has been shrunken below the number of requested
                    // leases in the meanwhile, fail the request.
                    queue.remove_waiter(*waiter_id);
                    this.private = AsyncSemaphoreLeasesWaitFuturePriv::Done;
                    task::Poll::Ready(Err(AsyncSemaphoreError::RequestExceedsSemaphoreCapacity))
                } else {
                    task::Poll::Pending
                }
            }
            AsyncSemaphoreLeasesWaitFuturePriv::LeasesGranted {
                sem,
                leases_granted,
            } => {
                let sem = match sem.upgrade() {
                    Some(sem) => sem,
                    None => {
                        // The semaphore is gone, indicating some teardown going on. Let the user
                        // retry to get a more definitive answer.
                        return task::Poll::Ready(Err(AsyncSemaphoreError::TpmErr(tpm_err_rc!(
                            RETRY
                        ))));
                    }
                };
                let leases_granted = *leases_granted;
                this.private = AsyncSemaphoreLeasesWaitFuturePriv::Done;
                task::Poll::Ready(Ok(AsyncSemaphoreLeasesGuard {
                    sem,
                    leases_granted,
                }))
            }
            AsyncSemaphoreLeasesWaitFuturePriv::Done => {
                // The semaphore leases had been acquired and handed out already.
                task::Poll::Ready(Err(AsyncSemaphoreError::TpmErr(tpm_err_internal!())))
            }
        }
    }
}

impl<ST: sync_types::SyncTypes> Drop for AsyncSemaphoreLeasesWaitFuture<ST> {
    fn drop(&mut self) {
        match &self.private {
            AsyncSemaphoreLeasesWaitFuturePriv::Enqueued {
                sem,
                waiter_id,
                leases_requested,
            } => {
                if let Some(sem) = sem.upgrade() {
                    sem.queue.lock().cancel_waiter(
                        *waiter_id,
                        AsyncSemaphoreLeaseGrantCount::Leases {
                            count: *leases_requested,
                        },
                    );
                }
            }
            AsyncSemaphoreLeasesWaitFuturePriv::LeasesGranted {
                sem,
                leases_granted,
            } => {
                if *leases_granted != 0 {
                    // The semaphore leases had been granted right from the beginning, but the
                    // future never got polled for them. Return the grants.
                    if let Some(sem) = sem.upgrade() {
                        sem.queue.lock().return_granted_leases(
                            AsyncSemaphoreLeaseGrantCount::Leases {
                                count: *leases_granted,
                            },
                        );
                    }
                }
            }
            AsyncSemaphoreLeasesWaitFuturePriv::Done => (),
        }
    }
}

/// Leases grant acquired from an [`AsyncSemaphore`].
pub struct AsyncSemaphoreLeasesGuard<ST: sync_types::SyncTypes> {
    sem: sync::Arc<AsyncSemaphore<ST>>,
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

    /// Permanently remove the the owned leases from the associated
    /// [`AsyncSemaphore`]'s capacity.
    ///
    /// Note that this might potentially make some other, still enqueued waiters
    /// to
    /// fail with [`RequestExceedsSemaphoreCapacity`](AsyncSemaphoreError::RequestExceedsSemaphoreCapacity)
    /// in case their number of leases requested would now exceed the remaining
    /// capacity.
    pub fn leak(mut self) {
        let mut queue = self.sem.queue.lock();
        debug_assert!(queue.max_leases >= self.leases_granted);
        queue.max_leases -= self.leases_granted;
        debug_assert!(queue.leases_granted >= self.leases_granted);
        queue.leases_granted -= self.leases_granted;
        self.leases_granted = 0;

        // Shrinking the semaphore capcacity might have rendered some pending requests
        // unsatisfiable. Wake them.
        queue.wake_failed_wakers();
    }
}

impl<ST: sync_types::SyncTypes> Drop for AsyncSemaphoreLeasesGuard<ST> {
    fn drop(&mut self) {
        if self.leases_granted == 0 {
            return;
        }

        self.sem
            .queue
            .lock()
            .return_granted_leases(AsyncSemaphoreLeaseGrantCount::Leases {
                count: self.leases_granted,
            });
    }
}

/// Internal [`AsyncSemaphoreExclusiveAllWaitFuture`] state.
enum AsyncSemaphoreExclusiveAllWaitFuturePriv<ST: sync_types::SyncTypes> {
    /// The exclusive grant on all of the semaphore's capcaity had been
    /// unavailable at enqueueing time and the waiter got indeed enqueued.
    Enqueued {
        sem: sync::Weak<AsyncSemaphore<ST>>,
        waiter_id: num::NonZeroU64,
    },
    /// All of the semaphore's capacity had been free at enqueueing time and the
    /// exclusive grant got issued right away.
    Granted { sem: sync::Weak<AsyncSemaphore<ST>> },
    /// The future is done: the exclusive grant had been acquired at some time
    /// and polled out to the user.
    Done,
}

/// Asynchronous wait for an exclusive grant on all of an [`AsyncSemaphore`]'s
/// capacity.
///
/// To be obtained through [`AsyncSemaphore::acquire_exclusive_all()`].
///
/// # Note on lifetime management
///
/// An [`AsyncSemaphoreExclusiveAllWaitFuture`] instance will only maintain a
/// weak reference (i.e. a [`Weak`](sync::Weak)) to the associated
/// [`AsyncSemaphore`] instance and thus, would not hinder its deallocation. In
/// case the semaphore gets dropped before the future had a chance to acquire
/// the exclusive grant on it, its `poll()` would return
/// [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct AsyncSemaphoreExclusiveAllWaitFuture<ST: sync_types::SyncTypes> {
    private: AsyncSemaphoreExclusiveAllWaitFuturePriv<ST>,
}

impl<ST: sync_types::SyncTypes> marker::Unpin for AsyncSemaphoreExclusiveAllWaitFuture<ST> {}

impl<ST: sync_types::SyncTypes> future::Future for AsyncSemaphoreExclusiveAllWaitFuture<ST> {
    type Output = Result<AsyncSemaphoreExclusiveAllGuard<ST>, AsyncSemaphoreError>;

    /// Poll for an exclusive grant on all of the associated
    /// [`AsyncSemaphore`]'s capacity.
    ///
    /// Upon future completion, either a [`AsyncSemaphoreExclusiveAllGuard`] is
    /// returned or if the associated [`AsyncSemaphore`] had been dropped in the
    /// meanwhile, an error of [`TpmRc::RETRY`](interface::TpmRc::RETRY).
    ///
    /// The future must not get polled any further once completed.
    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.get_mut();
        match &this.private {
            AsyncSemaphoreExclusiveAllWaitFuturePriv::Enqueued { sem, waiter_id } => {
                let sem = match sem.upgrade() {
                    Some(sem) => sem,
                    None => {
                        // The semaphore is gone, indicating some teardown going on. Let the user
                        // retry to get a more definitive answer.
                        return task::Poll::Ready(Err(AsyncSemaphoreError::TpmErr(tpm_err_rc!(
                            RETRY
                        ))));
                    }
                };
                let mut queue = sem.queue.lock();
                if queue.poll_waiter(*waiter_id, cx.waker().clone()) {
                    this.private = AsyncSemaphoreExclusiveAllWaitFuturePriv::Done;
                    task::Poll::Ready(Ok(AsyncSemaphoreExclusiveAllGuard { sem }))
                } else {
                    task::Poll::Pending
                }
            }
            AsyncSemaphoreExclusiveAllWaitFuturePriv::Granted { sem } => {
                let sem = match sem.upgrade() {
                    Some(sem) => sem,
                    None => {
                        // The semaphore is gone, indicating some teardown going on. Let the user
                        // retry to get a more definitive answer.
                        return task::Poll::Ready(Err(AsyncSemaphoreError::TpmErr(tpm_err_rc!(
                            RETRY
                        ))));
                    }
                };
                this.private = AsyncSemaphoreExclusiveAllWaitFuturePriv::Done;
                task::Poll::Ready(Ok(AsyncSemaphoreExclusiveAllGuard { sem }))
            }
            AsyncSemaphoreExclusiveAllWaitFuturePriv::Done => {
                // The semaphore leases had been acquired and handed out already.
                task::Poll::Ready(Err(AsyncSemaphoreError::TpmErr(tpm_err_internal!())))
            }
        }
    }
}

impl<ST: sync_types::SyncTypes> Drop for AsyncSemaphoreExclusiveAllWaitFuture<ST> {
    fn drop(&mut self) {
        match &self.private {
            AsyncSemaphoreExclusiveAllWaitFuturePriv::Enqueued { sem, waiter_id } => {
                if let Some(sem) = sem.upgrade() {
                    sem.queue
                        .lock()
                        .cancel_waiter(*waiter_id, AsyncSemaphoreLeaseGrantCount::ExclusiveAll);
                }
            }
            AsyncSemaphoreExclusiveAllWaitFuturePriv::Granted { sem } => {
                // The exclusive grant had been issued right from the beginning, but the
                // future never got polled for it. Return the grants.
                if let Some(sem) = sem.upgrade() {
                    sem.queue
                        .lock()
                        .return_granted_leases(AsyncSemaphoreLeaseGrantCount::ExclusiveAll);
                }
            }
            AsyncSemaphoreExclusiveAllWaitFuturePriv::Done => (),
        }
    }
}

/// Exclusive grant on all of an [`AsyncSemaphore`]'s capacity.
///
/// As long as [`AsyncSemaphoreExclusiveAllGuard`] is alive, it is guaranteed
/// that there aren't any other (non-trivial) grants active on the associated
/// [`AsyncSemaphore`].
pub struct AsyncSemaphoreExclusiveAllGuard<ST: sync_types::SyncTypes> {
    sem: sync::Arc<AsyncSemaphore<ST>>,
}

impl<ST: sync_types::SyncTypes> AsyncSemaphoreExclusiveAllGuard<ST> {
    /// Grow or shrink the associated [`AsyncSemaphore`]'s capacity.
    ///
    /// Independent of whether the capacity is being in- or decreased,
    /// all of it will still be exclusively owned by `self`.
    ///
    /// Note that shrinking the capacity might potentially make some other,
    /// still enqueued waiters to fail with
    /// [`RequestExceedsSemaphoreCapacity`](AsyncSemaphoreError::RequestExceedsSemaphoreCapacity) in
    /// case their number of leases requested would now exceed the remaining
    /// capacity.
    pub fn resize_future(&mut self, max_leases: usize) {
        let mut queue = self.sem.queue.lock();
        let capacity_shrunken = max_leases < queue.max_leases;
        queue.max_leases = max_leases;
        queue.leases_granted = max_leases + 1;
        // Shrinking the capacity might render some pending requests unsatisfiable.
        if capacity_shrunken {
            queue.wake_failed_wakers();
        }
    }

    /// Downgrade the exclusive grant on all of a semaphore's capacity to a
    /// regular grant.
    ///
    /// The exclusive grant will be downgraded to a regular grant on all
    /// of the associated [`AsyncSempaphore`]'s capacity. This may beed in
    /// case the full grant needs to be
    /// [split](AsyncSemaphoreLeaseGuard::split_leases] into smaller ones.
    pub fn downgrade(self) -> AsyncSemaphoreLeasesGuard<ST> {
        let Self { sem } = self;
        let mut queue = sem.queue.lock();
        queue.leases_granted = queue.max_leases;
        AsyncSemaphoreLeasesGuard {
            sem,
            leases_granted: queue.leases_granted,
        }
    }
}

impl<ST: sync_types::SyncTypes> Drop for AsyncSemaphoreExclusiveAllGuard<ST> {
    fn drop(&mut self) {
        self.sem
            .queue
            .lock()
            .return_granted_leases(AsyncSemaphoreLeaseGrantCount::ExclusiveAll);
    }
}
