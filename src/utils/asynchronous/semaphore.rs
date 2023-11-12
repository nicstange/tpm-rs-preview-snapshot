// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`AsyncSemaphore`]

extern crate alloc;
use crate::interface;
use crate::sync_types::{self, Lock as _};
use crate::utils;
use alloc::{collections, sync};
use core::sync::atomic;
use core::{cell, convert, future, marker, num, ops, pin, task};

/// Error information returned by the [`AsyncSemaphore`] API.
#[derive(Debug)]
pub enum AsyncSemaphoreError {
    /// The requested number of leases exceeds the inquired
    /// [`AsyncSemaphore`]'s total capacity.
    RequestExceedsSemaphoreCapacity,
    /// Generic error.
    TpmErr(interface::TpmErr),
}

/// Internal representation of the number/type of leases requested respectively
/// granted from an [`AsyncSemaphore`].
enum AsyncSemaphoreLeaseGrantCount {
    /// "Trivial" grant for zero leases, mutually exclusive with
    /// [`ExclusiveAll`](Self::ExclusiveAll) grants.
    TrivialLease,
    /// A specific, non-zero number of leases.
    Leases { count: num::NonZeroUsize },
    /// All of an [`AsyncSemaphore`]'s capacity. Mutually exclusive with any
    /// other grant of any type, including itself.
    ExclusiveAll,
}

impl convert::From<usize> for AsyncSemaphoreLeaseGrantCount {
    fn from(value: usize) -> Self {
        if value == 0 {
            AsyncSemaphoreLeaseGrantCount::TrivialLease
        } else {
            AsyncSemaphoreLeaseGrantCount::Leases {
                count: num::NonZeroUsize::new(value).unwrap(),
            }
        }
    }
}

/// Internal representation of a waiter enqueued to [`AsyncSemaphoreQueue`].
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

    /// Maximum number of leases that can be granted at a time.
    max_leases: usize,

    /// Last waiter id allocated in the course of enqueueing.
    last_waiter_id: u64,

    /// Number of currently enqueued
    /// [`TrivialLease`](AsyncSemaphoreLeaseGrantCount::TrivialLease) waiters.
    enqueued_trivial_lease_waiters: usize,
    /// Number of currently enqueued
    /// [`Exclusive`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) waiters.
    enqueued_exclusive_all_waiters: usize,
}

impl AsyncSemaphoreQueue {
    /// Create a new [`AsyncSemaphoreQueue`] instance.
    fn new(max_leases: usize) -> Self {
        Self {
            queue: collections::VecDeque::new(),
            max_leases,
            last_waiter_id: 0,
            enqueued_trivial_lease_waiters: 0,
            enqueued_exclusive_all_waiters: 0,
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
    ///
    /// In general, uncompleted waiters are still on the queue, completes are
    /// not.
    ///
    /// # Arguments:
    ///
    /// * `waiter_id` - The waiter id, as previously returned by
    ///   [`enqueue_waiter()`](Self::enqueue_waiter) of the enqueued waiter
    ///   instance to check for completion.
    /// * `waker` - The waker to register at the enqueued waiter entry in case
    ///   the waiter is not ready yet.
    fn poll_waiter(&mut self, waiter_id: num::NonZeroU64, waker: task::Waker) -> bool {
        if let Some(index) = self.waiter_position(waiter_id) {
            self.queue[index].waker = Some(waker);
            false
        } else {
            true
        }
    }

    /// Remove a waiter from the queue and update the queue's internal
    /// bookkeeping, but take no action beyond that.
    ///
    /// # Arguments:
    ///
    /// * `index` - Index within the queue of the waiter entry to remove.
    fn remove_entry(&mut self, index: usize) {
        match self.queue[index].leases_requested {
            AsyncSemaphoreLeaseGrantCount::TrivialLease => {
                debug_assert!(self.enqueued_trivial_lease_waiters != 0);
                self.enqueued_trivial_lease_waiters -= 1;
            }
            AsyncSemaphoreLeaseGrantCount::ExclusiveAll => {
                debug_assert!(self.enqueued_exclusive_all_waiters != 0);
                self.enqueued_exclusive_all_waiters -= 1;
            }
            AsyncSemaphoreLeaseGrantCount::Leases { .. } => (),
        }
        self.queue.remove(index);
    }

    /// Remove an enqueued waiter from the queue by `waiter_id` and update the
    /// queues internal bookkeeping, but take no action beyond that.
    ///
    /// # Arguments:
    ///
    /// * `waiter_id` - The waiter id as previously returned by
    ///   [`enqueue_waiter()`](Self::enqueue_waiter) of the waiter entry to
    ///   remove from the queue..
    fn remove_waiter(&mut self, waiter_id: num::NonZeroU64) {
        let index = self.waiter_position(waiter_id).unwrap();
        self.remove_entry(index);
    }

    /// Enqueue a waiter for the semaphore and update the queue's internal
    /// bookkeeping.
    ///
    /// # Arguments:
    ///
    /// * `leases_requested` - The request number/type of leases to record at
    ///   the newly created waiter entry.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn enqueue_waiter(
        &mut self,
        leases_requested: AsyncSemaphoreLeaseGrantCount,
    ) -> Result<num::NonZeroU64, interface::TpmErr> {
        if self.queue.capacity() <= self.queue.len() {
            self.queue.try_reserve(1).map_err(|_| tpm_err_rc!(MEMORY))?;
        }

        match leases_requested {
            AsyncSemaphoreLeaseGrantCount::TrivialLease => {
                self.enqueued_trivial_lease_waiters += 1;
            }
            AsyncSemaphoreLeaseGrantCount::ExclusiveAll => {
                self.enqueued_exclusive_all_waiters += 1;
            }
            AsyncSemaphoreLeaseGrantCount::Leases { .. } => (),
        }

        self.last_waiter_id += 1;
        let waiter_id = num::NonZeroU64::new(self.last_waiter_id).unwrap();
        self.queue.push_back(AsyncSemaphoreQueueEntry {
            leases_requested,
            waker: None,
            waiter_id,
        });
        Ok(waiter_id)
    }

    /// Check whether the queue has any uncancelled waiters enqueued.
    fn has_uncancelled_waiters(&self) -> bool {
        self.queue.iter().any(|entry| match entry.leases_requested {
            AsyncSemaphoreLeaseGrantCount::TrivialLease => true,
            AsyncSemaphoreLeaseGrantCount::Leases { count } => count.get() <= self.max_leases,
            AsyncSemaphoreLeaseGrantCount::ExclusiveAll => true,
        })
    }

    /// Check whether the queue has any
    /// [`TrivialLease`](AsyncSemaphoreLeaseGrantCount::TrivialLease) waiters
    /// enqueued.
    fn has_trivial_lease_waiters(&self) -> bool {
        let has_trivial_lease_waiters = self.enqueued_trivial_lease_waiters != 0;
        debug_assert_eq!(
            has_trivial_lease_waiters,
            self.queue.iter().any(|entry| {
                matches!(
                    entry.leases_requested,
                    AsyncSemaphoreLeaseGrantCount::TrivialLease
                )
            })
        );
        has_trivial_lease_waiters
    }

    /// Check whether the queue has any
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) waiters
    /// enqueued.
    fn has_exclusive_all_waiters(&self) -> bool {
        let has_exclusive_all_waiters = self.enqueued_exclusive_all_waiters != 0;
        debug_assert_eq!(
            has_exclusive_all_waiters,
            self.queue.iter().any(|entry| {
                matches!(
                    entry.leases_requested,
                    AsyncSemaphoreLeaseGrantCount::ExclusiveAll
                )
            })
        );
        has_exclusive_all_waiters
    }
}

/// An [`AsyncSemaphore`]'s state.
///
/// The semaphore state is maintained in a separate `struct` because it,
/// and the associated maintenance logic in particular, is independent of
/// of the user-specified generic type of the data wrapped in an
/// [`AsyncSemaphore`].
struct AsyncSemaphoreState<ST: sync_types::SyncTypes> {
    queue: ST::Lock<AsyncSemaphoreQueue>,
    /// Number of active,
    /// non-[trivial](AsyncSemaphoreLeaseGrantCount::TrivialLease) lease grants
    /// handed out. They must eventually get returned
    /// via [`return_grant()`](Self::return_grant).
    ///
    /// For an [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll)
    /// grant, this will be one more than the total
    /// [`max_leases`](Self::max_leases) capacity. This ensures that there
    /// can only ever be one exlusive owner around at a time, even with a
    /// capacity of zero.
    ///
    /// The zero-sized
    /// [`TrivialLease`](AsyncSemaphoreLeaseGrantCount::TrivialLease) grants
    /// are tracked separately in
    /// [`trivial_leases_granted`](Self::trivial_leases_granted).
    ///
    /// Note that `leases_granted` itself is updated only under the
    /// [`Self::queue`] lock, but read from without that lock being held in
    /// [`return_trivial_lease_grant()`](Self::return_trivial_lease_grant).
    leases_granted: atomic::AtomicUsize,

    /// Number of active, zero-sized
    /// [`TrivialLease`](AsyncSemaphoreLeaseGrantCount::TrivialLease) grants
    /// handed out.
    trivial_leases_granted: atomic::AtomicUsize,
}

impl<ST: sync_types::SyncTypes> AsyncSemaphoreState<ST> {
    /// Constant offset added to
    /// [`trivial_leases_granted`](Self::trivial_leases_granted) whenever no
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) waiter
    /// is enqueued on the [`queue`](Self::queue).
    ///
    /// This is an optimization to disable the wake-up path in
    /// [`return_trivial_lease_grant()`](Self::return_trivial_lease_grant).
    /// when not needed.
    const TRIVIAL_LEASES_GRANTED_NO_EXCLUSIVE_ALL_WAITERS_OFFSET: usize = 1;

    /// Instantiate a [`AsyncSemaphoreState`] for a [`AsyncSemaphore`] with
    /// specified capacity.
    ///
    /// # Arguments:
    ///
    /// * `max_leases` - The containg [`AsyncSemaphore`]'s desired capacity.
    ///   Must be **strictly** less than [`usize::MAX`].
    fn new(max_leases: usize) -> Self {
        debug_assert!(max_leases < usize::MAX);
        Self {
            queue: ST::Lock::from(AsyncSemaphoreQueue::new(max_leases)),
            leases_granted: atomic::AtomicUsize::new(0),
            trivial_leases_granted: atomic::AtomicUsize::new(
                Self::TRIVIAL_LEASES_GRANTED_NO_EXCLUSIVE_ALL_WAITERS_OFFSET,
            ),
        }
    }

    /// Maximum number of total semaphore leases which can be active at a time.
    fn max_leases(&self) -> usize {
        self.queue.lock().max_leases
    }

    /// Prepare to asynchronously acquire semaphore leases.
    ///
    /// * If the number of requested leases cannot be granted right away, a
    ///   waiter entry will be enqueued and the associated waiter id returned.
    ///   The waiter **must** eventually get removed again either
    ///   - implicitly by getting completed asynchronously through
    ///     [`wake_completed_waiters()`](Self::wake_completed_waiters),
    ///   - explicitly through [`cancel_waiter()`](Self::cancel_waiter) or, upon
    ///     getting asynchronously [failed](Self::wake_failed_waiters), via
    ///     [`remove_waiter`](AsyncSemaphoreQueue::remove_waiter).
    ///   It is imperative to wrap the returned waiter id in an RAAIsh type
    ///   as soon as possible without intermediate potential failure points.
    /// * If the number of leases can get granted right away, `None` will get
    ///   returned. The granted leases must eventually get returned via
    ///   [`return_grant()`](Self::return_grant), or, as an optimization, via
    ///   [`return_trivial_lease_grant()`](Self::return_trivial_lease_grant) if
    ///   applicable.
    ///
    /// # Arguments:
    ///
    /// * `leases_requested` - The number of leases to obtain. May be zero for
    ///   requesting a [trivial](AsyncSemaphoreLeaseGrantCount::TrivialLease)
    ///   lease.
    ///
    /// # Errors:
    ///
    /// * [`AsyncSemaphoreError::RequestExceedsSemaphoreCapacity`] - The number
    ///   of leases requested exceeds the [`AsyncSemaphore`]'s total capacity.
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn prepare_acquire_leases(
        &self,
        leases_requested: usize,
    ) -> Result<Option<num::NonZeroU64>, AsyncSemaphoreError> {
        let mut locked_queue = self.queue.lock();
        if self._try_acquire_leases(&locked_queue, leases_requested)? {
            Ok(None)
        } else {
            let waiter_id = locked_queue
                .enqueue_waiter(AsyncSemaphoreLeaseGrantCount::from(leases_requested))
                .map_err(AsyncSemaphoreError::TpmErr)?;
            Ok(Some(waiter_id))
        }
    }

    /// Prepare to asynchronously acquire an
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll)
    /// grant on all of a semaphore's capacity.
    ///
    /// * If the [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll)
    ///   grant cannot get issued right away, a waiter entry will be enqueued
    ///   and the associated waiter id returned. The waiter **must** eventually
    ///   get removed again either
    ///   - implicitly by getting completed asynchronously through
    ///     [`wake_completed_waiters()`](Self::wake_completed_waiters),
    ///   - explicitly through [`cancel_waiter()`](Self::cancel_waiter).
    ///   It is imperative to wrap the returned waiter id in an RAAIsh type
    ///   as soon as possible without intermediate potential failure points.
    /// * If the [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll)
    ///   grant can get issued right away, `None` will get returned. The grant
    ///   must eventually get returned via
    ///   [`return_grant()`](Self::return_grant).
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn prepare_acquire_exclusive_all(&self) -> Result<Option<num::NonZeroU64>, interface::TpmErr> {
        let mut locked_queue = self.queue.lock();
        self.acquire_exclusive_all_begin(&locked_queue);
        if self._try_acquire_exclusive_all(&locked_queue) {
            self.acquire_exclusive_all_end(&locked_queue);
            Ok(None)
        } else {
            let waiter_id =
                match locked_queue.enqueue_waiter(AsyncSemaphoreLeaseGrantCount::ExclusiveAll) {
                    Ok(waiter_id) => waiter_id,
                    Err(e) => {
                        self.acquire_exclusive_all_end(&locked_queue);
                        return Err(e);
                    }
                };
            Ok(Some(waiter_id))
        }
    }

    /// Try to synchronously acquire a leases grant.
    ///
    /// Simple wrapper around
    /// [`_try_acquire_leases()`](Self::_try_acquire_leases) establishing the
    /// [`queue`](Self::queue) lock.
    fn try_acquire_leases(&self, leases_requested: usize) -> Result<bool, AsyncSemaphoreError> {
        let locked_queue = self.queue.lock();
        self._try_acquire_leases(&locked_queue, leases_requested)
    }

    /// Try to synchronously acquire an
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) grant on
    /// all of a semaphore's capacity with the [`queue`](Self::queue) lock
    /// held.
    ///
    /// Simple wrapper around
    /// [`_try_acquire_exclusive_all()`](Self::_try_acquire_exclusive_all)
    /// establishing the [`queue`](Self::queue) lock and issuing a
    /// [`acquire_exclusive_all_begin()`](Self::acquire_exclusive_all_begin)/
    /// [`acquire_exclusive_all_end()`](Self::acquire_exclusive_all_end) pair
    /// around the call.
    pub fn try_acquire_exclusive_all(&self) -> bool {
        let locked_queue = self.queue.lock();
        self.acquire_exclusive_all_begin(&locked_queue);
        let granted = self._try_acquire_exclusive_all(&locked_queue);
        self.acquire_exclusive_all_end(&locked_queue);
        granted
    }

    /// Try to synchronously obtain a
    /// [`TrivialLease`](AsyncSemaphoreLeaseGrantCount::TrivialLease),
    /// if available, with the [`queue`](Self::queue) lock held.
    ///
    /// The operation will only succeed and return `true` if there is no
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) waiter
    /// ahead in line. Otherwise `false` will get returned.
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    fn _try_acquire_trivial_lease(
        &self,
        locked_queue: &<ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<
                                          AsyncSemaphoreQueue,
                                      >>::Guard<'_>,
    ) -> bool {
        !locked_queue.has_exclusive_all_waiters()
            && self.try_grant_one(locked_queue, &AsyncSemaphoreLeaseGrantCount::TrivialLease)
    }

    /// Try to synchronously acquire a leases grant with the
    /// [`queue`](Self::queue) lock held.
    ///
    /// The operation will only succeed and return `true` if the requested
    /// number of leases is available, no
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) grant is
    /// active, and there is no other waiter ahead in line.  Otherwise
    /// `false` will get returned.
    ///
    /// In the case of success, the granted leases must eventually get returned
    /// via [`return_grant()`](Self::return_grant), or, as an optimization,
    /// via
    /// [`return_trivial_lease_grant()`](Self::return_trivial_lease_grant) if
    /// applicable
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    /// * `leases_requested` - The number of leases to obtain. May be zero for
    ///   requesting a [trivial](AsyncSemaphoreLeaseGrantCount::TrivialLease)
    ///   lease.
    ///
    /// # Errors:
    ///
    /// * [`AsyncSemaphoreError::RequestExceedsSemaphoreCapacity`] - The number
    ///   of leases requested exceeds the [`AsyncSemaphore`]'s total capacity.
    fn _try_acquire_leases(
        &self,
        locked_queue: &<ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<
                                   AsyncSemaphoreQueue,
                               >>::Guard<'_>,
        leases_requested: usize,
    ) -> Result<bool, AsyncSemaphoreError> {
        if leases_requested == 0 {
            Ok(self._try_acquire_trivial_lease(locked_queue))
        } else if locked_queue.max_leases < leases_requested {
            Err(AsyncSemaphoreError::RequestExceedsSemaphoreCapacity)
        } else if !locked_queue.has_uncancelled_waiters()
            && self.try_grant_one(
                locked_queue,
                &AsyncSemaphoreLeaseGrantCount::from(leases_requested),
            )
        {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Try to synchronously acquire an
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) grant on
    /// all of a semaphore's capacity with the [`queue`](Self::queue) lock
    /// held.
    ///
    /// The call **must** be wrapped in an
    /// [`acquire_exclusive_all_begin()`](Self::acquire_exclusive_all_begin)/
    /// [`acquire_exclusive_all_end()`](Self::acquire_exclusive_all_end) pair or
    /// it will fail unconditionally.
    ///
    /// The operation will only succeed and return `true` if no other grants of
    /// any kind are active. Otherwise `false` will get returned.
    ///
    /// In the case of success, the grant must eventually get returned
    /// via [`return_grant()`](Self::return_grant).
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    pub fn _try_acquire_exclusive_all(
        &self,
        locked_queue: &<ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<
                AsyncSemaphoreQueue,
            >>::Guard<'_>,
    ) -> bool {
        !locked_queue.has_uncancelled_waiters()
            && self.try_grant_one(locked_queue, &AsyncSemaphoreLeaseGrantCount::ExclusiveAll)
    }

    /// Try to issue a grant assuming the request is due next in
    /// [`queue`](Self::queue) order.
    ///
    /// [`try_grant_one()`](Self::try_grant_one) exclusively considers currently
    /// issued grants only, and is completely oblivious of any waiters
    /// enqueued on the [`queue`](Self::queue). In particular, queue order
    /// logic must get maintained externally. More specifically
    /// * For [`TrivialLease`](AsyncSemaphoreLeaseGrantCount::TrivialLease)
    ///   requests, no
    ///   [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) waiters
    ///   may be enqueued ahead in line.
    /// * For "reqular" [`Leases`](AsyncSemaphoreLeaseGrantCount::Leases)
    ///   requests, no
    ///   [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) or
    ///   (uncancelled) other [`Leases`](AsyncSemaphoreLeaseGrantCount::Leases)
    ///   waiters may be ahead in line.
    /// * For [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll)
    ///   requests, no other (uncancelled) waiters of any type may be ahead in
    ///   line.
    ///
    /// The operation will succeed with `true` if the requested grant can be
    /// issued, otherwise `false` will get returned. In the former case, the
    /// associated grant must eventually get returned via
    /// [`return_grant()`](Self::return_grant).
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    /// * `leases_requested` - The grant to obtain.
    fn try_grant_one(
        &self,
        locked_queue: &<ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<AsyncSemaphoreQueue>>::Guard<'_>,
        leases_requested: &AsyncSemaphoreLeaseGrantCount,
    ) -> bool {
        match leases_requested {
            AsyncSemaphoreLeaseGrantCount::TrivialLease => {
                if !self.is_exclusive_all_granted(locked_queue) {
                    self.trivial_leases_granted
                        .fetch_add(1, atomic::Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            AsyncSemaphoreLeaseGrantCount::Leases { count } => {
                let leases_granted = self.leases_granted.load(atomic::Ordering::Relaxed);
                debug_assert!(count.get() <= locked_queue.max_leases);
                if locked_queue.max_leases >= leases_granted + count.get() {
                    self.leases_granted
                        .store(leases_granted + count.get(), atomic::Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            AsyncSemaphoreLeaseGrantCount::ExclusiveAll => {
                // The Acquire pairs with Release in return_grant(), it ensures that
                // 1.) any prior trivial_leases_grant split out from
                //     non-trivial ones (in another thread) are also observed here and
                // 2.) that the zeroization of leases_granted, if any, happens-before
                //     the SeqCst fence below.
                // (Both should be achieved by locked_queue held here and in
                // return_grant() already,  but don't rely on
                // implementation details and make it explicit).
                let leases_granted = self.leases_granted.load(atomic::Ordering::Acquire);
                if leases_granted == 0 {
                    // Issue a SeqCst fence between the preceeding zeroization, if any, and the test
                    // of trivial_leases_granted. Pairs with the fence in
                    // return_trivial_lease_grant(), c.f. the comment there.
                    atomic::fence(atomic::Ordering::SeqCst);
                    let trivial_leases_granted =
                        self.trivial_leases_granted.load(atomic::Ordering::Relaxed);
                    if trivial_leases_granted == 0 {
                        self.leases_granted
                            .store(locked_queue.max_leases + 1, atomic::Ordering::Relaxed);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Preparatory setup for acquiring an
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) grant,
    /// either asynchronously or synchronously.
    ///
    /// Before attempting to acquire some
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) grant, the
    /// [`trivial_leases_granted`](Self::trivial_leases_granted) tracking
    /// counter must get decremented by
    /// the [`TRIVIAL_LEASES_GRANTED_NO_EXCLUSIVE_ALL_WAITERS_OFFSET`](Self::TRIVIAL_LEASES_GRANTED_NO_EXCLUSIVE_ALL_WAITERS_OFFSET)
    /// in order to
    /// - make the request satisifiable in the first place, as
    ///   [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) grants
    ///   will be issued only when
    ///   [`trivial_leases_granted`](Self::trivial_leases_granted) reaches zero
    ///   and
    /// - to arm the wakeup path in
    ///   [`return_trivial_lease_grant()`](Self::return_trivial_lease_grant).
    ///
    /// The setup must eventually be undone by
    /// [`acquire_exclusive_all_end()`](Self::acquire_exclusive_all_end).
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    fn acquire_exclusive_all_begin(
        &self,
        locked_queue: &<ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<AsyncSemaphoreQueue>>::Guard<'_>,
    ) {
        if !locked_queue.has_exclusive_all_waiters() {
            // The first one, arm the wake-up path in return_trivial_lease_grant(), and
            // also, enable the ExlusiveAll grant in the first place.
            debug_assert_ne!(
                self.trivial_leases_granted.load(atomic::Ordering::Relaxed),
                0
            );
            self.trivial_leases_granted.fetch_sub(
                Self::TRIVIAL_LEASES_GRANTED_NO_EXCLUSIVE_ALL_WAITERS_OFFSET,
                atomic::Ordering::Relaxed,
            );
        }
    }

    /// Teardown the setup established by a previous
    /// [`acquire_exclusive_all_begin()`](Self::acquire_exclusive_all_begin).
    ///
    /// If
    /// - there had been no waiter enqueued for the associated request ever, the
    ///   `locked_queue` guard must not have been dropped at any point inbetween
    ///   the calls to
    ///   [`acquire_exclusive_all_begin()`](Self::acquire_exclusive_all_begin)
    ///   and [`acquire_exclusive_all_end()`](Self::acquire_exclusive_all_end),
    /// - there had been a waiter enqueued for the associated request, it must
    ///   have been removed before the call to
    ///   [`acquire_exclusive_all_end()`](Self::acquire_exclusive_all_end) and
    ///   `locked_queue` must not have been dropped at any point in time between
    ///   the removal from the queue and the invocation.
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    fn acquire_exclusive_all_end(
        &self,
        locked_queue: &<ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<AsyncSemaphoreQueue>>::Guard<'_>,
    ) {
        if !locked_queue.has_exclusive_all_waiters() {
            // That's been the last one, disarm the wake-up path in
            // return_trivial_lease_grant() again.
            self.trivial_leases_granted.fetch_add(
                Self::TRIVIAL_LEASES_GRANTED_NO_EXCLUSIVE_ALL_WAITERS_OFFSET,
                atomic::Ordering::Relaxed,
            );
        }
    }

    /// Return a previously issued
    /// [`TrivialLease`](AsyncSemaphoreLeaseGrantCount::TrivialLease) grant
    /// back locklessly.
    ///
    /// It is explicitly permitted to invoke this **without** holding the
    /// [`queue`](Self::queue) lock.
    ///
    /// In case the grant return potentially enables some queued
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll)
    /// waiter to complete, `true` will get returned. In this case, the caller
    /// **must** wake those via
    /// [`wake_completed_waiters()`](Self::wake_completed_waiters).
    fn return_trivial_lease_grant(&self) -> bool {
        // In the common case of no ExclusiveAll waiter enqueued, the condition
        // right below always evaluates to false, because trivial_leases_granted is
        // offset by TRIVIAL_LEASES_GRANTED_NO_EXCLUSIVE_ALL_WAITERS_OFFSET.
        if self
            .trivial_leases_granted
            .fetch_sub(1, atomic::Ordering::Relaxed)
            == 1
        {
            // Optimistic load w/o a fence.
            if self.leases_granted.load(atomic::Ordering::Relaxed) == 0 {
                true
            } else {
                // Issue a SeqCst fence pairing with the one from the ExclusiveAll path in
                // try_grant_one() and redo the test.  The argument for correctness proceeds as
                // follows: If leases_granted != 0 below, then the load is
                // coherence-ordered before the decrement to zero in
                // return_grant(), which happens-before the fence in the
                // ExlusiveAll path in try_grant_one(). It follows that
                // the fence below is SC-ordered before that latter fence. An analoguous
                // argument can be made in the other direction for the case that
                // the ExclusiveAll path in try_grant_one() observes a trivial_leases_granted !=
                // 0, leading to a contradiction.
                atomic::fence(atomic::Ordering::SeqCst);
                self.leases_granted.load(atomic::Ordering::Relaxed) == 0
            }
        } else {
            false
        }
    }

    /// Return a previously issued grant back.
    ///
    /// Return granted leases back to the pool, making them available to
    /// other waiters again. If there are some other such waiters queued,
    /// they will be [woken](Self::wake_completed_waiters) for completion as
    /// appropriate.
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    /// * `leases` - The grant to return.
    fn return_grant(
        &self,
        locked_queue: &mut <ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<
            AsyncSemaphoreQueue,
        >>::Guard<'_>,
        leases: AsyncSemaphoreLeaseGrantCount,
    ) {
        let leases_granted = self.leases_granted.load(atomic::Ordering::Relaxed);
        let mut wake = true;
        match leases {
            AsyncSemaphoreLeaseGrantCount::TrivialLease => {
                wake = self.return_trivial_lease_grant();
            }
            AsyncSemaphoreLeaseGrantCount::Leases { count } => {
                debug_assert!(count.get() <= leases_granted);
                let leases_granted = leases_granted - count.get();
                // Release pairs with Acquire in the ExclusiveAll path from try_grant_one(),
                // c.f. the comment there.
                self.leases_granted
                    .store(leases_granted, atomic::Ordering::Release);
                // Iff leases_granted dropped to zero *and* the next waiter is
                // an ExclusiveAll one, then a SeqCst fence
                // pairing with the one in return_trivial_lease_grant() will
                // be issued before the test of trivial_leases_granted in
                // wake_completed_waiters() -> try_grant_one().
            }
            AsyncSemaphoreLeaseGrantCount::ExclusiveAll => {
                debug_assert!(self.is_exclusive_all_granted(locked_queue));
                self.leases_granted.store(0, atomic::Ordering::Relaxed);
            }
        }
        if wake {
            self.wake_completed_waiters(locked_queue);
        }
    }

    /// Complete and wake the maximum possible amount of waiters queued for
    /// semaphore grants.
    ///
    /// Walk the [`queue`](Self::queue) and complete waiters as possible.
    /// Completed waiters will be woken by means of their associated
    /// [`wakers`](AsyncSemaphoreQueueEntry::waker), if any, and removed from
    /// the queue.
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    fn wake_completed_waiters(
        &self,
        locked_queue: &mut <ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<
            AsyncSemaphoreQueue,
        >>::Guard<'_>,
    ) {
        let mut i = 0;
        while i < locked_queue.queue.len() {
            let entry = &locked_queue.queue[i];
            if let AsyncSemaphoreLeaseGrantCount::Leases { count } = &entry.leases_requested {
                if count.get() > locked_queue.max_leases {
                    // The semaphore has been shrunken, skip over this
                    // failed, already woken request.
                    i += 1;
                    continue;
                }
            }
            if self.try_grant_one(locked_queue, &entry.leases_requested) {
                let entry = &mut locked_queue.queue[i];
                if let Some(waker) = entry.waker.take() {
                    waker.wake();
                }
                let was_exclusive_all_waiter = matches!(
                    &entry.leases_requested,
                    AsyncSemaphoreLeaseGrantCount::ExclusiveAll
                );
                locked_queue.remove_entry(i);
                if was_exclusive_all_waiter {
                    self.acquire_exclusive_all_end(locked_queue);
                }
            } else if !self.is_exclusive_all_granted(locked_queue)
                && locked_queue.has_trivial_lease_waiters()
            {
                // TrivialLease waiters shall be blocked by ExclusiveAll grants ahead in line
                // only.
                i += 1;
            } else {
                break;
            }
        }
    }

    /// Wake all queued waiters bound for failure.
    ///
    /// Shrinking the [`AsyncSemaphore`] capacity might render some pending
    /// requests unsatisfiable. Walk the [`queue`](Self::queue) and wake
    /// waiters bound for failure y means of their associated
    /// [`wakers`](AsyncSemaphoreQueueEntry::waker), if any. The waiters will be
    /// left on the queue and subsequently removed from the associated
    /// [`AsyncSemaphoreLeasesFuture`]'s `poll()  once the latter has taken
    /// notice of the failure.
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    fn wake_failed_waiters(
        &self,
        locked_queue: &mut <ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<
            AsyncSemaphoreQueue,
        >>::Guard<'_>,
    ) {
        let mut failed_some = false;
        let max_leases = locked_queue.max_leases;
        for entry in locked_queue.queue.iter_mut() {
            match entry.leases_requested {
                AsyncSemaphoreLeaseGrantCount::Leases { count } if max_leases < count.get() => {
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
            self.wake_completed_waiters(locked_queue);
        }
    }

    /// Cancel an enqueued waiter.
    ///
    /// Cancelling an enqueued waiter might potentially unblock subsequent
    /// waiters in the queue, so they would get
    /// [woken](Self::wake_completed_waiters) in the course of cancelling if so.
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    /// * `waiter_id` - The waiter id, as previously returned by
    ///   [`enqueue_waiter()`](AsyncSemaphoreQueue::enqueue_waiter) of the
    ///   enqueued waiter instance to cancel.
    /// * `leases_requested` - The grant request associated with the waiter to
    ///   cancel.
    fn cancel_waiter(
        &self,
        locked_queue: &mut <ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<
            AsyncSemaphoreQueue,
        >>::Guard<'_>,
        waiter_id: num::NonZeroU64,
        leases_requested: AsyncSemaphoreLeaseGrantCount,
    ) {
        match locked_queue.waiter_position(waiter_id) {
            Some(index) => {
                locked_queue.remove_entry(index);
                match leases_requested {
                    AsyncSemaphoreLeaseGrantCount::TrivialLease => {
                        // A TrivialLease waiter can only be on the queue
                        // if some ExclusiveAll waiter is ahead of it. In either
                        // case, cancelling
                        // it won't unblock anything.
                        debug_assert!(
                            self.is_exclusive_all_granted(locked_queue)
                                || locked_queue.has_exclusive_all_waiters()
                        );
                    }
                    AsyncSemaphoreLeaseGrantCount::Leases { count } => {
                        // This waiter might have blocked subsequent entries waiting
                        // for a smaller number of leases, which might already be
                        // available. Kick those waiters.
                        if count.get() > 1 {
                            self.wake_completed_waiters(locked_queue);
                        }
                    }
                    AsyncSemaphoreLeaseGrantCount::ExclusiveAll => {
                        self.acquire_exclusive_all_end(locked_queue);
                        // This exclusive waiter might have blocked subsequent entries, kick them.
                        self.wake_completed_waiters(locked_queue);
                    }
                }
            }
            None => {
                // The waiter has previously been removed, which means that it got the requested
                // number of semaphore leases granted. The fact that the waiter is attempting to
                // cancel itself means that it hasn't noticed yet. Return the grants to the
                // pool.
                self.return_grant(locked_queue, leases_requested);
            }
        }
    }

    /// Check whether some issued
    /// [`ExclusiveAll`](AsyncSemaphoreLeaseGrantCount::ExclusiveAll) grant is
    /// active.
    ///
    /// # Arguments:
    ///
    /// * `locked_queue` - Guard for the locked [`queue`](Self::queue).
    fn is_exclusive_all_granted(
        &self,
        locked_queue: &<ST::Lock<AsyncSemaphoreQueue> as sync_types::Lock<AsyncSemaphoreQueue>>::Guard<'_>,
    ) -> bool {
        self.leases_granted.load(atomic::Ordering::Relaxed) == locked_queue.max_leases + 1
    }
}

/// A semaphore which can be waited asynchronously for.
///
/// There are two types of grants which can be issued:
/// * regular "leases" grants - these can be issued within the bounds of the
///   [`AsyncSemaphore`]'s capacity at a time and enable immutable access to the
///   wrapped data item. Obtained either asynchrononously via
///   [`acquire_leases()`](Self::acquire_leases), or synchronously via
///   [`try_acquire_leases()`](Self::try_acquire_leases).
/// * "exclusive-all" grants - this type of grant is mutually exclusive with any
///   other grant of any kind, that is, it is blocked by and blocks itself any
///   other regular "leases" grant or "exclusive-all" grant. "Exclusive-all"
///   grants provide mutable access to the wrapped data item. Obtained either
///   asynchrononously via
///   [`acquire_exclusive_all()`](Self::acquire_exclusive_all), or synchronously
///   via [`try_acquire_exclusive_all()`](Self::try_acquire_exclusive_all).
///
/// It is worth noting that, perhaps rather uncommon among semaphore
/// implementations, the regular "leases" grants can be zero-sized or "trivial".
/// For these "trivial lease" grants, the [`AsyncSemaphore`]'s capacity imposes
/// no effective bound whatsoever, their only significance is that they are
/// mutually exclusive with the "exclusive-all" grants. This feature can be used
/// to implement e.g. an asynchronous Read-Write-Lock on the grounds of
/// [`AsyncSemaphore`] right away. Furthermore, as the regular "leases" grants
/// can be [split](AsyncSemaphoreLeasesGuard::split_leases) at little cost, it
/// enables the instantiation of an indefinite amount of "trivial lease" grant
/// instances out of other lease grants, trivial or not, also providing
/// immutable access to the wrapped data item without consuming any additional
/// semaphore capacity. Observe how this resembles plain immutable Rust
/// references to some extent, but without those lifetime or borrow constraints
/// respectively which are often a hindrance in asynchronous settings.
pub struct AsyncSemaphore<ST: sync_types::SyncTypes, T> {
    state: AsyncSemaphoreState<ST>,
    data: cell::UnsafeCell<T>,
}

impl<ST: sync_types::SyncTypes, T> AsyncSemaphore<ST, T> {
    /// Instantiate a new [`AsyncSemaphore`].
    ///
    /// # Arguments:
    ///
    /// * `max_leases` - The semaphore capacity, i.e. the maximum on the total
    ///   number of regular "leases" grants which can be active at a time. Must
    ///   be **strictly** less than [`usize::MAX`].
    /// * `data` - The data item to wrap and synchronize accesses to.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn new(max_leases: usize, data: T) -> Result<sync::Arc<Self>, interface::TpmErr> {
        debug_assert!(max_leases < usize::MAX);
        utils::arc_try_new(Self {
            state: AsyncSemaphoreState::new(max_leases),
            data: cell::UnsafeCell::new(data),
        })
    }

    /// The semaphore capacity, i.e. the maximum on the total number of regular
    /// "leases" grants which can be active at a time.
    ///
    /// Note that a semaphore's capacity can be adjusted after instantiation,
    /// either through "leases" grant
    /// [leaking](AsyncSemaphoreLeasesGuard::leak), or
    /// [directly](AsyncSemaphoreExclusiveAllGuard::resize_future) through an
    /// "exclusive-all" grant, so be careful to stabilize the value as
    /// needed.
    pub fn max_leases(&self) -> usize {
        self.state.max_leases()
    }

    /// Asynchronously acquire a regular semaphore "leases" grant.
    ///
    /// Instantiate an [`AsyncSemaphoreLeasesFuture`] for asynchronous
    /// acquisition of the specified number of leases, `leases_requested`.
    ///
    /// The returned future will only become ready once all previously submitted
    /// requests have been completed and the semaphore has the requested
    /// number of leases available.
    ///
    /// In order to avoid deadlocks, care must be taken to not build up a task's
    /// granted leases incrementally: if some task already owns some leases,
    /// including trivial ones, by the time it invokes another
    /// [`acquire_leases()`](Self::acquire_leases) operation, it can block some
    /// other requests scheduled ahead to make progress, thereby effectively
    /// blocking itself from making any progress. If needed, a task can
    /// allocate all needed leases at once and then
    /// [split](AsyncSemaphoreLeasesGuard::split_leases) the grant into
    /// parts as needed.
    ///
    /// # Arguments:
    ///
    /// * `leases_requested` - The number of leases to obtain. May be set to
    ///   zero for requesting a "trivial lease" grant.
    ///
    /// # Errors:
    ///
    /// * [`AsyncSemaphoreError::RequestExceedsSemaphoreCapacity`] - The number
    ///   of leases requested exceeds the [`AsyncSemaphore`]'s total capacity.
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn acquire_leases(
        self: &sync::Arc<Self>,
        leases_requested: usize,
    ) -> Result<AsyncSemaphoreLeasesFuture<ST, T>, AsyncSemaphoreError> {
        match self.state.prepare_acquire_leases(leases_requested)? {
            Some(waiter_id) => Ok(AsyncSemaphoreLeasesFuture {
                private: AsyncSemaphoreLeasesFuturePriv::Enqueued {
                    sem: sync::Arc::downgrade(self),
                    waiter_id,
                    leases_requested,
                },
            }),
            None => Ok(AsyncSemaphoreLeasesFuture {
                private: AsyncSemaphoreLeasesFuturePriv::LeasesGranted {
                    sem: sync::Arc::downgrade(self),
                    leases_granted: leases_requested,
                },
            }),
        }
    }

    /// Asynchronously acquire an exclusive-all grant on all of a semaphore's
    /// capacity.
    ///
    /// Instantiate an [`AsyncSemaphoreExclusiveAllFuture`] for asynchronous
    /// acquisition of an exclusive-all grant on all of the [`AsyncSemaphore`]'s
    /// capacity.
    ///
    /// The returned future will only become ready once all previously submitted
    /// requests have been completed and the resulting guards dropped again.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn acquire_exclusive_all(
        self: &sync::Arc<Self>,
    ) -> Result<AsyncSemaphoreExclusiveAllFuture<ST, T>, interface::TpmErr> {
        match self.state.prepare_acquire_exclusive_all()? {
            Some(waiter_id) => Ok(AsyncSemaphoreExclusiveAllFuture {
                private: AsyncSemaphoreExclusiveAllFuturePriv::Enqueued {
                    sem: sync::Arc::downgrade(self),
                    waiter_id,
                },
            }),
            None => Ok(AsyncSemaphoreExclusiveAllFuture {
                private: AsyncSemaphoreExclusiveAllFuturePriv::Granted {
                    sem: sync::Arc::downgrade(self),
                },
            }),
        }
    }

    /// Try to synchronously acquire a regular semaphore "leases" grant.
    ///
    /// The operation will only succeed and return a
    /// [`AsyncSemaphoreLeasesGuard`] if the requested number of leases is
    /// available and there is no other, conflicting waiter ahead in line.
    /// Otherwise [`None`] will get returned.
    ///
    /// # Arguments:
    ///
    /// * `leases_requested` - The number of leases to obtain. May be set to
    ///   zero for requesting a "trivial lease" grant.
    ///
    /// # Errors:
    ///
    /// * [`AsyncSemaphoreError::RequestExceedsSemaphoreCapacity`] - The number
    ///   of leases requested exceeds the [`AsyncSemaphore`]'s total capacity.
    pub fn try_acquire_leases(
        self: &sync::Arc<Self>,
        leases_requested: usize,
    ) -> Result<Option<AsyncSemaphoreLeasesGuard<ST, T>>, AsyncSemaphoreError> {
        if self.state.try_acquire_leases(leases_requested)? {
            Ok(Some(AsyncSemaphoreLeasesGuard::new(
                self.clone(),
                leases_requested,
            )))
        } else {
            Ok(None)
        }
    }

    /// Try to synchronously acquire an exclusive-all grant on all of a
    /// semaphore's capacity.
    ///
    /// The operation will only succeed and return a
    /// [`AsyncSemaphoreExclusiveAllGuard`] if no other grants of any kind are
    /// active. Otherwise [`None`] will get returned.
    pub fn try_acquire_exclusive_all(
        self: &sync::Arc<Self>,
    ) -> Option<AsyncSemaphoreExclusiveAllGuard<ST, T>> {
        if self.state.try_acquire_exclusive_all() {
            Some(AsyncSemaphoreExclusiveAllGuard::new(self.clone()))
        } else {
            None
        }
    }
}

// A non-Sync semaphore would be quite pointless.
unsafe impl<ST: sync_types::SyncTypes, T> Sync for AsyncSemaphore<ST, T> {}

/// Internal [`AsyncSemaphoreLeasesFuture`] state.
enum AsyncSemaphoreLeasesFuturePriv<ST: sync_types::SyncTypes, T> {
    /// The requested number of semaphore leases had been unavailable at
    /// enqueueing time and the waiter got indeed enqueued.
    Enqueued {
        sem: sync::Weak<AsyncSemaphore<ST, T>>,
        waiter_id: num::NonZeroU64,
        leases_requested: usize,
    },
    /// The requested number of semaphore leases had been available at
    /// enqueueing time and they got granted right away.
    LeasesGranted {
        sem: sync::Weak<AsyncSemaphore<ST, T>>,
        leases_granted: usize,
    },
    /// The future is done: the semaphore leases had been acquired at some time
    /// and polled out to the user.
    Done,
}

/// Asynchronous wait for [`AsyncSemaphore`] leases.
///
/// To be obtained through [`AsyncSemaphore::acquire_leases()`].
///
/// # Note on lifetime management
///
/// An [`AsyncSemaphoreLeasesFuture`] instance will only maintain a weak
/// reference (i.e. a [`Weak`](sync::Weak)) to the associated [`AsyncSemaphore`]
/// instance and thus, would not hinder its deallocation. In case the semaphore
/// gets dropped before the future had a chance to acquire leases from it, its
/// `poll()` would return [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct AsyncSemaphoreLeasesFuture<ST: sync_types::SyncTypes, T> {
    private: AsyncSemaphoreLeasesFuturePriv<ST, T>,
}

impl<ST: sync_types::SyncTypes, T> marker::Unpin for AsyncSemaphoreLeasesFuture<ST, T> {}

impl<ST: sync_types::SyncTypes, T> future::Future for AsyncSemaphoreLeasesFuture<ST, T> {
    type Output = Result<AsyncSemaphoreLeasesGuard<ST, T>, AsyncSemaphoreError>;

    /// Poll for a regular "leases" grant from the associated
    /// [`AsyncSemaphore`].
    ///
    /// Upon successful future completion, an [`AsyncSemaphoreLeasesGuard`] is
    /// returned, otherwise some error information indicating the cause of the
    /// failure.
    ///
    /// The future must not get polled any further once completed.
    ///
    /// # Errors:
    ///
    /// * [`AsyncSemaphoreError::RequestExceedsSemaphoreCapacity`] - The
    ///   associated [`AsyncSemaphore`]'s capacity has been shrunken below the
    ///   requested number of leases after the request was made.
    /// * [`TpmRc::RETRY`](interface::TpmRc::RETRY) - The associated
    ///   [`AsyncSemaphore`] has been dropped after the request was made.
    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.get_mut();
        match &this.private {
            AsyncSemaphoreLeasesFuturePriv::Enqueued {
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
                let mut locked_queue = sem.state.queue.lock();
                if locked_queue.poll_waiter(*waiter_id, cx.waker().clone()) {
                    drop(locked_queue);
                    let leases_granted = *leases_requested;
                    this.private = AsyncSemaphoreLeasesFuturePriv::Done;
                    task::Poll::Ready(Ok(AsyncSemaphoreLeasesGuard::new(sem, leases_granted)))
                } else if locked_queue.max_leases < *leases_requested {
                    // The semaphore's capacity has been shrunken below the number of requested
                    // leases in the meanwhile, fail the request.
                    locked_queue.remove_waiter(*waiter_id);
                    this.private = AsyncSemaphoreLeasesFuturePriv::Done;
                    task::Poll::Ready(Err(AsyncSemaphoreError::RequestExceedsSemaphoreCapacity))
                } else {
                    task::Poll::Pending
                }
            }
            AsyncSemaphoreLeasesFuturePriv::LeasesGranted {
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
                this.private = AsyncSemaphoreLeasesFuturePriv::Done;
                task::Poll::Ready(Ok(AsyncSemaphoreLeasesGuard::new(sem, leases_granted)))
            }
            AsyncSemaphoreLeasesFuturePriv::Done => {
                // The semaphore leases had been acquired and handed out already.
                task::Poll::Ready(Err(AsyncSemaphoreError::TpmErr(tpm_err_internal!())))
            }
        }
    }
}

impl<ST: sync_types::SyncTypes, T> Drop for AsyncSemaphoreLeasesFuture<ST, T> {
    fn drop(&mut self) {
        match &self.private {
            AsyncSemaphoreLeasesFuturePriv::Enqueued {
                sem,
                waiter_id,
                leases_requested,
            } => {
                if let Some(sem) = sem.upgrade() {
                    sem.state.cancel_waiter(
                        &mut sem.state.queue.lock(),
                        *waiter_id,
                        AsyncSemaphoreLeaseGrantCount::from(*leases_requested),
                    );
                }
            }
            AsyncSemaphoreLeasesFuturePriv::LeasesGranted {
                sem,
                leases_granted,
            } => {
                // The semaphore leases had been granted right from the beginning, but the
                // future never got polled for them. Return the grants.
                if let Some(sem) = sem.upgrade() {
                    sem.state.return_grant(
                        &mut sem.state.queue.lock(),
                        AsyncSemaphoreLeaseGrantCount::from(*leases_granted),
                    );
                }
            }
            AsyncSemaphoreLeasesFuturePriv::Done => (),
        }
    }
}

/// RAII guard for a regular "leases" grant acquired from an [`AsyncSemaphore`].
///
/// To be obtained either synchronously through
/// [`AsyncSemaphore::try_acquire_leases()`] or asynchronously via
/// [AsyncSemaphore::acquire_leases()].
///
/// Provides immutable access to the associated [`AsyncSemaphore`]'s wrapped
/// data item.
///
/// Until an [`AsyncSemaphoreLeasesGuard`] gets dropped again, it will block
/// other conflicting requests to the associated [`AsyncSemaphore`] from making
/// progress:
/// - other, subsequent requests for regular "leases" grants if the total number
///   of active leases would exceed the semaphore's capacity any
/// - any requests for `exclusive-all` grants.
/// It should be worth noting again, that [`AsyncSemaphoreLeasesGuard`] for
/// "trivial lease" grants, i.e. grants for a zero number of semaphore leases,
/// do establish mutual exclusion with "exclusive-all" grants.
///
/// An [`AsyncSemaphoreLeasesGuard`] can be [split](Self::split_leases) into
/// two, distributing the currently owned leases among the new instances as
/// specified. This is needed for obtaining more than one semaphore lease in a
/// deadlock-free manner, c.f. the discussion at
/// [`AsyncSemaphore::acquire_leases()`].
pub struct AsyncSemaphoreLeasesGuard<ST: sync_types::SyncTypes, T> {
    sem: Option<sync::Arc<AsyncSemaphore<ST, T>>>,
    leases_granted: usize,
}

impl<ST: sync_types::SyncTypes, T> AsyncSemaphoreLeasesGuard<ST, T> {
    fn new(sem: sync::Arc<AsyncSemaphore<ST, T>>, leases_granted: usize) -> Self {
        Self {
            sem: Some(sem),
            leases_granted,
        }
    }

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
    /// subsequently get managed independently, c.f. the discussion at
    /// [`AsyncSemaphore::acquire_leases()`].
    ///
    /// # Arguments:
    ///
    /// * `leases` - The number of leases to split off from `self`. May be set
    ///   to zero for requesting a "trivial lease" grant.
    ///
    /// # Errors:
    /// * [`TpmErr::InternalErr`](interface::TpmErr::InternalErr) - The number
    ///   of `leases` to split off exceeds the number of leases owned by `self`.
    pub fn split_leases(&mut self, leases: usize) -> Result<Self, interface::TpmErr> {
        if leases > self.leases_granted {
            Err(tpm_err_internal!())
        } else {
            if leases == 0 || leases == self.leases_granted {
                // Either the new or the old grant will become a trivial one, account for it
                // at the semaphore.
                //
                // At least one of leases_granted or trivial_leases_granted is non-zero at this
                // point. If only the former, the Release decrement in
                // return_grant() will ensure that the ExclusiveAll
                // path in try_grant_one() will see the increment here.
                self.sem
                    .as_ref()
                    .unwrap()
                    .state
                    .trivial_leases_granted
                    .fetch_add(1, atomic::Ordering::Relaxed);
            }

            self.leases_granted -= leases;
            Ok(Self {
                sem: self.sem.clone(),
                leases_granted: leases,
            })
        }
    }

    /// Split off a zero-sized, "trivial lease" grant.
    ///
    /// Effectively a special-cased, never failing variant of
    /// [`split_leases()`](Self::split_leases) for the case that the latter's
    /// `leases` argument is known to be zero, i.e. for splitting off a "trivial
    /// lease" grant.
    ///
    /// Returns a [`AsyncSemaphoreLeasesGuard`] wrapping a zero-sized, i.e.
    /// "trivial lease" grant.
    pub fn spawn_trivial_lease(&self) -> Self {
        self.sem
            .as_ref()
            .unwrap()
            .state
            .trivial_leases_granted
            .fetch_add(1, atomic::Ordering::Relaxed);
        Self {
            sem: self.sem.clone(),
            leases_granted: 0,
        }
    }

    /// Permanently remove the the owned leases from the associated
    /// [`AsyncSemaphore`]'s capacity.
    ///
    /// Note that this might potentially make some other, still enqueued waiters
    /// to
    /// fail with
    /// [`RequestExceedsSemaphoreCapacity`](AsyncSemaphoreError::RequestExceedsSemaphoreCapacity)
    /// in case their number of leases requested would now exceed the remaining
    /// capacity.
    pub fn leak(mut self) {
        if self.leases_granted == 0 {
            // A trivial lease, just return it.
            drop(self);
            return;
        }
        let sem = self.sem.take().unwrap();
        let mut locked_queue = sem.state.queue.lock();
        debug_assert!(locked_queue.max_leases >= self.leases_granted);
        locked_queue.max_leases -= self.leases_granted;
        debug_assert!(
            sem.state.leases_granted.load(atomic::Ordering::Relaxed) >= self.leases_granted
        );
        sem.state.leases_granted.store(
            sem.state.leases_granted.load(atomic::Ordering::Relaxed) - self.leases_granted,
            atomic::Ordering::Relaxed,
        );

        // Shrinking the semaphore capcacity might have rendered some pending
        // unsatisfiable. Wake them.
        sem.state.wake_failed_waiters(&mut locked_queue);
        // This lease grant could have blocked subsequent ExclusiveAll waiters.
        // Wake those as well.
        if locked_queue.has_exclusive_all_waiters() {
            sem.state.wake_completed_waiters(&mut locked_queue);
        }
    }
}

impl<ST: sync_types::SyncTypes, T> Drop for AsyncSemaphoreLeasesGuard<ST, T> {
    fn drop(&mut self) {
        if let Some(sem) = self.sem.as_ref() {
            if self.leases_granted == 0 {
                // Fast path for TrivialLease guards.
                let wake = sem.state.return_trivial_lease_grant();
                if wake {
                    let mut locked_queue = sem.state.queue.lock();
                    sem.state.wake_completed_waiters(&mut locked_queue);
                }
            } else {
                sem.state.return_grant(
                    &mut sem.state.queue.lock(),
                    AsyncSemaphoreLeaseGrantCount::from(self.leases_granted),
                );
            }
        }
    }
}

impl<ST: sync_types::SyncTypes, T> ops::Deref for AsyncSemaphoreLeasesGuard<ST, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.sem.as_ref().unwrap().data.get() as *const T;
        unsafe { &*p }
    }
}

/// Internal [`AsyncSemaphoreExclusiveAllFuture`] state.
enum AsyncSemaphoreExclusiveAllFuturePriv<ST: sync_types::SyncTypes, T> {
    /// The exclusive grant on all of the semaphore's capcaity had been
    /// unavailable at enqueueing time and the waiter got indeed enqueued.
    Enqueued {
        sem: sync::Weak<AsyncSemaphore<ST, T>>,
        waiter_id: num::NonZeroU64,
    },
    /// All of the semaphore's capacity had been free at enqueueing time and the
    /// exclusive grant got issued right away.
    Granted {
        sem: sync::Weak<AsyncSemaphore<ST, T>>,
    },
    /// The future is done: the exclusive grant had been acquired at some time
    /// and polled out to the user.
    Done,
}

/// Asynchronous wait for an exclusive-all grant on all of an
/// [`AsyncSemaphore`]'s capacity.
///
/// To be obtained through [`AsyncSemaphore::acquire_exclusive_all()`].
///
/// # Note on lifetime management
///
/// An [`AsyncSemaphoreExclusiveAllFuture`] instance will only maintain a
/// weak reference (i.e. a [`Weak`](sync::Weak)) to the associated
/// [`AsyncSemaphore`] instance and thus, would not hinder its deallocation. In
/// case the semaphore gets dropped before the future had a chance to acquire
/// the exclusive grant on it, its `poll()` would return
/// [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct AsyncSemaphoreExclusiveAllFuture<ST: sync_types::SyncTypes, T> {
    private: AsyncSemaphoreExclusiveAllFuturePriv<ST, T>,
}

impl<ST: sync_types::SyncTypes, T> marker::Unpin for AsyncSemaphoreExclusiveAllFuture<ST, T> {}

impl<ST: sync_types::SyncTypes, T> future::Future for AsyncSemaphoreExclusiveAllFuture<ST, T> {
    type Output = Result<AsyncSemaphoreExclusiveAllGuard<ST, T>, interface::TpmErr>;

    /// Poll for an "exclusive-all" grant on all of the associated
    /// [`AsyncSemaphore`]'s capacity.
    ///
    /// Upon successful future completion, an
    /// [`AsyncSemaphoreExclusiveAllGuard`] is returned, otherwise some
    /// error information indicating the cause of the failure.
    ///
    /// The future must not get polled any further once completed.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::RETRY`](interface::TpmRc::RETRY) - The associated
    ///   [`AsyncSemaphore`] has been dropped after the request was made.
    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.get_mut();
        match &this.private {
            AsyncSemaphoreExclusiveAllFuturePriv::Enqueued { sem, waiter_id } => {
                let sem = match sem.upgrade() {
                    Some(sem) => sem,
                    None => {
                        // The semaphore is gone, indicating some teardown going on. Let the user
                        // retry to get a more definitive answer.
                        return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                    }
                };
                let mut locked_queue = sem.state.queue.lock();
                if locked_queue.poll_waiter(*waiter_id, cx.waker().clone()) {
                    drop(locked_queue);
                    this.private = AsyncSemaphoreExclusiveAllFuturePriv::Done;
                    task::Poll::Ready(Ok(AsyncSemaphoreExclusiveAllGuard::new(sem)))
                } else {
                    task::Poll::Pending
                }
            }
            AsyncSemaphoreExclusiveAllFuturePriv::Granted { sem } => {
                let sem = match sem.upgrade() {
                    Some(sem) => sem,
                    None => {
                        // The semaphore is gone, indicating some teardown going on. Let the user
                        // retry to get a more definitive answer.
                        return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                    }
                };
                this.private = AsyncSemaphoreExclusiveAllFuturePriv::Done;
                task::Poll::Ready(Ok(AsyncSemaphoreExclusiveAllGuard::new(sem)))
            }
            AsyncSemaphoreExclusiveAllFuturePriv::Done => {
                // The semaphore leases had been acquired and handed out already.
                task::Poll::Ready(Err(tpm_err_internal!()))
            }
        }
    }
}

impl<ST: sync_types::SyncTypes, T> Drop for AsyncSemaphoreExclusiveAllFuture<ST, T> {
    fn drop(&mut self) {
        match &self.private {
            AsyncSemaphoreExclusiveAllFuturePriv::Enqueued { sem, waiter_id } => {
                if let Some(sem) = sem.upgrade() {
                    sem.state.cancel_waiter(
                        &mut sem.state.queue.lock(),
                        *waiter_id,
                        AsyncSemaphoreLeaseGrantCount::ExclusiveAll,
                    );
                }
            }
            AsyncSemaphoreExclusiveAllFuturePriv::Granted { sem } => {
                // The exclusive grant had been issued right from the beginning, but the
                // future never got polled for it. Return the grants.
                if let Some(sem) = sem.upgrade() {
                    sem.state.return_grant(
                        &mut sem.state.queue.lock(),
                        AsyncSemaphoreLeaseGrantCount::ExclusiveAll,
                    );
                }
            }
            AsyncSemaphoreExclusiveAllFuturePriv::Done => (),
        }
    }
}

/// RAII guard for an "exclusive-all" grant acquired from an [`AsyncSemaphore`].
///
/// To be obtained either synchronously through
/// [`AsyncSemaphore::try_acquire_exclusive_all()`] or asynchronously via
/// [AsyncSemaphore::acquire_exclusive_all()].
///
/// Provides mutable access to the associated [`AsyncSemaphore`]'s wrapped
/// data item.
///
/// Until an [`AsyncSemaphoreExclusiveAllGuard`] gets dropped again, it will
/// block any other request, including ones for a zero-sized "trivial lease",
/// from making progress.
pub struct AsyncSemaphoreExclusiveAllGuard<ST: sync_types::SyncTypes, T> {
    sem: Option<sync::Arc<AsyncSemaphore<ST, T>>>,
}

impl<ST: sync_types::SyncTypes, T> AsyncSemaphoreExclusiveAllGuard<ST, T> {
    fn new(sem: sync::Arc<AsyncSemaphore<ST, T>>) -> Self {
        Self { sem: Some(sem) }
    }

    /// Return the associated [`AsyncSemaphore`] the "exclusive-all" grant had
    /// been issued for.
    pub fn semaphore(&self) -> &AsyncSemaphore<ST, T> {
        self.sem.as_ref().unwrap()
    }

    /// Grow or shrink the associated [`AsyncSemaphore`]'s capacity.
    ///
    /// Independent of whether the capacity is being in- or decreased,
    /// all of it will still be exclusively owned by `self`.
    ///
    /// Note that shrinking the capacity might potentially make some other,
    /// still enqueued waiters to fail with
    /// [`RequestExceedsSemaphoreCapacity`](AsyncSemaphoreError::RequestExceedsSemaphoreCapacity)
    /// in case their number of leases requested would now exceed the
    /// remaining capacity.
    ///
    /// # Arguments:
    ///
    /// * `max_leases` - The new [`AsyncSemaphore`] capacity. Must be
    ///   **strictly** less than [`usize::MAX`].
    pub fn resize_future(&mut self, max_leases: usize) {
        debug_assert!(max_leases < usize::MAX);
        let sem = self.sem.as_ref().unwrap();
        let mut locked_queue = sem.state.queue.lock();
        let capacity_shrunken = max_leases < locked_queue.max_leases;
        locked_queue.max_leases = max_leases;
        sem.state
            .leases_granted
            .store(max_leases + 1, atomic::Ordering::Relaxed);
        // Shrinking the capacity might render some pending requests unsatisfiable.
        if capacity_shrunken {
            sem.state.wake_failed_waiters(&mut locked_queue);
        }
    }

    /// Downgrade the "exclusive-all" grant on all of a semaphore's capacity to
    /// a regular "leases" grant.
    ///
    /// The "exclusive-all" grant will be downgraded to a regular grant on all
    /// of the associated [`AsyncSemaphore`]'s capacity. This may e.g. be used
    /// in case the full grant needs to be
    /// [split](AsyncSemaphoreLeasesGuard::split_leases) into smaller ones.
    pub fn downgrade(mut self) -> AsyncSemaphoreLeasesGuard<ST, T> {
        let sem = self.sem.take().unwrap();
        let mut locked_queue = sem.state.queue.lock();
        let leases_granted = locked_queue.max_leases;
        sem.state
            .leases_granted
            .store(leases_granted, atomic::Ordering::Relaxed);
        if locked_queue.max_leases == 0 {
            sem.state
                .trivial_leases_granted
                .fetch_add(1, atomic::Ordering::Release);
        }
        // Turning the ExclusiveAll grant into a regular one might
        // unblock TrivialLease waiters.
        if locked_queue.has_trivial_lease_waiters() {
            sem.state.wake_completed_waiters(&mut locked_queue);
        }
        drop(locked_queue);
        AsyncSemaphoreLeasesGuard::new(sem, leases_granted)
    }
}

impl<ST: sync_types::SyncTypes, T> Drop for AsyncSemaphoreExclusiveAllGuard<ST, T> {
    fn drop(&mut self) {
        if let Some(sem) = self.sem.as_ref() {
            sem.state.return_grant(
                &mut sem.state.queue.lock(),
                AsyncSemaphoreLeaseGrantCount::ExclusiveAll,
            );
        }
    }
}

impl<ST: sync_types::SyncTypes, T> ops::Deref for AsyncSemaphoreExclusiveAllGuard<ST, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.sem.as_ref().unwrap().data.get() as *const T;
        unsafe { &*p }
    }
}

impl<ST: sync_types::SyncTypes, T> ops::DerefMut for AsyncSemaphoreExclusiveAllGuard<ST, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let p = self.sem.as_ref().unwrap().data.get();
        unsafe { &mut *p }
    }
}

#[test]
fn test_async_semaphore_lease_vs_lease() {
    use super::test::executor;
    use core::mem;
    use ops::DerefMut as _;

    enum TestFuture {
        ExpectLease0Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            lease_fut0: AsyncSemaphoreLeasesFuture<executor::TestNopSyncTypes, ()>,
        },
        ExpectLease1Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            lease_fut1: AsyncSemaphoreLeasesFuture<executor::TestNopSyncTypes, ()>,
        },
        ExpectLeases23Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            lease_fut2: AsyncSemaphoreLeasesFuture<executor::TestNopSyncTypes, ()>,
            lease_fut3: AsyncSemaphoreLeasesFuture<executor::TestNopSyncTypes, ()>,
        },
        Done,
    }

    impl future::Future for TestFuture {
        type Output = ();

        fn poll(
            mut self: pin::Pin<&mut Self>,
            cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            let this = mem::replace(self.deref_mut(), Self::Done);
            match this {
                Self::ExpectLease0Ready {
                    sem,
                    mut lease_fut0,
                } => {
                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));

                    let mut lease_fut1 = sem.acquire_leases(2).unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut1).poll(cx),
                        task::Poll::Pending
                    ));

                    let _lease0 = match pin::Pin::new(&mut lease_fut0).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut1).poll(cx),
                        task::Poll::Pending
                    ));

                    // Dropping the lease0 guard is supposed to wake lease_fut1.
                    *self.deref_mut() = Self::ExpectLease1Ready { sem, lease_fut1 };
                    task::Poll::Pending
                }
                Self::ExpectLease1Ready {
                    sem,
                    mut lease_fut1,
                } => {
                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));

                    let _lease1 = match pin::Pin::new(&mut lease_fut1).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));
                    let mut lease_fut2 = sem.acquire_leases(1).unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut2).poll(cx),
                        task::Poll::Pending
                    ));
                    let mut lease_fut3 = sem.acquire_leases(1).unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut3).poll(cx),
                        task::Poll::Pending
                    ));

                    // Dropping the lease1 guard is supposed to wake lease_fut2 and lease_fut3.
                    *self.deref_mut() = Self::ExpectLeases23Ready {
                        sem,
                        lease_fut2,
                        lease_fut3,
                    };
                    task::Poll::Pending
                }
                Self::ExpectLeases23Ready {
                    sem,
                    mut lease_fut2,
                    mut lease_fut3,
                } => {
                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));

                    let lease2 = match pin::Pin::new(&mut lease_fut2).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };
                    let lease3 = match pin::Pin::new(&mut lease_fut3).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));
                    drop(lease2);
                    let lease4 = sem.try_acquire_leases(1).unwrap().unwrap();

                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));
                    drop(lease3);
                    let lease5 = sem.try_acquire_leases(1).unwrap().unwrap();

                    assert!(matches!(sem.try_acquire_leases(2), Ok(None)));
                    drop(lease4);
                    assert!(matches!(sem.try_acquire_leases(2), Ok(None)));
                    drop(lease5);
                    assert!(matches!(sem.try_acquire_leases(2), Ok(Some(..))));

                    let _lease6 = sem.try_acquire_leases(1).unwrap().unwrap();
                    let mut lease_fut7 = sem.acquire_leases(2).unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut7).poll(cx),
                        task::Poll::Pending
                    ));
                    let mut lease_fut8 = sem.acquire_leases(1).unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut8).poll(cx),
                        task::Poll::Pending
                    ));
                    drop(lease_fut7);
                    let _lease8 = match pin::Pin::new(&mut lease_fut8).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    task::Poll::Ready(())
                }
                Self::Done => unreachable!(),
            }
        }
    }

    impl Unpin for TestFuture {}

    let e = executor::TestAsyncExecutor::new();
    let sem = AsyncSemaphore::<executor::TestNopSyncTypes, _>::new(2, ()).unwrap();
    let lease_fut0 = sem.acquire_leases(2).unwrap();
    let w = e.spawn(TestFuture::ExpectLease0Ready { sem, lease_fut0 });
    e.run_to_completion();
    w.take().unwrap();
}

#[test]
fn test_async_semaphore_lease_vs_trivial() {
    use super::test::executor;
    use core::mem;
    use ops::DerefMut as _;

    enum TestFuture {
        ExpectLease0Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            lease_fut0: AsyncSemaphoreLeasesFuture<executor::TestNopSyncTypes, ()>,
        },
        ExpectLease1Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            trivial_lease: AsyncSemaphoreLeasesGuard<executor::TestNopSyncTypes, ()>,
            lease_fut1: AsyncSemaphoreLeasesFuture<executor::TestNopSyncTypes, ()>,
        },
        Done,
    }

    impl future::Future for TestFuture {
        type Output = ();

        fn poll(
            mut self: pin::Pin<&mut Self>,
            cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            let this = mem::replace(self.deref_mut(), Self::Done);
            match this {
                Self::ExpectLease0Ready {
                    sem,
                    mut lease_fut0,
                } => {
                    assert!(matches!(sem.try_acquire_leases(0), Ok(..)));
                    let mut trivial_fut = sem.acquire_leases(0).unwrap();
                    match pin::Pin::new(&mut trivial_fut).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    let _lease0 = match pin::Pin::new(&mut lease_fut0).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(sem.try_acquire_leases(0), Ok(..)));
                    let mut trivial_fut = sem.acquire_leases(0).unwrap();
                    let trivial_lease = match pin::Pin::new(&mut trivial_fut).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(sem.try_acquire_leases(0), Ok(..)));
                    let mut trivial_fut = sem.acquire_leases(0).unwrap();
                    match pin::Pin::new(&mut trivial_fut).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    let mut lease_fut1 = sem.acquire_leases(1).unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut1).poll(cx),
                        task::Poll::Pending
                    ));

                    // Dropping the lease0 guard is supposed to wake lease_fut1.
                    *self.deref_mut() = Self::ExpectLease1Ready {
                        sem,
                        trivial_lease,
                        lease_fut1,
                    };
                    task::Poll::Pending
                }
                Self::ExpectLease1Ready {
                    sem,
                    trivial_lease: _trivial_lease,
                    mut lease_fut1,
                } => {
                    let lease1 = match pin::Pin::new(&mut lease_fut1).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };
                    drop(lease1);
                    assert!(matches!(sem.try_acquire_leases(1), Ok(Some(..))));
                    task::Poll::Ready(())
                }
                Self::Done => unreachable!(),
            }
        }
    }

    impl Unpin for TestFuture {}

    let e = executor::TestAsyncExecutor::new();
    let sem = AsyncSemaphore::<executor::TestNopSyncTypes, _>::new(1, ()).unwrap();
    let lease_fut0 = sem.acquire_leases(1).unwrap();
    let w = e.spawn(TestFuture::ExpectLease0Ready { sem, lease_fut0 });
    e.run_to_completion();
    w.take().unwrap();
}

#[test]
fn test_async_semaphore_exclusive_vs_exclusive() {
    use super::test::executor;
    use core::mem;
    use ops::DerefMut as _;

    enum TestFuture {
        ExpectExclusiveAll0Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            excl_fut0: AsyncSemaphoreExclusiveAllFuture<executor::TestNopSyncTypes, ()>,
        },
        ExpectExclusiveAll1Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            excl_fut1: AsyncSemaphoreExclusiveAllFuture<executor::TestNopSyncTypes, ()>,
        },
        Done,
    }

    impl future::Future for TestFuture {
        type Output = ();

        fn poll(
            mut self: pin::Pin<&mut Self>,
            cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            let this = mem::replace(self.deref_mut(), Self::Done);
            match this {
                Self::ExpectExclusiveAll0Ready { sem, mut excl_fut0 } => {
                    assert!(sem.try_acquire_exclusive_all().is_none());

                    let mut excl_fut1 = sem.acquire_exclusive_all().unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut excl_fut1).poll(cx),
                        task::Poll::Pending
                    ));

                    let _excl0 = match pin::Pin::new(&mut excl_fut0).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(
                        pin::Pin::new(&mut excl_fut1).poll(cx),
                        task::Poll::Pending
                    ));

                    *self.deref_mut() = Self::ExpectExclusiveAll1Ready { sem, excl_fut1 };
                    task::Poll::Pending
                }
                Self::ExpectExclusiveAll1Ready { sem, mut excl_fut1 } => {
                    assert!(sem.try_acquire_exclusive_all().is_none());

                    let excl1 = match pin::Pin::new(&mut excl_fut1).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(sem.try_acquire_exclusive_all().is_none());
                    drop(excl1);
                    assert!(sem.try_acquire_exclusive_all().is_some());

                    task::Poll::Ready(())
                }
                Self::Done => unreachable!(),
            }
        }
    }

    impl Unpin for TestFuture {}

    let e = executor::TestAsyncExecutor::new();
    let sem = AsyncSemaphore::<executor::TestNopSyncTypes, _>::new(0, ()).unwrap();
    let excl_fut0 = sem.acquire_exclusive_all().unwrap();
    let w = e.spawn(TestFuture::ExpectExclusiveAll0Ready { sem, excl_fut0 });
    e.run_to_completion();
    w.take().unwrap();
}

#[test]
fn test_async_semaphore_exclusive_vs_lease() {
    use super::test::executor;
    use core::mem;
    use ops::DerefMut as _;

    enum TestFuture {
        ExpectExclusiveAll0Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            excl_fut0: AsyncSemaphoreExclusiveAllFuture<executor::TestNopSyncTypes, ()>,
        },
        ExpectLease1Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            lease_fut1: AsyncSemaphoreLeasesFuture<executor::TestNopSyncTypes, ()>,
        },
        ExpectExclusiveAll2Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            excl_fut2: AsyncSemaphoreExclusiveAllFuture<executor::TestNopSyncTypes, ()>,
        },
        Done,
    }

    impl future::Future for TestFuture {
        type Output = ();

        fn poll(
            mut self: pin::Pin<&mut Self>,
            cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            let this = mem::replace(self.deref_mut(), Self::Done);
            match this {
                Self::ExpectExclusiveAll0Ready { sem, mut excl_fut0 } => {
                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));

                    let mut lease_fut1 = sem.acquire_leases(1).unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut1).poll(cx),
                        task::Poll::Pending
                    ));

                    let _excl0 = match pin::Pin::new(&mut excl_fut0).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut1).poll(cx),
                        task::Poll::Pending
                    ));

                    *self.deref_mut() = Self::ExpectLease1Ready { sem, lease_fut1 };
                    task::Poll::Pending
                }
                Self::ExpectLease1Ready {
                    sem,
                    mut lease_fut1,
                } => {
                    assert!(sem.try_acquire_exclusive_all().is_none());

                    let mut excl_fut2 = sem.acquire_exclusive_all().unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut excl_fut2).poll(cx),
                        task::Poll::Pending
                    ));

                    let _lease1 = match pin::Pin::new(&mut lease_fut1).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };
                    assert!(sem.try_acquire_exclusive_all().is_none());
                    assert!(matches!(
                        pin::Pin::new(&mut excl_fut2).poll(cx),
                        task::Poll::Pending
                    ));

                    *self.deref_mut() = Self::ExpectExclusiveAll2Ready { sem, excl_fut2 };
                    task::Poll::Pending
                }
                Self::ExpectExclusiveAll2Ready { sem, mut excl_fut2 } => {
                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));

                    let excl2 = match pin::Pin::new(&mut excl_fut2).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(sem.try_acquire_leases(1), Ok(None)));
                    drop(excl2);
                    assert!(matches!(sem.try_acquire_leases(1), Ok(Some(..))));
                    task::Poll::Ready(())
                }
                Self::Done => unreachable!(),
            }
        }
    }

    impl Unpin for TestFuture {}

    let e = executor::TestAsyncExecutor::new();
    let sem = AsyncSemaphore::<executor::TestNopSyncTypes, _>::new(1, ()).unwrap();
    let excl_fut0 = sem.acquire_exclusive_all().unwrap();
    let w = e.spawn(TestFuture::ExpectExclusiveAll0Ready { sem, excl_fut0 });
    e.run_to_completion();
    w.take().unwrap();
}

#[test]
fn test_async_semaphore_exclusive_vs_trivial() {
    use super::test::executor;
    use core::mem;
    use ops::DerefMut as _;

    enum TestFuture {
        ExpectExclusiveAll0Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            excl_fut0: AsyncSemaphoreExclusiveAllFuture<executor::TestNopSyncTypes, ()>,
        },
        ExpectTrivial1Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            trivial_fut1: AsyncSemaphoreLeasesFuture<executor::TestNopSyncTypes, ()>,
        },
        ExpectExclusiveAll2Ready {
            sem: sync::Arc<AsyncSemaphore<executor::TestNopSyncTypes, ()>>,
            excl_fut2: AsyncSemaphoreExclusiveAllFuture<executor::TestNopSyncTypes, ()>,
        },
        Done,
    }

    impl future::Future for TestFuture {
        type Output = ();

        fn poll(
            mut self: pin::Pin<&mut Self>,
            cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            let this = mem::replace(self.deref_mut(), Self::Done);
            match this {
                Self::ExpectExclusiveAll0Ready { sem, mut excl_fut0 } => {
                    assert!(matches!(sem.try_acquire_leases(0), Ok(None)));

                    let mut trivial_fut1 = sem.acquire_leases(0).unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut trivial_fut1).poll(cx),
                        task::Poll::Pending
                    ));

                    let _excl0 = match pin::Pin::new(&mut excl_fut0).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(sem.try_acquire_leases(0), Ok(None)));
                    assert!(matches!(
                        pin::Pin::new(&mut trivial_fut1).poll(cx),
                        task::Poll::Pending
                    ));

                    *self.deref_mut() = Self::ExpectTrivial1Ready { sem, trivial_fut1 };
                    task::Poll::Pending
                }
                Self::ExpectTrivial1Ready {
                    sem,
                    mut trivial_fut1,
                } => {
                    assert!(sem.try_acquire_exclusive_all().is_none());

                    let mut excl_fut2 = sem.acquire_exclusive_all().unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut excl_fut2).poll(cx),
                        task::Poll::Pending
                    ));

                    let mut trivial1 = match pin::Pin::new(&mut trivial_fut1).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    let _trivial = trivial1.split_leases(0).unwrap();
                    drop(trivial1);

                    assert!(sem.try_acquire_exclusive_all().is_none());
                    assert!(matches!(
                        pin::Pin::new(&mut excl_fut2).poll(cx),
                        task::Poll::Pending
                    ));

                    *self.deref_mut() = Self::ExpectExclusiveAll2Ready { sem, excl_fut2 };
                    task::Poll::Pending
                }
                Self::ExpectExclusiveAll2Ready { sem, mut excl_fut2 } => {
                    assert!(matches!(sem.try_acquire_leases(0), Ok(None)));

                    let excl2 = match pin::Pin::new(&mut excl_fut2).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };

                    assert!(matches!(sem.try_acquire_leases(0), Ok(None)));
                    drop(excl2);
                    assert!(matches!(sem.try_acquire_leases(0), Ok(Some(..))));

                    let _trivial3 = sem.try_acquire_leases(0).unwrap().unwrap();
                    let mut excl_fut4 = sem.acquire_exclusive_all().unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut excl_fut4).poll(cx),
                        task::Poll::Pending
                    ));

                    let mut trivial_fut5 = sem.acquire_leases(0).unwrap();
                    let mut lease_fut6 = sem.acquire_leases(1).unwrap();
                    let mut lease_fut7 = sem.acquire_leases(1).unwrap();
                    let mut trivial_fut8 = sem.acquire_leases(0).unwrap();
                    assert!(matches!(
                        pin::Pin::new(&mut trivial_fut5).poll(cx),
                        task::Poll::Pending
                    ));
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut6).poll(cx),
                        task::Poll::Pending
                    ));
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut7).poll(cx),
                        task::Poll::Pending
                    ));
                    assert!(matches!(
                        pin::Pin::new(&mut trivial_fut8).poll(cx),
                        task::Poll::Pending
                    ));

                    drop(excl_fut4);

                    assert!(matches!(
                        pin::Pin::new(&mut trivial_fut5).poll(cx),
                        task::Poll::Ready(Ok(..))
                    ));
                    let lease6 = match pin::Pin::new(&mut lease_fut6).poll(cx) {
                        task::Poll::Ready(guard) => guard.unwrap(),
                        task::Poll::Pending => unreachable!(),
                    };
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut7).poll(cx),
                        task::Poll::Pending
                    ));
                    assert!(matches!(
                        pin::Pin::new(&mut trivial_fut8).poll(cx),
                        task::Poll::Ready(Ok(..))
                    ));
                    drop(lease6);
                    assert!(matches!(
                        pin::Pin::new(&mut lease_fut7).poll(cx),
                        task::Poll::Ready(Ok(..))
                    ));

                    task::Poll::Ready(())
                }
                Self::Done => unreachable!(),
            }
        }
    }

    impl Unpin for TestFuture {}

    let e = executor::TestAsyncExecutor::new();
    let sem = AsyncSemaphore::<executor::TestNopSyncTypes, _>::new(1, ()).unwrap();
    let excl_fut0 = sem.acquire_exclusive_all().unwrap();
    let w = e.spawn(TestFuture::ExpectExclusiveAll0Ready { sem, excl_fut0 });
    e.run_to_completion();
    w.take().unwrap();
}
