//! Implementation of the generic [`Cache`] manager.
extern crate alloc;
use crate::interface;
use crate::sync_types::{self, Lock as _, SyncTypes};
use crate::utils;
use crate::utils::asynchronous::{
    AsyncSemaphoreExclusiveAllFuture, AsyncSemaphoreExclusiveAllGuard,
};
use alloc::{sync, vec};
use core::ops::DerefMut;
use core::{borrow, cmp, future, marker, mem, num, ops, pin, task};
use utils::asynchronous;

/// Internal [`KeysToSlotsMap`] entry.
struct KeyToSlot<K: cmp::Ord> {
    /// The key.
    key: K,
    /// Index of the cache slot.
    slot_index: usize,
}

/// Internal map mapping keys to [`Cache`] slots.
struct KeysToSlotsMap<K: cmp::Ord + Clone> {
    /// The key to slot map, represented as a sequence of [`KeyToSlot`] ordered
    /// by [`KeyToSlot::key`].
    keys_to_slots: vec::Vec<KeyToSlot<K>>,
}

impl<K: cmp::Ord + Clone> KeysToSlotsMap<K> {
    /// Create a new, empty [`KeysToSlotsMap`] instance.
    fn new() -> Self {
        Self {
            keys_to_slots: vec::Vec::new(),
        }
    }

    /// Determine the position of a key in the sorted [`Self::keys_to_slots`]
    /// sequence. If `key` is already mapped, the position of the map entry
    /// is returned as wrapped in [`Result::Ok`]. Otherwise the value found
    /// in the retunrned [`Result::Err`] gives the position an entry for
    /// `key` is to be inserted at.
    ///
    /// # Arguments:
    ///
    /// * `key` - The key to lookup in the map.
    fn lookup_map_pos<Q: borrow::Borrow<K>>(&self, key: &Q) -> Result<usize, usize> {
        let key = <Q as borrow::Borrow<K>>::borrow(key);
        self.keys_to_slots
            .binary_search_by(|key_to_slot| key_to_slot.key.cmp(key))
    }

    /// Lookup the cache slot index associated with `key`, if any.
    ///
    /// If the key is found in the mapping, the associated cache slot index will
    /// get returned, [`None`] otherwise.
    ///
    /// # Arguments:
    ///
    /// * `key` - The key to lookup in the map.
    fn lookup_slot_index<Q: borrow::Borrow<K>>(&self, key: &Q) -> Option<usize> {
        self.lookup_map_pos(key)
            .ok()
            .map(|index| self.keys_to_slots[index].slot_index)
    }

    /// Remove the mapping for a given key.
    ///
    /// # Arguments:
    ///
    /// * `key` - The key to remove from the mapping.
    fn remove<Q: borrow::Borrow<K>>(&mut self, key: &Q) {
        match self.lookup_map_pos(key) {
            Ok(map_pos) => {
                self.keys_to_slots.remove(map_pos);
            }
            Err(_) => {
                // Huh?
                debug_assert!(false, "Attempt to remove non-existant cache key");
            }
        }
    }

    /// Establish a mapping for a given key.
    ///
    /// It must have been made sure beforehand through a call to
    /// [`try_reserve()`](Self::try_reserve) that the memory allocated for
    /// the mapping has enough capacity to accomodate for the additional entry.
    ///
    /// # Arguments:
    ///
    /// * `entry` - The key and slot index pair to establish a mapping for.
    /// * `insertion_pos_hint` - If [`Some`], the insertion position within the
    ///   ordered [`keys_to_slots`](Self::keys_to_slots) sequence as previously
    ///   returned in the [`Result::Err`] arm of
    ///   [`lookup_map_pos`](Self::lookup_map_pos).
    fn insert(&mut self, entry: KeyToSlot<K>, insertion_pos_hint: Option<usize>) {
        let insertion_pos = match insertion_pos_hint {
            Some(insertion_pos) => insertion_pos,
            None => {
                match self.lookup_map_pos(&entry.key) {
                    Ok(_) => {
                        // Should not happen, handle it conservatively.
                        debug_assert!(false, "Attempted to insert key duplicated into cache");
                        return;
                    }
                    Err(insertion_pos) => insertion_pos,
                }
            }
        };
        debug_assert!(self.keys_to_slots.capacity() > self.keys_to_slots.len());
        self.keys_to_slots.insert(insertion_pos, entry);
    }

    /// Try to reserve memory to accomodate for `additional` new mapping
    /// entries.
    ///
    /// # Arguments:
    ///
    /// * `additional` - The number of additional mapping entries to allocated
    ///   memory for.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn try_reserve(&mut self, additional: usize) -> Result<(), interface::TpmErr> {
        self.keys_to_slots
            .try_reserve(additional)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        Ok(())
    }
}

/// Internal definition for encapsulation the type of the slots
/// [`Vec`](vec::Vec) wrapped in the [`Cache::slots`]
/// [`AsyncSemaphore`](asynchronous::AsyncSemaphore).
struct SlotsVec<ST: sync_types::SyncTypes, V> {
    vec: vec::Vec<ST::Lock<Option<V>>>,
}

/// Internal tracking of active reservations of a cache slot.
enum SlotReservationCount<ST: sync_types::SyncTypes, V> {
    /// The slot entry contents are still there, but there are no active
    /// reservations for it. The slot entry is not being accounted for at
    /// the [slots allocation semaphore](Cache::slots). The entry may get
    /// evicted to make room.
    NoReservations {
        /// Snapshot of [`CacheSlotsStates::last_lru_seqno`] at the time
        /// the last reservation has been returned.
        lru_seqno: u32,
    },
    /// The slot entry is being actively used, i.e. there are reservations for
    /// it. It is accounted for at the [slots allocation
    /// semaphore](Cache::slots), by means of the owned
    /// [`slots_allocation_lease`](`Self::ActiveReservations::slots_allocation_lease`).
    ActiveReservations {
        /// The number of active [`CacheSlotReservation`] instances referencing
        /// this entry.
        refcount: num::NonZeroUsize,
        /// A lease of size one from [slots allocation semaphore](Cache::slots)
        /// for this cache slot allocation. It will get returned once
        /// the the last reservation referencing this slot is getting
        /// dropped, to reflect the fact that this slot may get
        /// repurposed for a different key.
        slots_allocation_lease: asynchronous::AsyncSemaphoreLeasesGuard<ST, SlotsVec<ST, V>>,
    },
}

impl<ST: sync_types::SyncTypes, V> SlotReservationCount<ST, V> {
    /// Make a new [`SlotReservationCount`] representing one active reservation.
    ///
    /// # Arguments:
    ///
    /// * `slots_allocation_leases` - The cache [slots allocation
    ///   semaphore](Cache::slots) leases to split off one lease from for the
    ///   newly allocated slot. It must have at least one lease left.
    fn new_reserved(
        slots_allocation_leases: &mut asynchronous::AsyncSemaphoreLeasesGuard<ST, SlotsVec<ST, V>>,
    ) -> Self {
        debug_assert!(slots_allocation_leases.leases() >= 1);
        let slot_allocation_lease = slots_allocation_leases.split_leases(1).unwrap();
        Self::ActiveReservations {
            refcount: num::NonZeroUsize::new(1).unwrap(),
            slots_allocation_lease: slot_allocation_lease,
        }
    }

    /// Increment a [`SlotReservationCount`] in order to account for a newly
    /// issued reservation for the associated cache slot.
    ///
    /// If `self` is currently in the [`NoReservations`](Self::NoReservations)
    /// state, the cache slot is getting revived for the previously
    /// associated key and a new cache [slots allocation
    /// semaphore](Cache::slots) lease must be assigned to account for this
    /// slot being considered allocated again. Thus, whenever there's a
    /// chance `self` might be in the
    /// [`NoReservations`](Self::NoReservations), the `slots_allocation_leases`
    /// argument must have at least one spare lease to draw from it.
    ///
    /// Returns a trivial, zero-sized [slots allocation semaphore](Cache::slots)
    /// lease to be used for the about to be instantiated
    /// [CacheSlotReservation::slots_trivial_lease] for enabling subsequent
    /// accesses to the slot.
    ///
    /// # Arguments:
    ///
    /// * `slots_allocation_leases` - The cache [slots allocation
    ///   semaphore](Cache::slots) leases to split off one lease from in case
    ///   `self` is currently in the [`NoReservations`](Self::NoReservations)
    ///   state.
    fn increment(
        &mut self,
        slots_allocation_leases: &mut asynchronous::AsyncSemaphoreLeasesGuard<ST, SlotsVec<ST, V>>,
    ) -> asynchronous::AsyncSemaphoreLeasesGuard<ST, SlotsVec<ST, V>> {
        match self {
            Self::NoReservations { lru_seqno: _ } => {
                let slots_trivial_lease = slots_allocation_leases.spawn_trivial_lease();
                *self = Self::new_reserved(slots_allocation_leases);
                slots_trivial_lease
            }
            Self::ActiveReservations {
                refcount,
                slots_allocation_lease,
            } => {
                *refcount = num::NonZeroUsize::new(refcount.get() + 1).unwrap();
                slots_allocation_lease.spawn_trivial_lease()
            }
        }
    }

    /// Increment a [`SlotReservationCount`] known to have active reservations.
    ///
    /// `self` must not be in the [`NoReservations`](Self::NoReservations)
    /// state, i.e. some other reservation for the cache slot must exist
    /// already.
    ///
    /// Returns a trivial, zero-sized [slots allocation semaphore](Cache::slots)
    /// lease to be used for the about to be instantiated
    /// [CacheSlotReservation::slots_trivial_lease] for enabling subsequent
    /// accesses to the slot.
    fn increment_from_reservation(
        &mut self,
    ) -> asynchronous::AsyncSemaphoreLeasesGuard<ST, SlotsVec<ST, V>> {
        match self {
            Self::NoReservations { lru_seqno: _ } => {
                unreachable!();
            }
            Self::ActiveReservations {
                refcount,
                slots_allocation_lease,
            } => {
                *refcount = num::NonZeroUsize::new(refcount.get() + 1).unwrap();
                slots_allocation_lease.spawn_trivial_lease()
            }
        }
    }

    /// Decrement a [`SlotReservationCount`] in order to account for the
    /// destruction of some previously issued reservation for the associated
    /// cache slot. If this is the last reference, the cache slot may get
    /// evicted and repurposed for a different key, in particular the [slots
    /// allocation semaphore](Cache::slots) lease will get returned in this
    /// case.
    ///
    /// * `last_lru_seqno` - Reference to the containing [`CacheSlotsStates`]'
    ///   [`last_lru_seqno`](CacheSlotsStates::last_lru_seqno) member.
    fn decrement(&mut self, last_lru_seqno: &mut u32) {
        match self {
            Self::NoReservations { lru_seqno: _ } => {
                unreachable!();
            }
            Self::ActiveReservations {
                refcount,
                slots_allocation_lease: _,
            } => {
                if refcount.get() == 1 {
                    // Last reservation has gone, the slot can be evicted now if needed. Release the
                    // slot allocation lease so that new ones can be acquired.
                    *last_lru_seqno = last_lru_seqno.wrapping_add(1);
                    *self = Self::NoReservations {
                        lru_seqno: *last_lru_seqno,
                    };
                } else {
                    *refcount = num::NonZeroUsize::new(refcount.get() - 1).unwrap();
                }
            }
        }
    }
}

/// Internal tracking data for cache slot usage state.
enum SlotState<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> {
    /// The cache slot is associated with a key. Depending on
    /// whether or not there are active reservations around,
    /// i.e. on the state of [`reservations`](Self::Used::reservations),
    /// the slot might get evicted to make room for new allocations.
    Used {
        /// The key asssociated wit the cache slot.
        key: K,
        /// Tracking of active reservations for this cache slot.
        reservations: SlotReservationCount<ST, V>,
    },
    /// The cache slot is unused.
    Empty,
}

/// Internal wrapper for collective [`Cache`] state tracking metadata.
struct CacheSlotsStates<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> {
    /// The maps from keys to their associated slots.
    keys_to_slots: KeysToSlotsMap<K>,
    /// Cache slot state tracking data.
    slots_states: vec::Vec<SlotState<ST, K, V>>,
    /// The last LRU sequence number assigned to any of slots with no active
    /// reservations.
    last_lru_seqno: u32,
}

impl<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> CacheSlotsStates<ST, K, V> {
    /// Create a new [`CacheSlotsStates`] instance for the specified number
    /// of cache slots.
    ///
    /// # Arguments:
    /// * `nslots` - Number of slots the owning [`Cache`] will provide. Must be
    ///   greater than zero and **strictly** less than [`usize::MAX`].
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn new(nslots: usize) -> Result<Self, interface::TpmErr> {
        let mut slots_states = vec::Vec::new();
        slots_states
            .try_reserve_exact(nslots)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        slots_states.resize_with(nslots, || SlotState::Empty);
        Ok(Self {
            keys_to_slots: KeysToSlotsMap::new(),
            slots_states,
            last_lru_seqno: 0,
        })
    }

    /// Try to find a cache slot with no reservations and evict it.
    ///
    /// If an eviction victim has been found, its metadata will get updated to
    /// reflect the eviction and the corresponding cache slot index will get
    /// returned. The caller must then proceed and clear the slot's actual
    /// contents.
    ///
    /// **Attention**: this will only modify the cache slot state tracking
    /// metadata, **not** the slot contents! The latter must get pruned
    /// separately by the caller.
    fn try_evict_slot(&mut self) -> Option<usize> {
        let mut found_victim_slot: Option<(usize, u32)> = None;
        for (slot_index, slot_state) in self.slots_states.iter().enumerate() {
            match slot_state {
                SlotState::Used {
                    key: _,
                    reservations,
                } => match reservations {
                    SlotReservationCount::NoReservations { lru_seqno } => {
                        let age = self.last_lru_seqno.wrapping_sub(*lru_seqno);
                        match found_victim_slot {
                            Some((_, cur_victim_slot_age)) => {
                                if age > cur_victim_slot_age {
                                    found_victim_slot = Some((slot_index, age));
                                }
                            }
                            None => {
                                found_victim_slot = Some((slot_index, age));
                            }
                        }
                    }
                    SlotReservationCount::ActiveReservations {
                        refcount: _,
                        slots_allocation_lease: _,
                    } => (),
                },
                SlotState::Empty => (),
            }
        }

        match found_victim_slot {
            Some((slot_index, _)) => {
                match &self.slots_states[slot_index] {
                    SlotState::Used {
                        key,
                        reservations: _,
                    } => {
                        self.keys_to_slots.remove(key);
                    }
                    SlotState::Empty => unreachable!(),
                };
                self.slots_states[slot_index] = SlotState::Empty;
                Some(slot_index)
            }
            None => None,
        }
    }

    /// Count the number of keys with no existing cache slot reservations in a
    /// given set of keys.
    ///
    /// Count the number of elements among `keys` which have either not been
    /// associated with any cache slot at all or which are, but for which
    /// there is no active reservation. This is significant in sofar as in
    /// either case a lease must be allocated from the
    /// [slots allocation semaphore](Cache::slots) in order to evenutally
    /// establish a reservation for such keys each.
    ///
    /// # Arguments:
    ///
    /// * `keys` - Iterator over the set of keys to examine for matching active
    ///   reservations.
    fn count_unallocated_keys<Q: borrow::Borrow<K>, KI: Iterator<Item = Q>>(
        &mut self,
        keys: KI,
    ) -> usize {
        let mut unallocated: usize = 0;
        for key in keys {
            match self.keys_to_slots.lookup_slot_index(&key) {
                Some(slot_index) => {
                    match &self.slots_states[slot_index] {
                        SlotState::Empty => {
                            // Huh?
                            debug_assert!(false, "Unexpected empty cache slot state");
                            // Even though it should be unreachable, be conservative and
                            // fix it up.
                            self.keys_to_slots.remove(&key);
                            unallocated += 1;
                        }
                        SlotState::Used {
                            key: _,
                            reservations,
                        } => {
                            match reservations {
                                SlotReservationCount::ActiveReservations {
                                    refcount: _,
                                    slots_allocation_lease: _,
                                } => {
                                    // The key maps to a slot and there is an
                                    // active reservation for
                                    // it. If the containing Cache::slots_state
                                    // won't get unlocked,
                                    // the user will be able to piggy-back on
                                    // this reservation by
                                    // incrementing its reference count. If the
                                    // state lock does get
                                    // dropped inbetween, it might still be
                                    // possible, but must get
                                    // rechecked under the lock again.
                                }
                                SlotReservationCount::NoReservations { lru_seqno: _ } => {
                                    // The key maps to a slot, but there is no active allocation for
                                    // it.
                                    unallocated += 1;
                                }
                            }
                        }
                    }
                }
                None => {
                    unallocated += 1;
                }
            }
        }
        unallocated
    }

    /// Establish cache slot reservations for a given set of keys.
    ///
    /// Once a sufficient (see
    /// [`count_unallocated_keys()`](Self::count_unallocated_keys)) number of
    /// leases has been obtained from the [slots allocation
    /// semaphore](Cache::slots), slot reservations can be established.
    ///
    /// If a given key from the set of `keys` has previously been associated
    /// with a cache slot already, the association remains intact. In case
    /// there are no existing active reservations for such a cache slot around,
    /// a new one might need to get established, requiring one [slots allocation
    /// semaphore](Cache::slots) lease to be drawn from
    /// `slots_allocation_leases`. In either case, the cache slot's contents
    /// will remain unmodified.
    ///
    /// If a given key is not yet allocated with some cache slot, a new one will
    /// get allocated, with the slot contents initialized to `None`. Note
    /// that this slot allocation might involve the eviction of some other
    /// key not in the `keys` set and for which there are no active
    /// reservations around. In either case, a slot allocation semaphore lease
    /// will be drawn from `slots_allocation_leases` in order to instantiate
    /// a new reservation for the key.
    ///
    /// # Arguments:
    ///
    /// * `keys` - The set of keys to establish reservations for. If successful,
    ///   the reservations will be returned as a [`Vec`](vec::Vec) of
    ///   [`CacheSlotReservation`] instances of matching order.
    /// * `slots_allocation_leases` - Leases from the [slots allocation
    ///   semaphore](Cache::slots) to split off leases from for newly
    ///   instantiated slot reservations.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    /// * [`TpmErr::InternalErr`](interface::TpmErr::InternalErr) - The internal
    ///   [`Cache`] state has been found inconsistent due to some bug.
    fn establish_keys_reservations<Q: borrow::Borrow<K>, KI: Iterator<Item = Q> + Clone>(
        &mut self,
        cache: &sync::Arc<Cache<ST, K, V>>,
        keys: KI,
        mut slots_allocation_leases: asynchronous::AsyncSemaphoreLeasesGuard<ST, SlotsVec<ST, V>>,
    ) -> Result<vec::Vec<CacheSlotReservation<ST, K, V>>, interface::TpmErr> {
        debug_assert!(self.count_unallocated_keys(keys.clone()) < slots_allocation_leases.leases());

        // First ensure that the keys_to_slots map has enough room, count the number of
        // keys to be newly added to the cache and reserve memory for the map
        // afterwards. While sweeping through the keys anwyay, forward the LRU
        // sequence number of those keys which are present but don't have an
        // active reservation so that they won't get evicted further below.
        let mut new_keys = 0;
        self.last_lru_seqno = self.last_lru_seqno.wrapping_add(1);
        for key in keys.clone() {
            match self.keys_to_slots.lookup_slot_index(&key) {
                None => {
                    new_keys += 1;
                }
                Some(slot_index) => {
                    match &mut self.slots_states[slot_index] {
                        SlotState::Empty => {
                            // Huh?
                            debug_assert!(false, "Unexpected empty cache slot state");
                        }
                        SlotState::Used {
                            key: _,
                            reservations,
                        } => match reservations {
                            SlotReservationCount::NoReservations { lru_seqno } => {
                                *lru_seqno = self.last_lru_seqno;
                            }
                            SlotReservationCount::ActiveReservations {
                                refcount: _,
                                slots_allocation_lease: _,
                            } => (),
                        },
                    }
                }
            }
        }
        self.keys_to_slots.try_reserve(new_keys)?;

        // Allocate memory for the result now so that we cannot fail after the
        // state has been modified.
        let mut slots_reservations = vec::Vec::<CacheSlotReservation<ST, K, V>>::new();
        slots_reservations
            .try_reserve_exact(keys.clone().count())
            .map_err(|_| tpm_err_rc!(MEMORY))?;

        // Find and assign empty slots for the new keys.
        let mut empty_slot_search_begin = 0;
        for key in keys.clone() {
            let keys_to_slots_map_insertion_pos = match self.keys_to_slots.lookup_map_pos(&key) {
                Ok(_) => continue,
                Err(pos) => pos,
            };

            let slot_index = match self.slots_states[empty_slot_search_begin..]
                .iter()
                .position(|state| matches!(state, SlotState::Empty))
            {
                Some(slot_index) => {
                    // Start the next search one past the found empty slot.
                    empty_slot_search_begin = slot_index + 1;
                    slot_index
                }
                None => {
                    // No more free slots, stop searching, start evicting.
                    empty_slot_search_begin = self.slots_states.len();
                    match self.try_evict_slot() {
                        Some(slot_index) => {
                            // slots_allocation_leases provides access to the slots
                            // wrapped in the Cache::slots semaphore.
                            *slots_allocation_leases.vec[slot_index].lock() = None;
                            slot_index
                        }
                        None => {
                            // That should be impossible, because we have a
                            // slot allocation semaphore lease.
                            debug_assert!(
                                false,
                                "Unexpectedly failed to find cache slot eviction victim"
                            );
                            // Be conservative and roll back, i.e. remove all keys from the map
                            // which point to slots marked empty.
                            for key in keys {
                                if let Some(slot_index) = self.keys_to_slots.lookup_slot_index(&key)
                                {
                                    if matches!(self.slots_states[slot_index], SlotState::Empty) {
                                        self.keys_to_slots.remove(&key);
                                    }
                                }
                            }
                            return Err(tpm_err_internal!());
                        }
                    }
                }
            };
            self.keys_to_slots.insert(
                KeyToSlot {
                    key: key.borrow().clone(),
                    slot_index,
                },
                Some(keys_to_slots_map_insertion_pos),
            )
        }

        // And finally obtain reservations for the slots to stabilize them.
        for key in keys {
            let slot_index = self.keys_to_slots.lookup_slot_index(&key).unwrap();
            let slot = &mut self.slots_states[slot_index];
            let slots_trivial_lease = match slot {
                SlotState::Empty => {
                    let slots_trivial_lease = slots_allocation_leases.spawn_trivial_lease();
                    *slot = SlotState::Used {
                        key: key.borrow().clone(),
                        reservations: SlotReservationCount::new_reserved(
                            &mut slots_allocation_leases,
                        ),
                    };
                    slots_trivial_lease
                }
                SlotState::Used {
                    key: _,
                    reservations,
                } => reservations.increment(&mut slots_allocation_leases),
            };
            slots_reservations.push(CacheSlotReservation {
                cache: cache.clone(),
                slots_trivial_lease,
                slot_index,
            });
        }

        Ok(slots_reservations)
    }
}

/// A generic keyed element cache.
///
/// The cache's capacity is organized in units of slots. Slots are allocated to
/// keys by making [`CacheSlotReservation`]s, either asynchrononously through
/// [`reserve_slots()`](Self::reserve_slots) or synchronously through
/// [`try_reserve_slots()`](Self::try_reserve_slots):
/// - the former's returned [`Future`](future::Future) will only complete once
///   the requested number of slots become available within the [`Cache`]'s
///   capacity whereas
/// - the latter will just fail if the requested number of slots is not
///   immediately available (or the [`Cache`] has been locked for exclusive
///   access, c.f. below).
///
/// As long as there is at least one [`CacheSlotReservation`] for a given key
/// alive, subsequent requests for the same key will yield additional
/// reservations for the same associated slot. That is, all reservations for the
/// same key are guaranteed to map to a single unique cache slot.
///
/// Once all [`CacheSlotReservation`] instances for a given key have been
/// dropped, the associated slot might or might not get evicted in order to make
/// room on behalf of subsequent reservation requests. If not, subsequent
/// reservations for the original key will get associated with its previously
/// allocated cache slot again, in particular the former value would still be
/// found there. If the previously associated cache slot had gotten repurposed
/// in the meanwhile, a new slot with its cached value reset ([`None`]) will get
/// allocated instead.
///
/// Certain operations which would otherwise conflict with concurrent cache slot
/// usages, like flushing or global capacity adjustments, can still be carried
/// out once exclusive access has been established via either
/// [`lock_exclusive()`](Self::lock_exclusive) or its synchronous
/// [`try_lock_exclusive()`](Self::try_lock_exclusive) counterpart.
pub struct Cache<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> {
    /// The cache slots wrapped in a
    /// [`AsyncSemaphore`](asynchronous::AsyncSemaphore) for managing slot
    /// allocation grants through semaphore leases.
    slots: sync::Arc<asynchronous::AsyncSemaphore<ST, SlotsVec<ST, V>>>,
    /// Cache slot tracking information: mapping of keys to slots as well as the
    /// individual slot reservation states.
    slots_states: ST::Lock<CacheSlotsStates<ST, K, V>>,
}

impl<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> Cache<ST, K, V> {
    /// Instantiate a [`Cache`] with a specified number of available slots.
    ///
    /// # Arguments:
    ///
    /// * `nslots` - Number of cache slots.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn new(nslots: usize) -> Result<sync::Arc<Self>, interface::TpmErr> {
        let mut slots = vec::Vec::new();
        slots
            .try_reserve_exact(nslots)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        let slots = SlotsVec { vec: slots };
        let slots = asynchronous::AsyncSemaphore::new(nslots, slots)?;
        let slots_states = ST::Lock::from(CacheSlotsStates::new(nslots)?);
        utils::arc_try_new(Self {
            slots,
            slots_states,
        })
    }

    /// Asynchronously obtain cache slot reservations for `keys`.
    ///
    /// Instantiate a future for asynchronous waiting on the required cache slot
    /// allocations to become available. See the [`Cache`] documentation for
    /// additional details on the guarantees given for the assocations
    /// between `keys` and cache slots.
    ///
    /// **Attention:** [`reserve_slots()`](Self::reserve_slots) must **not** be
    /// used for building up reservations "incrementally", i.e. it must not
    /// get invoked when the task is already holding
    /// any [`CacheSlotReservation`] for the `self` [`Cache`] instance: as the
    /// total number of allocatable slots is fixed, two such tasks could
    /// block each other from making progress, effectively resulting in a
    /// deadlock.
    ///
    /// # Arguments:
    ///
    /// * `keys` - The keys to make cache slot reservations for. The respective
    ///   associated [`CacheSlotReservation`] instances will get returned
    ///   (subsequently by the [`Future`](future::Future)) in the same order.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    /// * [`TpmErr::InternalErr`](interface::TpmErr::InternalErr) - Either the
    ///   request can never be satisfied, because the number of `keys` specified
    ///   exceeds the maximum available cache slots or the internal [`Cache`]
    ///   state has been found inconsistent due to some bug.
    pub fn reserve_slots<Q: borrow::Borrow<K>>(
        self: &sync::Arc<Self>,
        keys: vec::Vec<Q>,
    ) -> Result<CacheReserveSlotsFuture<ST, K, V, Q>, interface::TpmErr> {
        // First try to get along with as few slot allocation semaphore leases
        // as possible by piggy-backing onto active allocations, if any.
        // However, do not grab reservations on the already allocated
        // slots before attempting to wait for leases from the semaphore as this
        // could result in a deadlock.
        let mut locked_slots_states = self.slots_states.lock();
        let slot_leases_needed = locked_slots_states
            .count_unallocated_keys(keys.iter().map(<Q as borrow::Borrow<K>>::borrow));
        // No cutting in line.
        let slot_leases_needed = slot_leases_needed.max(1);

        // Fast path: try to acquire all needed slot allocation leases without waiting
        // and with slots_states locked. If successful the future can get
        // completed immediately.
        if let Some(slots_allocation_leases) = self
            .slots
            .clone()
            .try_acquire_leases(slot_leases_needed)
            .map_err(|e| match e {
                asynchronous::AsyncSemaphoreError::RequestExceedsSemaphoreCapacity => {
                    tpm_err_internal!()
                }
                asynchronous::AsyncSemaphoreError::TpmErr(e) => e,
            })?
        {
            return Ok(CacheReserveSlotsFuture {
                progress: CacheReserveSlotsFutureProgress::Ready(
                    locked_slots_states.establish_keys_reservations(
                        self,
                        keys.iter().map(<Q as borrow::Borrow<K>>::borrow),
                        slots_allocation_leases,
                    )?,
                ),
            });
        }

        // Construct a future for waiting for the slot allocation leases.
        drop(locked_slots_states);
        let keys_len = keys.len();
        let acquire_leases_common = CacheReserveSlotsFutureAcquireLeasesCommon {
            cache: sync::Arc::downgrade(self),
            acquire_slot_leases_fut: self.slots.acquire_leases(slot_leases_needed).map_err(
                |e| match e {
                    asynchronous::AsyncSemaphoreError::RequestExceedsSemaphoreCapacity => {
                        tpm_err_internal!()
                    }
                    asynchronous::AsyncSemaphoreError::TpmErr(e) => e,
                },
            )?,
            keys,
        };
        Ok(CacheReserveSlotsFuture {
            progress: if slot_leases_needed < keys_len {
                // Some of the keys had allocated slots already, at least when the slots_states
                // had still been locked above. Try to piggy-back on the
                // allocations first.
                CacheReserveSlotsFutureProgress::AcquireSlotLeasesMinimal(acquire_leases_common)
            } else {
                CacheReserveSlotsFutureProgress::AcquireSlotLeasesFull(acquire_leases_common)
            },
        })
    }

    /// Attempt to make cache slot reservations synchronously.
    ///
    /// Try to obtain the required cache slot allocations immediately if
    /// available. The request will fail with `Ok(None)` if the slots are
    /// not immediately available or there are some other waiters ahead in
    /// line. On success, a [`Vec`](vec::Vec) of [`CacheSlotReservation`]
    /// instances associated with the specified `keys` each will get
    /// returned.
    ///
    /// See the [`Cache`] documentation for additional details on the guarantees
    /// given for the assocations between `keys` and cache slots.
    ///
    /// # Arguments:
    ///
    /// * `keys` - The keys to make cache slot reservations for. The respective
    ///   associated [`CacheSlotReservation`] instances will get returned in the
    ///   same order.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    /// * [`TpmErr::InternalErr`](interface::TpmErr::InternalErr) - Either the
    ///   request can never be satisfied, because the number of `keys` specified
    ///   exceeds the maximum available cache slots or the internal [`Cache`]
    ///   state has been found inconsistent due to some bug.
    #[allow(clippy::type_complexity)]
    pub fn try_reserve_slots<Q: borrow::Borrow<K>, KI: Iterator<Item = Q> + Clone>(
        self: &sync::Arc<Self>,
        keys: KI,
    ) -> Result<Option<vec::Vec<CacheSlotReservation<ST, K, V>>>, interface::TpmErr> {
        let mut locked_slots_states = self.slots_states.lock();
        let slot_leases_needed = locked_slots_states.count_unallocated_keys(keys.clone());
        // No cutting in line.
        let slot_leases_needed = slot_leases_needed.max(1);

        if let Some(slots_allocation_leases) = self
            .slots
            .clone()
            .try_acquire_leases(slot_leases_needed)
            .map_err(|e| match e {
                asynchronous::AsyncSemaphoreError::RequestExceedsSemaphoreCapacity => {
                    tpm_err_internal!()
                }
                asynchronous::AsyncSemaphoreError::TpmErr(e) => e,
            })?
        {
            Ok(Some(locked_slots_states.establish_keys_reservations(
                self,
                keys,
                slots_allocation_leases,
            )?))
        } else {
            Ok(None)
        }
    }

    /// Asynchronously lock the [`Cache`] for exclusive access.
    ///
    /// Return a [`CacheExclusiveLockFuture`] for asynchronously establishing
    /// exclusive access to the [`Cache`].
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn lock_exclusive(
        self: &sync::Arc<Self>,
    ) -> Result<CacheExclusiveLockFuture<ST, K, V>, interface::TpmErr> {
        Ok(CacheExclusiveLockFuture {
            cache: sync::Arc::downgrade(self),
            slots_exlusive_all_fut: self.slots.acquire_exclusive_all()?,
        })
    }

    /// Attempt to synchronously lock the [`Cache`] for exclusive access.
    ///
    /// In case there are no active [`CacheSlotReservation`] or waiters ahead in
    /// line, exclusive excess will be granted and a
    /// [`CacheExclusiveLockGuard`] returned, otherwise `None`.
    pub fn try_lock_exclusive(self: &sync::Arc<Self>) -> Option<CacheExclusiveLockGuard<ST, K, V>> {
        self.slots
            .try_acquire_exclusive_all()
            .map(|slots_exclusive_all_guard| CacheExclusiveLockGuard {
                cache: self.clone(),
                slots_exclusive_all_guard,
            })
    }
}

/// A [`Cache`] slot reservation previously established for a given key.
///
/// A [`CacheSlotReservation`] acts as a guard for the reservation: as long as
/// it (or clones) continues to exist, the association between the key and the
/// cache slot will remain valid and it is also the only means by which the
/// cache slot contents are made accessible.
///
/// Once the last [`CacheSlotReservation`] for a given key gets destructed, the
/// associated cache slot may or may not get repurposed for a different key. If
/// not, subsequent reservations for the original key, will find the previous
/// value in the slot.
pub struct CacheSlotReservation<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> {
    /// The cache instance the reservation has been made in.
    cache: sync::Arc<Cache<ST, K, V>>,
    /// A trivial (zero-sized) lease from the allocation semaphore enabling
    /// immutable access to the [`SlotsVec`] wrapped in the semaphore and thus,
    /// to the reservation's associated slot. Logically considered to be
    /// [spawned](asynchronous::AsyncSemaphoreLeasesGuard::spawn_trivial_lease)
    /// off from allocated slot's non-trivial [allocation
    /// lease](SlotReservationCount::ActiveReservations::slots_allocation_lease).
    slots_trivial_lease: asynchronous::AsyncSemaphoreLeasesGuard<ST, SlotsVec<ST, V>>,
    /// The reservation's associated slot index within `cache`.
    slot_index: usize,
}

impl<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> CacheSlotReservation<ST, K, V> {
    /// Provide access to the reservation's associated cache slot.
    pub fn lock(&self) -> CacheSlotLockGuard<'_, ST, V> {
        CacheSlotLockGuard {
            locked_slot: self.slots_trivial_lease.vec[self.slot_index].lock(),
        }
    }
}

impl<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> Clone for CacheSlotReservation<ST, K, V> {
    fn clone(&self) -> Self {
        let mut locked_slots_states = self.cache.slots_states.lock();
        match &mut locked_slots_states.slots_states[self.slot_index] {
            SlotState::Empty => {
                unreachable!()
            }
            SlotState::Used {
                key: _,
                reservations,
            } => {
                reservations.increment_from_reservation();
            }
        };
        Self {
            cache: self.cache.clone(),
            slots_trivial_lease: self.slots_trivial_lease.spawn_trivial_lease(),
            slot_index: self.slot_index,
        }
    }
}

impl<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> Drop for CacheSlotReservation<ST, K, V> {
    fn drop(&mut self) {
        let mut locked_slots_states = self.cache.slots_states.lock();
        let CacheSlotsStates {
            keys_to_slots: _,
            slots_states,
            last_lru_seqno,
        } = locked_slots_states.deref_mut();
        match &mut slots_states[self.slot_index] {
            SlotState::Empty => {
                unreachable!()
            }
            SlotState::Used {
                key: _,
                reservations,
            } => {
                reservations.decrement(last_lru_seqno);
            }
        }
    }
}

/// Lock guard for a [`Cache`] slot.
///
/// Holders of cache slot reservations may access the slot contents by
/// locking it via [`CacheSlotReservation::lock()`] and dereferencing the
/// obtained [`CacheSlotLockGuard`].
pub struct CacheSlotLockGuard<'a, ST: sync_types::SyncTypes, V>
where
    ST::Lock<Option<V>>: 'a,
{
    /// The actual guard for the lock instance wrapping the slot contents.
    locked_slot: <ST::Lock<Option<V>> as sync_types::Lock<Option<V>>>::Guard<'a>,
}

impl<'a, ST: sync_types::SyncTypes, V> ops::Deref for CacheSlotLockGuard<'a, ST, V> {
    type Target = Option<V>;

    fn deref(&self) -> &Self::Target {
        self.locked_slot.deref()
    }
}

impl<'a, ST: sync_types::SyncTypes, V> ops::DerefMut for CacheSlotLockGuard<'a, ST, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.locked_slot.deref_mut()
    }
}

/// Asynchronously wait for cache slot allocations to become available.
///
/// To be obtained through [`Cache::reserve_slots()`].
///
/// # Note on lifetime management
///
/// A [`CacheReserveSlotsFuture`] instance will only maintain a weak reference
/// (i.e. a [`Weak`](sync::Weak)) to the associated [`Cache`] instance and thus,
/// would not hinder its deallocation. In case the cache gets dropped before the
/// future had a chance to complete, its `poll()` would return
/// [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct CacheReserveSlotsFuture<
    ST: sync_types::SyncTypes,
    K: cmp::Ord + Clone,
    V,
    Q: borrow::Borrow<K>,
> {
    /// Internal future progress tracing, opaque to extern.
    progress: CacheReserveSlotsFutureProgress<ST, K, V, Q>,
}

/// Internal [`CacheReserveSlotsFuture`] progress tracking, opaque to extern.
enum CacheReserveSlotsFutureProgress<
    ST: sync_types::SyncTypes,
    K: cmp::Ord + Clone,
    V,
    Q: borrow::Borrow<K>,
> {
    /// There had been previously existing reservations for a subset of the keys
    /// around by the time the future got instantiated. Try to piggy-back on
    /// those once the remainder of required cache slot allocations becomes
    /// available. If the piggy-backing fails, continue with
    /// [`AcquireSlotLeasesFull`](Self::AcquireSlotLeasesFull).
    AcquireSlotLeasesMinimal(CacheReserveSlotsFutureAcquireLeasesCommon<ST, K, V, Q>),
    /// Main state for waiting on cache slot allocations, one for each key
    /// specified, to become available.
    AcquireSlotLeasesFull(CacheReserveSlotsFutureAcquireLeasesCommon<ST, K, V, Q>),
    /// The future got completed right at instantiation time.
    Ready(vec::Vec<CacheSlotReservation<ST, K, V>>),
    /// The future got completed and its result has been polled out.
    Done,
}

/// Internal state common to different [`CacheReserveSlotsFutureProgress`]
/// steps.
struct CacheReserveSlotsFutureAcquireLeasesCommon<
    ST: sync_types::SyncTypes,
    K: cmp::Ord + Clone,
    V,
    Q: borrow::Borrow<K>,
> {
    /// The [`Cache`] instance to make cache slot reservations in.
    cache: sync::Weak<Cache<ST, K, V>>,
    /// Inner future for waiting on the required number of cache slot
    /// allocations to become available.
    acquire_slot_leases_fut: asynchronous::AsyncSemaphoreLeasesFuture<ST, SlotsVec<ST, V>>,
    /// The keys to allocate cache slots for.
    keys: vec::Vec<Q>,
}

impl<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V, Q: borrow::Borrow<K>> future::Future
    for CacheReserveSlotsFuture<ST, K, V, Q>
{
    type Output = Result<vec::Vec<CacheSlotReservation<ST, K, V>>, interface::TpmErr>;

    /// Poll for cache slot reservations to become available in the associated
    /// [`Cache`].
    ///
    /// Upon future completion, either a [`Vec`](vec::Vec) of
    /// [`CacheSlotReservation`] instances, corresponding to the `keys` as
    /// originally specified in the future instantiation call
    /// to [`Cache::reserve_slots()`], or an error indicator will get returned.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    /// * [`TpmRc::RETRY`](interface::TpmRc::RETRY) - The reference to the
    ///   associated [`Cache`] instance has become stale, indicating some
    ///   teardown going on.
    /// * [`TpmErr::InternalErr`](interface::TpmErr::InternalErr) - The internal
    ///   [`Cache`] state has been found inconsistent due to some bug.
    fn poll(
        self: pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = self.get_mut();
        let progress = mem::replace(&mut this.progress, CacheReserveSlotsFutureProgress::Done);
        match progress {
            CacheReserveSlotsFutureProgress::AcquireSlotLeasesMinimal(mut common) => {
                // An attempt was made to piggy-back on existing allocations. After obtaining
                // the additional required leases, it must be checked that the
                // previously found overlapping allocation are still in place.
                match future::Future::poll(pin::Pin::new(&mut common.acquire_slot_leases_fut), cx) {
                    task::Poll::Pending => {
                        this.progress =
                            CacheReserveSlotsFutureProgress::AcquireSlotLeasesMinimal(common);
                        task::Poll::Pending
                    }
                    task::Poll::Ready(Ok(slots_allocation_leases)) => {
                        let CacheReserveSlotsFutureAcquireLeasesCommon {
                            cache,
                            acquire_slot_leases_fut: _,
                            keys,
                        } = common;
                        let cache = match cache.upgrade() {
                            Some(cache) => cache,
                            None => {
                                // The cache is gone, indicating some teardown is in progress.
                                // Let the user retry to get a definitive error.
                                return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                            }
                        };

                        let mut locked_slots_states = cache.slots_states.lock();
                        let slot_leases_needed = locked_slots_states.count_unallocated_keys(
                            keys.iter().map(<Q as borrow::Borrow<K>>::borrow),
                        );
                        if slot_leases_needed > slots_allocation_leases.leases() {
                            // One or more of the previously existing slot allocations has been
                            // freed in the meanwhile and no piggy-backing is possible. Give up
                            // and go for the maximum possible slot allocation count.
                            drop(locked_slots_states);
                            drop(slots_allocation_leases);
                            let acquire_slot_leases_fut = match cache
                                .slots
                                .acquire_leases(keys.len())
                            {
                                Ok(acquire_slot_leases) => acquire_slot_leases,
                                Err(e) => {
                                    let e = match e {
                                        asynchronous::AsyncSemaphoreError::RequestExceedsSemaphoreCapacity => {
                                            tpm_err_internal!()
                                        }
                                        asynchronous::AsyncSemaphoreError::TpmErr(e) => e,
                                    };
                                    return task::Poll::Ready(Err(e));
                                }
                            };
                            this.progress = CacheReserveSlotsFutureProgress::AcquireSlotLeasesFull(
                                CacheReserveSlotsFutureAcquireLeasesCommon {
                                    cache: sync::Arc::downgrade(&cache),
                                    acquire_slot_leases_fut,
                                    keys,
                                },
                            );
                            future::Future::poll(pin::Pin::new(this), cx)
                        } else {
                            task::Poll::Ready(locked_slots_states.establish_keys_reservations(
                                &cache,
                                keys.iter().map(<Q as borrow::Borrow<K>>::borrow),
                                slots_allocation_leases,
                            ))
                        }
                    }
                    task::Poll::Ready(Err(e)) => {
                        let e = match e {
                            asynchronous::AsyncSemaphoreError::RequestExceedsSemaphoreCapacity => {
                                tpm_err_internal!()
                            }
                            asynchronous::AsyncSemaphoreError::TpmErr(e) => e,
                        };
                        task::Poll::Ready(Err(e))
                    }
                }
            }
            CacheReserveSlotsFutureProgress::AcquireSlotLeasesFull(mut common) => {
                match future::Future::poll(pin::Pin::new(&mut common.acquire_slot_leases_fut), cx) {
                    task::Poll::Pending => {
                        this.progress =
                            CacheReserveSlotsFutureProgress::AcquireSlotLeasesFull(common);
                        task::Poll::Pending
                    }
                    task::Poll::Ready(Ok(slots_allocation_leases)) => {
                        let CacheReserveSlotsFutureAcquireLeasesCommon {
                            cache,
                            acquire_slot_leases_fut: _,
                            keys,
                        } = common;
                        let cache = match cache.upgrade() {
                            Some(cache) => cache,
                            None => {
                                // The cache is gone, indicating some teardown is in progress.
                                // Let the user retry to get a definitive error.
                                return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                            }
                        };

                        let mut locked_slots_states = cache.slots_states.lock();
                        task::Poll::Ready(locked_slots_states.establish_keys_reservations(
                            &cache,
                            keys.iter().map(<Q as borrow::Borrow<K>>::borrow),
                            slots_allocation_leases,
                        ))
                    }
                    task::Poll::Ready(Err(e)) => {
                        let e = match e {
                            asynchronous::AsyncSemaphoreError::RequestExceedsSemaphoreCapacity => {
                                tpm_err_internal!()
                            }
                            asynchronous::AsyncSemaphoreError::TpmErr(e) => e,
                        };
                        task::Poll::Ready(Err(e))
                    }
                }
            }
            CacheReserveSlotsFutureProgress::Ready(slots_reservations) => {
                // The slot allocation leases had been available at future instantiation
                // time already and the future had been completed right away. Grab the result.
                task::Poll::Ready(Ok(slots_reservations))
            }
            CacheReserveSlotsFutureProgress::Done => {
                // The future had been polled to completion already.
                task::Poll::Ready(Err(tpm_err_internal!()))
            }
        }
    }
}

impl<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V, Q: borrow::Borrow<K>> marker::Unpin
    for CacheReserveSlotsFuture<ST, K, V, Q>
{
}

/// Exclusive lock on a [`Cache`].
///
/// A [`CacheExclusiveLockGuard`] is mutually exlusive with any
/// [`CacheSlotReservation`] and allows for certain [`Cache`] updates, like e.g.
/// flushes or global cache capacity resizings, which would otherwise
/// potentially conflict with concurrent cache slot usages.
pub struct CacheExclusiveLockGuard<ST: SyncTypes, K: cmp::Ord + Clone, V> {
    /// The cache instance being locked exclusively.
    cache: sync::Arc<Cache<ST, K, V>>,
    /// Exlusive-all grant on the [slots allocation semaphore](Cache::slots).
    slots_exclusive_all_guard: AsyncSemaphoreExclusiveAllGuard<ST, SlotsVec<ST, V>>,
}

impl<ST: SyncTypes, K: cmp::Ord + Clone, V> CacheExclusiveLockGuard<ST, K, V> {
    /// Flush cached entries associated with keys from a given set.
    ///
    /// Iterate through `keys` and remove the matching entries from the cache,
    /// if any.
    ///
    /// # Arguments:
    ///
    /// * `keys` - Iterator over the set of keys to examine for matching active
    ///   reservations.
    pub fn flush_keys<Q: borrow::Borrow<K>, KI: Iterator<Item = Q>>(&mut self, keys: KI) {
        let mut locked_slots_states = self.cache.slots_states.lock();
        for key in keys {
            let keys_to_slots_map_pos = match locked_slots_states.keys_to_slots.lookup_map_pos(&key)
            {
                Ok(map_pos) => map_pos,
                Err(_) => continue,
            };
            let slot_index =
                locked_slots_states.keys_to_slots.keys_to_slots[keys_to_slots_map_pos].slot_index;
            locked_slots_states
                .keys_to_slots
                .keys_to_slots
                .remove(keys_to_slots_map_pos);
            // The slots allocation semaphore is being held exlusively, there cannot be any
            // active reservations.
            debug_assert!(matches!(
                locked_slots_states.slots_states[slot_index],
                SlotState::Used {
                    key: _,
                    reservations: SlotReservationCount::NoReservations { .. }
                }
            ));
            locked_slots_states.slots_states[slot_index] = SlotState::Empty;
            self.slots_exclusive_all_guard.vec[slot_index] = ST::Lock::from(None);
        }
    }

    /// Flush cached entries based on a predicate.
    ///
    /// Evaluate all entries in the cache with `pred` and flush those for which
    /// it returns `true`.
    ///
    /// # Arguments:
    ///
    /// * `pred` - The predicate to evaluate on all cached entries' keys in turn
    ///   to decide whether to flush or not.
    pub fn flush_cond<Q, P: FnMut(&Q) -> bool>(&mut self, pred: &mut P)
    where
        K: borrow::Borrow<Q>,
    {
        let mut locked_slots_states = self.cache.slots_states.lock();
        let mut keys_to_slots_map_pos = 0;
        while keys_to_slots_map_pos < locked_slots_states.keys_to_slots.keys_to_slots.len() {
            if !pred(
                locked_slots_states.keys_to_slots.keys_to_slots[keys_to_slots_map_pos]
                    .key
                    .borrow(),
            ) {
                keys_to_slots_map_pos += 1;
                continue;
            }

            let slot_index =
                locked_slots_states.keys_to_slots.keys_to_slots[keys_to_slots_map_pos].slot_index;
            locked_slots_states
                .keys_to_slots
                .keys_to_slots
                .remove(keys_to_slots_map_pos);
            // The slots allocation semaphore is being held exlusively, there cannot be any
            // active reservations.
            debug_assert!(matches!(
                locked_slots_states.slots_states[slot_index],
                SlotState::Used {
                    key: _,
                    reservations: SlotReservationCount::NoReservations { .. }
                }
            ));
            locked_slots_states.slots_states[slot_index] = SlotState::Empty;
            self.slots_exclusive_all_guard.vec[slot_index] = ST::Lock::from(None);
        }
    }

    /// Flush all cached entries.
    ///
    /// Completely prune the cache.
    pub fn flush_all(&mut self) {
        let mut locked_slots_states = self.cache.slots_states.lock();
        let mut keys_to_slots = mem::take(&mut locked_slots_states.keys_to_slots.keys_to_slots);
        for key_to_slot_entry in keys_to_slots.drain(..) {
            let slot_index = key_to_slot_entry.slot_index;
            debug_assert!(matches!(
                locked_slots_states.slots_states[slot_index],
                SlotState::Used {
                    key: _,
                    reservations: SlotReservationCount::NoReservations { .. }
                }
            ));
            locked_slots_states.slots_states[slot_index] = SlotState::Empty;
            self.slots_exclusive_all_guard.vec[slot_index] = ST::Lock::from(None);
        }
    }

    /// Change the [`Cache`]'s number of available slots.
    ///
    /// # Arguments:
    ///
    /// * `nslots` - New number of available cache entries. Must be greater than
    ///   zero and **strictly** less than `usize::MAX`.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn resize_cache_capacity(&mut self, nslots: usize) -> Result<(), interface::TpmErr> {
        debug_assert!(nslots > 0 && nslots < usize::MAX);
        let old_nslots = self.slots_exclusive_all_guard.semaphore().max_leases();
        match nslots.cmp(&old_nslots) {
            cmp::Ordering::Less => self.shrink_cache_capacity(nslots),
            cmp::Ordering::Greater => self.grow_cache_capacity(nslots),
            cmp::Ordering::Equal => Ok(()),
        }
    }

    /// Shrink the cache capacity.
    ///
    /// By the time this function gets invoked, it's assumed the new capacity
    /// has been determined to be strictly smaller than the current one.
    ///
    /// # Arguments:
    ///
    /// * `nslots` - New number of available cache entries. Must be greater than
    ///   zero and **strictly** less than `usize::MAX`.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn shrink_cache_capacity(&mut self, nslots: usize) -> Result<(), interface::TpmErr> {
        debug_assert!(nslots > 0 && nslots < usize::MAX);
        let mut locked_slots_states = self.cache.slots_states.lock();
        // First evict until the number of occupied slots is <= nslots.
        let used_slots =
            locked_slots_states
                .slots_states
                .iter()
                .fold(0usize, |used_slots, slot_state| {
                    used_slots
                        + match slot_state {
                            SlotState::Used {
                                key: _,
                                reservations,
                            } => {
                                // The slots allocation semaphore is being held exlusively, there
                                // cannot be any
                                // active reservations.
                                debug_assert!(matches!(
                                    reservations,
                                    SlotReservationCount::NoReservations { .. }
                                ));
                                1
                            }
                            SlotState::Empty => 0,
                        }
                });
        for _ in nslots..used_slots {
            let evicted_slot_index = locked_slots_states.try_evict_slot().unwrap();
            self.slots_exclusive_all_guard.vec[evicted_slot_index] = ST::Lock::from(None);
        }
        let used_slots = used_slots.min(nslots);

        let mut new_keys_to_slots = vec::Vec::new();
        new_keys_to_slots
            .try_reserve_exact(used_slots)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        let mut new_slots_states = vec::Vec::new();
        new_slots_states
            .try_reserve_exact(nslots)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        let mut new_slots = vec::Vec::new();
        new_slots
            .try_reserve_exact(nslots)
            .map_err(|_| tpm_err_rc!(MEMORY))?;

        let mut old_keys_to_slots = mem::take(&mut locked_slots_states.keys_to_slots.keys_to_slots);
        debug_assert!(old_keys_to_slots.len() <= used_slots);
        for (map_pos, mut map_entry) in old_keys_to_slots.drain(..).enumerate() {
            let old_slot_index = map_entry.slot_index;
            new_slots_states.push(mem::replace(
                &mut locked_slots_states.slots_states[old_slot_index],
                SlotState::Empty,
            ));
            new_slots.push(ST::Lock::from(
                self.slots_exclusive_all_guard.vec[old_slot_index]
                    .get_mut()
                    .take(),
            ));
            map_entry.slot_index = map_pos;
            new_keys_to_slots.push(map_entry);
        }
        new_slots_states.resize_with(nslots, || SlotState::Empty);
        new_slots.resize_with(nslots, || ST::Lock::from(None));

        locked_slots_states.keys_to_slots.keys_to_slots = new_keys_to_slots;
        locked_slots_states.slots_states = new_slots_states;
        self.slots_exclusive_all_guard.vec = new_slots;

        self.slots_exclusive_all_guard.resize_future(nslots);

        Ok(())
    }

    /// Increase the cache capacity.
    ///
    /// By the time this function gets invoked, it's assumed the new capacity
    /// has been determined to be strictly larger than the current one.
    ///
    /// # Arguments:
    ///
    /// * `nslots` - New number of available cache entries. Must be greater than
    ///   zero and **strictly** less than `usize::MAX`.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn grow_cache_capacity(&mut self, nslots: usize) -> Result<(), interface::TpmErr> {
        debug_assert!(nslots > 0 && nslots < usize::MAX);
        let mut locked_slots_states = self.cache.slots_states.lock();
        let old_nslots = locked_slots_states.slots_states.len();
        locked_slots_states
            .slots_states
            .try_reserve_exact(nslots - old_nslots)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        self.slots_exclusive_all_guard
            .vec
            .try_reserve_exact(nslots - old_nslots)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        locked_slots_states
            .slots_states
            .resize_with(nslots, || SlotState::Empty);
        self.slots_exclusive_all_guard
            .vec
            .resize_with(nslots, || ST::Lock::from(None));
        self.slots_exclusive_all_guard.resize_future(nslots);
        Ok(())
    }
}

/// Asynchronously wait for exlusive access to a [`Cache`].
///
/// To be obtained through [`Cache::lock_exclusive()`].
///
/// # Note on lifetime management
///
/// A [`CacheExclusiveLockFuture`] instance will only maintain a weak reference
/// (i.e. a [`Weak`](sync::Weak)) to the associated [`Cache`] instance and thus,
/// would not hinder its deallocation. In case the cache gets dropped before the
/// future had a chance to complete, its `poll()` would return
/// [`TpmRc::RETRY`](interface::TpmRc::RETRY).
pub struct CacheExclusiveLockFuture<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> {
    /// The [`Cache`] instance to obtain an exclusive lock on.
    cache: sync::Weak<Cache<ST, K, V>>,
    slots_exlusive_all_fut: AsyncSemaphoreExclusiveAllFuture<ST, SlotsVec<ST, V>>,
}

impl<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> future::Future
    for CacheExclusiveLockFuture<ST, K, V>
{
    type Output = Result<CacheExclusiveLockGuard<ST, K, V>, interface::TpmErr>;

    /// Poll for exclusive access to the associated [`Cache`] to become
    /// available.
    ///
    /// Upon successful future completion, a [`CacheExclusiveLockGuard`] will
    /// get returned, an error indicator otherwise.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::RETRY`](interface::TpmRc::RETRY) - The reference to the
    ///   associated [`Cache`] instance has become stale, indicating some
    ///   teardown going on.
    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match future::Future::poll(
            pin::Pin::new(&mut self.deref_mut().slots_exlusive_all_fut),
            cx,
        ) {
            task::Poll::Ready(result) => match result {
                Ok(slots_exclusive_all_guard) => {
                    let cache = match self.cache.upgrade() {
                        Some(cache) => cache,
                        None => {
                            return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                        }
                    };
                    task::Poll::Ready(Ok(CacheExclusiveLockGuard {
                        cache,
                        slots_exclusive_all_guard,
                    }))
                }
                Err(e) => task::Poll::Ready(Err(e)),
            },
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

impl<ST: sync_types::SyncTypes, K: cmp::Ord + Clone, V> marker::Unpin
    for CacheExclusiveLockFuture<ST, K, V>
{
}
