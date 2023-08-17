extern crate alloc;

use crate::interface;
use crate::leases;
use crate::session::{Session, SessionState};
use crate::sync_types::{PinArcLock, PinArcLockGuard, RwLock, SyncTypes};
use crate::utils::arc_try_new;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::num::NonZeroU16;
use core::ops::{Deref, DerefMut, Index, IndexMut};

pub struct Sessions<ST: SyncTypes> {
    max_loaded: u16,
    free_load_slots: u16,
    loaded: Vec<Option<(PinArcLock<ST, LoadedSession>, LoadedSessionMeta)>>,
    load_counter: u64,

    max_active: u16,
    active: Vec<Option<NonZeroU16>>,
    context_counter: u64,
    oldest_saved_active_index: Option<u16>,

    this: Weak<ST::RwLock<Self>>,
}

struct LoadedSession {
    session: Option<Session>,
}

#[derive(Clone, Copy)]
enum LoadedSessionType {
    Hmac,
    Policy,
}

impl From<&Session> for LoadedSessionType {
    fn from(value: &Session) -> Self {
        match &value.state {
            SessionState::Hmac(_) => Self::Hmac,
            SessionState::Policy(_) => Self::Policy,
        }
    }
}

struct LoadedSessionMeta {
    load_id: u64,
    session_type: LoadedSessionType,
}

pub struct LoadedSessionLease<ST: SyncTypes> {
    sessions: Weak<ST::RwLock<Sessions<ST>>>,
    /// Index of the associated slot within the Sessions::active array.
    active_index: u16,
    /// A snapshot of the Session::loaded slot's load generation counter
    /// for tracking lease validity.
    load_id: u64,
    /// Cached session type to allow for implementing Self::get_handle() without
    /// taking a lock on the Sessions registry.
    session_type: LoadedSessionType,
}

const SH_ACTIVE_INDEX_MASK: u32 = 0x00ffffff;
const SH_TYPE_MASK: u32 = 0xff000000;
const SH_TYPE_SHIFT: u8 = 24;

impl<ST: SyncTypes> LoadedSessionLease<ST> {
    pub fn try_hold(&self) -> Option<LockedLoadedSession<'_, ST>> {
        let sessions = self.sessions.upgrade()?;

        let sessions_rlocked = sessions.read();
        let load_index = sessions_rlocked.get_load_index(self.active_index)?;

        // A successful retrieval of the load_index implies the loaded[] slot is filled.
        let loaded = sessions_rlocked.loaded[load_index].as_ref().unwrap();
        if loaded.1.load_id != self.load_id {
            return None;
        }

        let session: PinArcLock<ST, LoadedSession> = loaded.0.clone();
        drop(sessions_rlocked);

        let session = LockedLoadedSession {
            lease: self,
            guard: session.lock(),
        };
        session.guard.session.as_ref()?;
        Some(session)
    }

    pub fn get_handle(&self) -> u32 {
        let ht = match &self.session_type {
            LoadedSessionType::Hmac => interface::TpmHt::HMAC_SESSION,
            LoadedSessionType::Policy => interface::TpmHt::POLICY_SESSION,
        };
        let ht = (ht as u32) << SH_TYPE_SHIFT;
        ht | self.active_index as u32
    }

    pub fn save(self) -> Result<Option<(u64, Session)>, u32> {
        Sessions::save_session(self)
    }

    pub fn flush(self) -> Option<Session> {
        Sessions::flush_session(self)
    }
}

impl<ST: SyncTypes> leases::Lease for LoadedSessionLease<ST> {
    fn get_handle(&self) -> u32 {
        LoadedSessionLease::get_handle(self)
    }
}

pub struct LockedLoadedSession<'a, ST: SyncTypes> {
    lease: &'a LoadedSessionLease<ST>,
    guard: PinArcLockGuard<'a, ST, LoadedSession>,
}

impl<'a, ST: SyncTypes> leases::LockedLeaseGuard<'a> for LockedLoadedSession<'a, ST> {}

impl<'a, ST: SyncTypes> LockedLoadedSession<'a, ST> {
    pub fn flush(self) -> Session {
        Sessions::flush_locked_session(self)
    }
}

impl<'a, ST: SyncTypes> Deref for LockedLoadedSession<'a, ST>
where
    <ST as SyncTypes>::Lock<LoadedSession>: 'a,
{
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        self.guard.deref().session.as_ref().unwrap()
    }
}

impl<'a, ST: SyncTypes> DerefMut for LockedLoadedSession<'a, ST>
where
    <ST as SyncTypes>::Lock<LoadedSession>: 'a,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.deref_mut().session.as_mut().unwrap()
    }
}

pub struct LoadedSessionsLeases<ST: SyncTypes> {
    sessions: Weak<ST::RwLock<Sessions<ST>>>,
    leases: leases::Leases<LoadedSessionLease<ST>>,
}

impl<ST: SyncTypes> LoadedSessionsLeases<ST> {
    fn new<HI: ExactSizeIterator<Item = u32>>(
        sessions: Arc<ST::RwLock<Sessions<ST>>>,
        handles: HI,
    ) -> Result<Self, interface::TpmErr> {
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(handles.len())
            .map_err(|_| tpm_err_rc!(MEMORY))?;

        let sessions_rlocked = sessions.read();
        for handle in handles {
            let lease = sessions_rlocked
                .get_lease(handle)
                .ok_or_else(|| interface::TpmErr::Rc(Self::index_to_rc_reference(leases.len())))?;
            leases.push(lease);
        }
        drop(sessions_rlocked);

        Ok(Self {
            sessions: Arc::downgrade(&sessions),
            leases: leases::Leases::new(leases)?,
        })
    }

    fn empty(sessions: Arc<ST::RwLock<Sessions<ST>>>) -> Self {
        Self {
            sessions: Arc::downgrade(&sessions),
            leases: leases::Leases::empty(),
        }
    }

    pub fn add(&mut self, handle: u32) -> Result<(), interface::TpmErr> {
        let sessions = self.sessions.upgrade().ok_or(tpm_err_rc!(RETRY))?;
        let lease = sessions
            .read()
            .get_lease(handle)
            .ok_or_else(|| interface::TpmErr::Rc(Self::index_to_rc_reference(self.leases.len())))?;
        self.leases.push(lease)
    }

    pub fn len(&self) -> usize {
        self.leases.len()
    }

    pub fn distinct_len(&self) -> usize {
        self.leases.distinct_len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    fn handle_to_first_index(&self, handle: u32) -> Option<usize> {
        self.leases.index_with_handle_iter(handle).next()
    }

    pub fn handle_to_rc_fmt1_addend(&self, handle: u32) -> u32 {
        let index = self.handle_to_first_index(handle).unwrap_or(0);
        match index {
            0 => tpm_rc!(RC_S) + tpm_rc!(RC_1),
            1 => tpm_rc!(RC_S) + tpm_rc!(RC_2),
            2 => tpm_rc!(RC_S) + tpm_rc!(RC_3),
            3 => tpm_rc!(RC_S) + tpm_rc!(RC_4),
            4 => tpm_rc!(RC_S) + tpm_rc!(RC_5),
            5 => tpm_rc!(RC_S) + tpm_rc!(RC_6),
            6 => tpm_rc!(RC_S) + tpm_rc!(RC_7),
            7 => tpm_rc!(RC_S) + tpm_rc!(RC_8),
            8 => tpm_rc!(RC_S) + tpm_rc!(RC_9),
            9 => tpm_rc!(RC_S) + tpm_rc!(RC_A),
            10 => tpm_rc!(RC_S) + tpm_rc!(RC_B),
            11 => tpm_rc!(RC_S) + tpm_rc!(RC_C),
            12 => tpm_rc!(RC_S) + tpm_rc!(RC_D),
            13 => tpm_rc!(RC_S) + tpm_rc!(RC_E),
            14 => tpm_rc!(RC_S) + tpm_rc!(RC_F),
            _ => 0,
        }
    }

    fn index_to_rc_reference(index: usize) -> u32 {
        match index {
            0 => tpm_rc!(REFERENCE_S0),
            1 => tpm_rc!(REFERENCE_S1),
            2 => tpm_rc!(REFERENCE_S2),
            3 => tpm_rc!(REFERENCE_S3),
            4 => tpm_rc!(REFERENCE_S4),
            5 => tpm_rc!(REFERENCE_S5),
            _ => tpm_rc!(REFERENCE_S6),
        }
    }

    fn handle_to_rc_reference(&self, handle: u32) -> u32 {
        let index = self.handle_to_first_index(handle).unwrap_or(0);
        Self::index_to_rc_reference(index)
    }

    pub fn try_hold<'a>(&'a self) -> Result<LockedLoadedSessions<'a, ST>, interface::TpmErr> {
        let guards = self
            .leases
            .try_hold(&mut |leases: &'a [LoadedSessionLease<ST>]| {
                let mut guards = Vec::new();
                if leases.is_empty() {
                    return Ok(guards);
                }
                guards
                    .try_reserve_exact(self.distinct_len())
                    .map_err(|_| tpm_err_rc!(MEMORY))?;

                let mut sessions_refs = Vec::new();
                sessions_refs
                    .try_reserve_exact(self.distinct_len())
                    .map_err(|_| tpm_err_rc!(MEMORY))?;

                let sessions = self.sessions.upgrade().ok_or(tpm_err_rc!(RETRY))?;
                let sessions_rlocked = sessions.read();
                for lease in leases.iter() {
                    let load_index = sessions_rlocked
                        .get_load_index(lease.active_index)
                        .ok_or_else(|| {
                            interface::TpmErr::Rc(self.handle_to_rc_reference(lease.get_handle()))
                        })?;
                    // A successful retrieval of the load_index implies the loaded[] slot is filled.
                    let loaded = sessions_rlocked.loaded[load_index].as_ref().unwrap();
                    if loaded.1.load_id != lease.load_id {
                        return Err(interface::TpmErr::Rc(
                            self.handle_to_rc_reference(lease.get_handle()),
                        ));
                    }

                    let session: PinArcLock<ST, LoadedSession> = loaded.0.clone();
                    sessions_refs.push(session)
                }
                drop(sessions_rlocked);

                for (index, session) in sessions_refs.drain(..).enumerate() {
                    let session = LockedLoadedSession {
                        lease: &leases[index],
                        guard: session.lock(),
                    };
                    if session.guard.session.is_none() {
                        let handle = self.leases[index].get_handle();
                        return Err(interface::TpmErr::Rc(self.handle_to_rc_reference(handle)));
                    }
                    guards.push(session);
                }

                Ok(guards)
            })?;
        Ok(LockedLoadedSessions { guards })
    }
}

impl<ST: SyncTypes> Index<usize> for LoadedSessionsLeases<ST> {
    type Output = LoadedSessionLease<ST>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.leases[index]
    }
}

pub struct LockedLoadedSessions<'a, ST: SyncTypes> {
    guards: leases::LockedLeasesGuards<'a, LoadedSessionLease<ST>, LockedLoadedSession<'a, ST>>,
}

impl<'a, ST: SyncTypes> LockedLoadedSessions<'a, ST> {
    pub fn len(&self) -> usize {
        self.guards.len()
    }

    pub fn distinct_len(&self) -> usize {
        self.guards.distinct_len()
    }

    pub fn is_empty(&self) -> bool {
        self.guards.is_empty()
    }

    pub fn iter_distinct(
        &'_ self,
    ) -> leases::DistinctLockedLeasesIterator<
        'a,
        '_,
        LoadedSessionLease<ST>,
        LockedLoadedSession<'a, ST>,
    > {
        self.guards.iter_distinct()
    }

    pub fn iter_distinct_mut(
        &'_ mut self,
    ) -> leases::DistinctLockedLeasesMutIterator<
        'a,
        '_,
        LoadedSessionLease<ST>,
        LockedLoadedSession<'a, ST>,
    > {
        self.guards.iter_distinct_mut()
    }
}

impl<'a, ST: SyncTypes> Index<usize> for LockedLoadedSessions<'a, ST> {
    type Output = LockedLoadedSession<'a, ST>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.guards[index]
    }
}

impl<'a, ST: SyncTypes> IndexMut<usize> for LockedLoadedSessions<'a, ST> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.guards[index]
    }
}

impl<ST: SyncTypes> Sessions<ST> {
    fn check_params(max_loaded: u16, max_active: u16) -> Result<(), interface::TpmErr> {
        if max_loaded == 0 || max_loaded >= max_active {
            Err(tpm_err_internal!())
        } else {
            Ok(())
        }
    }

    pub fn new(
        max_loaded: u16,
        max_active: u16,
    ) -> Result<Arc<ST::RwLock<Self>>, interface::TpmErr> {
        Self::check_params(max_loaded, max_active)?;

        let mut loaded = Vec::new();
        loaded
            .try_reserve_exact(max_loaded as usize)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        loaded.resize_with(max_loaded as usize, || None);

        let mut active = Vec::new();
        active
            .try_reserve_exact(max_active as usize)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        active.resize(max_active as usize, None);

        let sessions = arc_try_new(ST::RwLock::<Self>::from(Self {
            max_loaded,
            free_load_slots: max_loaded,
            loaded,
            load_counter: 0,
            max_active,
            active,
            context_counter: max_loaded as u64 + 1,
            oldest_saved_active_index: None,
            this: Weak::new(),
        }))?;
        sessions.write().this = Arc::downgrade(&sessions);

        Ok(sessions)
    }

    pub fn load<S: Iterator<Item = u16>>(
        max_loaded: u16,
        max_active: u16,
        saved_active_context_ids: S,
        context_counter: u64,
    ) -> Result<Arc<ST::RwLock<Self>>, interface::TpmErr> {
        Self::check_params(max_loaded, max_active)?;

        let mut loaded = Vec::new();
        loaded
            .try_reserve_exact(max_loaded as usize)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        loaded.resize_with(max_loaded as usize, || None);

        let mut active = Vec::new();
        active
            .try_reserve_exact(max_active as usize)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        for saved_context_id in saved_active_context_ids {
            if active.len() == max_active as usize {
                return Err(tpm_err_internal!());
            }

            let saved_context_id = NonZeroU16::new(saved_context_id)
                .map(|saved_context_id| {
                    if saved_context_id.get() <= max_loaded {
                        Err(tpm_err_internal!())
                    } else {
                        Ok(saved_context_id)
                    }
                })
                .transpose()?;
            active.push(saved_context_id);
        }
        if active.len() != max_active as usize {
            return Err(tpm_err_internal!());
        }

        if context_counter <= max_loaded as u64 {
            return Err(tpm_err_internal!());
        }

        let sessions = arc_try_new(ST::RwLock::<Self>::from(Self {
            max_loaded,
            free_load_slots: max_loaded,
            loaded,
            load_counter: 0,
            max_active,
            active,
            context_counter,
            oldest_saved_active_index: None,
            this: Weak::new(),
        }))?;
        let mut sessions_wlocked = sessions.write();
        sessions_wlocked.update_oldest_saved_active();
        sessions_wlocked.this = Arc::downgrade(&sessions);
        drop(sessions_wlocked);

        Ok(sessions)
    }

    fn update_oldest_saved_active(&mut self) {
        let context_counter_lsb16 = self.context_counter as u16;
        self.oldest_saved_active_index = self
            .active
            .iter()
            .enumerate()
            .filter_map(|(active_index, entry)| {
                entry
                    .filter(|load_index_or_context_id| {
                        load_index_or_context_id.get() > self.max_loaded
                    })
                    .map(|context_id| {
                        (
                            active_index,
                            context_counter_lsb16.wrapping_sub(context_id.get()),
                        )
                    })
            })
            .max_by(|(_, context_id0), (_, context_id1)| context_id0.cmp(context_id1))
            .map(|(active_index, _)| u16::try_from(active_index).unwrap());
    }

    fn get_load_index(&self, active_index: u16) -> Option<usize> {
        if active_index >= self.max_active {
            return None;
        }

        self.active[active_index as usize]
            .map(|load_index_or_context_id| load_index_or_context_id.get())
            .and_then(|load_index_or_context_id| {
                if load_index_or_context_id > self.max_loaded {
                    None
                } else {
                    Some(load_index_or_context_id - 1)
                }
            })
            .map(|load_index| load_index as usize)
    }

    fn handle_to_active_index(&self, handle: u32) -> Option<u16> {
        u16::try_from(handle & SH_ACTIVE_INDEX_MASK)
            .ok()
            .and_then(|active_index| {
                if active_index < self.max_active {
                    Some(active_index)
                } else {
                    None
                }
            })
    }

    fn handle_type(handle: u32) -> u8 {
        ((handle & SH_TYPE_MASK) >> SH_TYPE_SHIFT) as u8
    }

    pub fn get_lease(&self, handle: u32) -> Option<LoadedSessionLease<ST>> {
        let active_index = self.handle_to_active_index(handle)?;
        let load_index = self.get_load_index(active_index)?;

        let loaded = self.loaded[load_index].as_ref().unwrap();
        let session_type = loaded.1.session_type;
        let handle_type = Self::handle_type(handle);
        match session_type {
            LoadedSessionType::Hmac => {
                if handle_type != interface::TpmHt::HMAC_SESSION {
                    return None;
                }
            }
            LoadedSessionType::Policy => {
                if handle_type != interface::TpmHt::POLICY_SESSION {
                    return None;
                }
            }
        }
        let load_id = loaded.1.load_id;

        Some(LoadedSessionLease {
            sessions: self.this.clone(),
            active_index,
            load_id,
            session_type,
        })
    }

    pub fn get_leases<HI: ExactSizeIterator<Item = u32>>(
        &self,
        handles: HI,
    ) -> Result<LoadedSessionsLeases<ST>, interface::TpmErr> {
        LoadedSessionsLeases::new(self.this.upgrade().unwrap(), handles)
    }

    pub fn empty_leases(&self) -> LoadedSessionsLeases<ST> {
        LoadedSessionsLeases::empty(self.this.upgrade().unwrap())
    }

    fn have_context_gap(&self) -> bool {
        if let Some(oldest_saved_active_index) = self.oldest_saved_active_index {
            let oldest_active_context_id = self.active[oldest_saved_active_index as usize]
                .unwrap()
                .get();
            oldest_active_context_id == self.context_counter as u16
        } else {
            false
        }
    }

    fn find_free_load_slot(&self) -> u16 {
        self.loaded
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.is_none())
            .map(|(load_index, _)| load_index)
            .unwrap() as u16
    }

    fn alloc_load_id(&mut self) -> Result<u64, u32> {
        let load_id = self.load_counter;
        self.load_counter = self
            .load_counter
            .checked_add(1)
            .ok_or(tpm_rc!(TOO_MANY_CONTEXTS))?;
        Ok(load_id)
    }

    fn install_session(
        &mut self,
        active_index: u16,
        session: Session,
        session_type: LoadedSessionType,
    ) -> Result<LoadedSessionLease<ST>, u32> {
        let load_index = self.find_free_load_slot();
        let load_id = self.alloc_load_id()?;
        self.loaded[load_index as usize] = Some((
            PinArcLock::try_new(LoadedSession {
                session: Some(session),
            })
            .map_err(|_| tpm_rc!(MEMORY))?,
            LoadedSessionMeta {
                load_id,
                session_type,
            },
        ));
        self.active[active_index as usize] = Some(NonZeroU16::new(load_index + 1).unwrap());
        Ok(LoadedSessionLease {
            sessions: self.this.clone(),
            active_index,
            load_id,
            session_type,
        })
    }

    pub fn create_session(&mut self, session: Session) -> Result<LoadedSessionLease<ST>, u32> {
        if self.free_load_slots == 1 && self.have_context_gap() {
            return Err(tpm_rc!(CONTEXT_GAP));
        } else if self.free_load_slots == 0 {
            return Err(tpm_rc!(SESSION_MEMORY));
        }

        let active_index = self
            .active
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.is_none())
            .map(|(active_index, _)| active_index)
            .ok_or(tpm_rc!(SESSION_HANDLES))?;

        let session_type = LoadedSessionType::from(&session);
        self.install_session(active_index as u16, session, session_type)
    }

    fn context_id_is_latest(&self, active_context_id: u16, context_id: u64) -> bool {
        active_context_id > self.max_loaded
            && active_context_id == context_id as u16
            && context_id < self.context_counter
            && self.context_counter - context_id <= (u16::MAX as u64) + 1
    }

    pub fn load_session(
        &mut self,
        handle: u32,
        context_id: u64,
        session: Session,
    ) -> Result<LoadedSessionLease<ST>, u32> {
        const RC_INVALID_CONTEXT: u32 = tpm_rc!(HANDLE) + tpm_rc!(RC_P) + tpm_rc!(RC_1);

        let session_type = LoadedSessionType::from(&session);
        let handle_type = Self::handle_type(handle);
        match session_type {
            LoadedSessionType::Hmac => {
                if handle_type != interface::TpmHt::HMAC_SESSION {
                    return Err(tpm_rc!(BAD_CONTEXT));
                }
            }
            LoadedSessionType::Policy => {
                if handle_type != interface::TpmHt::POLICY_SESSION {
                    return Err(tpm_rc!(BAD_CONTEXT));
                }
            }
        }

        let active_index = self
            .handle_to_active_index(handle)
            .ok_or(tpm_rc!(BAD_CONTEXT))?;

        if self.free_load_slots == 1
            && self.have_context_gap()
            && self.oldest_saved_active_index.unwrap() != active_index
        {
            return Err(tpm_rc!(CONTEXT_GAP));
        } else if self.free_load_slots == 0 {
            return Err(tpm_rc!(SESSION_MEMORY));
        }

        let active_context_id = self.active[active_index as usize]
            .ok_or(RC_INVALID_CONTEXT)?
            .get();
        if !self.context_id_is_latest(active_context_id, context_id) {
            return Err(RC_INVALID_CONTEXT);
        }

        let lease = self.install_session(active_index, session, session_type);
        if lease.is_ok() {
            if let Some(oldest_saved_active_index) = self.oldest_saved_active_index {
                if oldest_saved_active_index == active_index {
                    self.update_oldest_saved_active();
                }
            }
        }
        lease
    }

    fn save_session(lease: LoadedSessionLease<ST>) -> Result<Option<(u64, Session)>, u32> {
        let this = match lease.sessions.upgrade() {
            Some(this) => this,
            None => return Ok(None),
        };

        let mut this_wlocked = this.write();
        if this_wlocked.have_context_gap() {
            return Err(tpm_rc!(CONTEXT_GAP));
        }

        let active_index = lease.active_index;
        let load_index = match this_wlocked.get_load_index(active_index) {
            Some(load_index) => load_index,
            None => return Ok(None),
        };
        // A successful retrieval of the load_index implies the loaded[] slot is filled.
        let loaded = this_wlocked.loaded[load_index].as_ref().unwrap();
        if loaded.1.load_id != lease.load_id {
            return Ok(None);
        }
        let session = this_wlocked.loaded[load_index].take().unwrap();
        this_wlocked.free_load_slots += 1;

        let context_id = this_wlocked.context_counter;
        this_wlocked.context_counter = this_wlocked
            .context_counter
            .checked_add(1)
            .ok_or(tpm_rc!(TOO_MANY_CONTEXTS))?;
        if this_wlocked.context_counter as u16 == 0 {
            this_wlocked.context_counter += this_wlocked.max_loaded as u64 + 1;
        }

        this_wlocked.active[active_index as usize] =
            Some(NonZeroU16::new(context_id as u16).unwrap());
        if this_wlocked.oldest_saved_active_index.is_none() {
            this_wlocked.oldest_saved_active_index = Some(active_index);
        }
        drop(this_wlocked);

        let mut session_locked = session.0.lock();
        let session = session_locked.session.take();
        drop(session_locked);

        match session {
            Some(session) => Ok(Some((context_id, session))),
            None => {
                // A "locked flush" from Self::flush_locked_session() executed concurrently
                // and has grabbed the session away. It will leave the context_id recorded in
                // Self::active[] from the code above there, but a subsequent
                // Self::flush_session() could have flushed it in the meanwhile.
                // So only flush the now stale context_id again if it's still
                // the same.
                let mut this_wlocked = this.write();
                if let Some(active_context_id) = this_wlocked.active[active_index as usize] {
                    if this_wlocked.context_id_is_latest(active_context_id.get(), context_id) {
                        this_wlocked.active[active_index as usize] = None;
                        if let Some(oldest_saved_active_index) =
                            this_wlocked.oldest_saved_active_index
                        {
                            if oldest_saved_active_index == active_index {
                                this_wlocked.update_oldest_saved_active();
                            }
                        }
                    }
                }
                Ok(None)
            }
        }
    }

    fn flush_session(lease: LoadedSessionLease<ST>) -> Option<Session> {
        let this = lease.sessions.upgrade()?;

        let mut this_wlocked = this.write();
        let active_index = lease.active_index;
        let load_index = match this_wlocked.get_load_index(active_index) {
            Some(load_index) => load_index,
            None => {
                // Flush request for a saved session context.
                this_wlocked.active[active_index as usize] = None;
                if let Some(oldest_saved_active_index) = this_wlocked.oldest_saved_active_index {
                    if oldest_saved_active_index == active_index {
                        this_wlocked.update_oldest_saved_active();
                    }
                }
                return None;
            }
        };
        // A successful retrieval of the load_index implies the loaded[] slot is filled.
        let loaded = this_wlocked.loaded[load_index].as_ref().unwrap();
        if loaded.1.load_id != lease.load_id {
            return None;
        }
        this_wlocked.active[active_index as usize] = None;
        let session = this_wlocked.loaded[load_index].take().unwrap();
        this_wlocked.free_load_slots += 1;
        drop(this_wlocked);

        let mut session_locked = session.0.lock();
        let session = session_locked.session.take();
        drop(session_locked);

        session
    }

    fn flush_locked_session(mut locked_session: LockedLoadedSession<ST>) -> Session {
        let session = locked_session.guard.session.take().unwrap();
        let lease = locked_session.lease;
        drop(locked_session.guard);

        let this = match lease.sessions.upgrade() {
            Some(this) => this,
            None => return session,
        };

        let mut this_wlocked = this.write();
        let load_index = match this_wlocked.get_load_index(lease.active_index) {
            Some(load_index) => load_index,
            None => {
                // A concurrent Self::save_session() or Self::flush_session() is in progress. In
                // either case, the session handle will be or has been freed from there.
                return session;
            }
        };
        // A successful retrieval of the load_index implies the loaded[] slot is filled.
        let loaded = this_wlocked.loaded[load_index].as_ref().unwrap();
        if loaded.1.load_id != lease.load_id {
            // A concurrent Self::save_session() or Self::flush_session() is in progress,
            // freed the Self::active[] slot and some other session got
            // installed there in the meanwhile. In either case, the session
            // handle of concern has been freed.
            return session;
        }
        this_wlocked.active[lease.active_index as usize] = None;
        this_wlocked.loaded[load_index].take().unwrap();
        this_wlocked.free_load_slots += 1;
        session
    }
}
