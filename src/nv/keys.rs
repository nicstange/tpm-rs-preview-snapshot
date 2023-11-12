// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;

use super::cache;
use crate::crypto::{hash, io_slices, kdf, symcipher};
use crate::interface;
use crate::sync_types;
use crate::utils;
use alloc::{sync, vec};
use core::ops::DerefMut;
use core::{array, future, marker, ops, pin, task, slice};
use kdf::Kdf as _;
use utils::cfg_zeroize;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum KeyPurpose {
    Derivation,
    Authentication = 1,
    PreAuthCcaMitigationAuthentication = 2,
    Encryption = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyId {
    domain: u32,
    purpose: KeyPurpose,
}

impl KeyId {
    pub fn new(domain: u32, purpose: KeyPurpose) -> Self {
        Self { domain, purpose }
    }
}

pub struct Keys<ST: sync_types::SyncTypes> {
    root_key: cfg_zeroize::Zeroizing<vec::Vec<u8>>,

    kdf_hash_alg: interface::TpmiAlgHash,

    auth_hmac_key_len: usize,
    preauth_cca_mitigation_hmac_key_len: usize,
    block_cipher_key_len: usize,

    key_cache: sync::Arc<cache::Cache<ST, KeyId, cfg_zeroize::Zeroizing<vec::Vec<u8>>>>,
}

impl<ST: sync_types::SyncTypes> Keys<ST> {
    pub fn new(
        key: &[u8],
        salt: &[u8],
        kdf_hash_alg: interface::TpmiAlgHash,
        auth_hmac_hash_alg: interface::TpmiAlgHash,
        auth_tree_hash_alg: interface::TpmiAlgHash,
        preauth_cca_mitigation_hmac_hash_alg: interface::TpmiAlgHash,
        block_cipher_alg: &symcipher::SymBlockCipherAlg,
    ) -> Result<sync::Arc<Self>, interface::TpmErr> {
        // Don't take the externally supplied key as the root key directly, but run it
        // through a KDF: the root key KDF's underlying hash algorithm is
        // mandatorily fixed to one with maximum supported security strength in
        // order to mitigate against downgrade attacks on the rest of the
        // parameter set. That is, downgrading any of the other parameters will yield
        // what is effectively a random root key, unrelated to the real one. The
        // security strength of the toplevel root key KDF would (hopefully) put
        // a barrier on any attempt to infer information about the externally
        // provided input key from knowledge gained about subkeys derived using
        // potentially weak methods.
        //
        // The context passed to KDFa for derivation of the root_key will be, in this
        // order,
        // - The magic 'TPMNV', without a null terminator.
        // - the image format version, as a big-endian u32, fixed to zero for now,
        // - the kdf_hash_alg, as a u16,
        // - the auth_hmac_hash_alg, as a u16,
        // - the auth_tree_hash_alg, as a u16,
        // - preauth_cca_mitigation_hmac_hash_alg, as a u16,
        // - the encryption parameters:
        //   - mode identifier as an u16, fixed to TpmiAlgCipherMode::Cfb for now,
        //     included for future extensibility,
        //   - block_cipher_alg, encoded as a pair block cipher identifier
        //     (TpmiAlgSymObject, u16) and key size, also an u16.
        // - The salt length, encoded as a big-endian u32.
        // - The salt itself.
        const CONTEXT_HEAD_LEN: usize = 5 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 4;
        let mut context_head = [0u8; CONTEXT_HEAD_LEN];
        let salt_len = u32::try_from(salt.len()).unwrap_or(u32::MAX);
        let context_tail = &salt[..salt_len as usize];
        let buf = context_head.as_mut_slice();
        buf[..5].copy_from_slice(b"TPMNV");
        let buf = &mut buf[5..];
        let buf = interface::marshal_u32(buf, 0);
        let buf = kdf_hash_alg.marshal(buf);
        let buf = auth_hmac_hash_alg.marshal(buf);
        let buf = auth_tree_hash_alg.marshal(buf);
        let buf = preauth_cca_mitigation_hmac_hash_alg.marshal(buf);
        let buf = interface::TpmiAlgCipherMode::Cbc.marshal(buf);
        let (block_cipher_alg_id, block_cipher_key_size) =
            <(interface::TpmiAlgSymObject, u16)>::from(block_cipher_alg);
        let buf = block_cipher_alg_id.marshal(buf);
        let buf = interface::marshal_u16(buf, block_cipher_key_size);
        let buf = interface::marshal_u32(buf, salt_len);
        debug_assert!(buf.is_empty());

        let root_key_len = hash::hash_alg_digest_len(kdf_hash_alg);
        let mut root_key = utils::try_alloc_zeroizing_vec::<u8>(root_key_len as usize)?;
        kdf::tcg_tpm2_kdf_a::TcgTpm2KdfA::new(
            interface::TpmiAlgHash::Sha512,
            key,
            &[KeyPurpose::Derivation as u8],
            Some(&context_head),
            Some(context_tail),
            8 * (root_key_len as u32),
        )?
        .generate(&mut io_slices::IoSlicesMut::new(&mut [Some(&mut root_key)]))?;

        let auth_hmac_key_len = hash::hash_alg_digest_len(auth_hmac_hash_alg) as usize;
        let preauth_cca_mitigation_hmac_key_len =
            hash::hash_alg_digest_len(preauth_cca_mitigation_hmac_hash_alg) as usize;
        let block_cipher_key_len = block_cipher_alg.key_len();

        let key_cache = cache::Cache::new(8)?;

        utils::arc_try_new(Self {
            root_key,
            kdf_hash_alg,
            auth_hmac_key_len,
            preauth_cca_mitigation_hmac_key_len,
            block_cipher_key_len,
            key_cache,
        })
    }

    pub fn derive_cached_keys<const N: usize>(
        self: &sync::Arc<Self>,
        key_ids: [KeyId; N],
    ) -> Result<KeysDeriveCachedKeysFuture<ST, N>, interface::TpmErr> {
        let mut cache_key_ids = vec::Vec::<KeyId>::new();
        cache_key_ids
            .try_reserve_exact(N)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        cache_key_ids.extend(key_ids.iter());
        let reserve_cache_slots_fut = self.key_cache.reserve_slots(KeyIds { key_ids })?;
        Ok(KeysDeriveCachedKeysFuture {
            keys: sync::Arc::downgrade(self),
            reserve_cache_slots_fut: Some(reserve_cache_slots_fut),
        })
    }

    pub fn try_derive_cached_keys<const N: usize>(
        self: &sync::Arc<Self>,
        key_ids: [KeyId; N],
    ) -> Result<Option<[CachedKey<ST>; N]>, interface::TpmErr> {
        let cache_slots_reservations = match self.key_cache.try_reserve_slots(key_ids.iter())? {
            Some(cache_slots_reservations) => cache_slots_reservations,
            None => return Ok(None),
        };
        Ok(Some(self.instantiate_cached_keys(
            &key_ids,
            cache_slots_reservations,
        )?))
    }

    fn instantiate_cached_keys<const N: usize>(
        &self,
        key_ids: &[KeyId; N],
        mut cache_slots_reservations: vec::Vec<
            cache::CacheSlotReservation<ST, KeyId, cfg_zeroize::Zeroizing<vec::Vec<u8>>>,
        >,
    ) -> Result<[CachedKey<ST>; N], interface::TpmErr> {
        let mut cached_keys: [Option<CachedKey<ST>>; N] = array::from_fn(|_| None);
        for (i, cache_slot_reservation) in cache_slots_reservations.drain(..).enumerate() {
            cached_keys[i] = Some(self.instantiate_cached_key(key_ids[i], cache_slot_reservation)?);
        }
        let cached_keys = array::from_fn(|i| cached_keys[i].take().unwrap());
        Ok(cached_keys)
    }

    fn instantiate_cached_key(
        &self,
        key_id: KeyId,
        cache_slot: cache::CacheSlotReservation<ST, KeyId, cfg_zeroize::Zeroizing<vec::Vec<u8>>>,
    ) -> Result<CachedKey<ST>, interface::TpmErr> {
        let locked_cache_slot = cache_slot.lock();
        if locked_cache_slot.is_some() {
            drop(locked_cache_slot);
            return Ok(CachedKey { cache_slot });
        }
        drop(locked_cache_slot);
        let key = self.derive_key(key_id)?;
        let mut locked_cache_slot = cache_slot.lock();
        *locked_cache_slot = Some(key);
        drop(locked_cache_slot);
        Ok(CachedKey { cache_slot })
    }

    pub fn derive_key(
        &self,
        key_id: KeyId,
    ) -> Result<cfg_zeroize::Zeroizing<vec::Vec<u8>>, interface::TpmErr> {
        let key_len = match key_id.purpose {
            KeyPurpose::Derivation => hash::hash_alg_digest_len(self.kdf_hash_alg) as usize,
            KeyPurpose::Authentication => self.auth_hmac_key_len,
            KeyPurpose::PreAuthCcaMitigationAuthentication => {
                self.preauth_cca_mitigation_hmac_key_len
            }
            KeyPurpose::Encryption => self.block_cipher_key_len,
        };
        let mut key = utils::try_alloc_zeroizing_vec(key_len)?;
        let domain = key_id.domain.to_be_bytes();
        kdf::tcg_tpm2_kdf_a::TcgTpm2KdfA::new(
            self.kdf_hash_alg,
            &self.root_key,
            &[key_id.purpose as u8],
            Some(&domain),
            None,
            8 * (key_len as u32),
        )?
        .generate(&mut io_slices::IoSlicesMut::new(&mut [Some(&mut key)]))?;
        Ok(key)
    }
}

struct KeyIds<const N: usize> {
    key_ids: [KeyId; N],
}

impl<const N: usize> cache::CacheKeys<KeyId> for KeyIds<N> {
    type Iterator<'a> = core::iter::Copied<slice::Iter<'a, KeyId>>;

    fn iter(&self) -> Self::Iterator<'_> {
        self.key_ids.iter().copied()
    }
}

pub struct KeysDeriveCachedKeysFuture<ST: sync_types::SyncTypes, const N: usize> {
    keys: sync::Weak<Keys<ST>>,
    #[allow(clippy::type_complexity)]
    reserve_cache_slots_fut: Option<
        cache::CacheReserveSlotsFuture<ST, KeyId, cfg_zeroize::Zeroizing<vec::Vec<u8>>, KeyId, KeyIds<N>>,
    >,
}

impl<ST: sync_types::SyncTypes, const N: usize> future::Future
    for KeysDeriveCachedKeysFuture<ST, N>
{
    type Output = Result<[CachedKey<ST>; N], interface::TpmErr>;

    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let reserve_cache_slots_fut =
            &mut self.deref_mut().reserve_cache_slots_fut.as_mut().unwrap();
        match pin::Pin::new(reserve_cache_slots_fut).poll(cx) {
            task::Poll::Ready(Ok((cache_slots_reservations, key_ids))) => {
                let keys = match self.keys.upgrade() {
                    Some(keys) => keys,
                    None => {
                        // The associated Keys instance is gone, indicating some teardown is in
                        // progress. Let the user retry to get a definitive
                        // error.
                        return task::Poll::Ready(Err(tpm_err_rc!(RETRY)));
                    }
                };
                self.deref_mut().reserve_cache_slots_fut = None;
                task::Poll::Ready(
                    keys.instantiate_cached_keys(&key_ids.key_ids, cache_slots_reservations),
                )
            }
            task::Poll::Ready(Err(e)) => Err(e)?,
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

impl<ST: sync_types::SyncTypes, const N: usize> marker::Unpin
    for KeysDeriveCachedKeysFuture<ST, N>
{
}

pub struct CachedKey<ST: sync_types::SyncTypes> {
    cache_slot: cache::CacheSlotReservation<ST, KeyId, cfg_zeroize::Zeroizing<vec::Vec<u8>>>,
}

impl<ST: sync_types::SyncTypes> CachedKey<ST> {
    pub fn get_key(&self) -> Key<'_, ST> {
        let locked_cache_slot = self.cache_slot.lock();
        debug_assert!(locked_cache_slot.is_some());
        Key { locked_cache_slot }
    }
}

pub struct Key<'a, ST: sync_types::SyncTypes> {
    locked_cache_slot: cache::CacheSlotLockGuard<'a, ST, cfg_zeroize::Zeroizing<vec::Vec<u8>>>,
}

impl<'a, ST: sync_types::SyncTypes> ops::Deref for Key<'a, ST> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.locked_cache_slot.as_ref().unwrap()
    }
}
