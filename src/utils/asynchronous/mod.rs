// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to Rust asynchronous support.

mod broadcast_future;
mod rwlock;
mod semaphore;
#[cfg(test)]
pub(crate) mod test;

pub use rwlock::{
    AsyncRwLock, AsyncRwLockReadGuard, AsyncRwLockReadFuture,
    AsyncRwLockWriteFuture, AsyncRwLockWriteGuard,
};
pub use semaphore::{
    AsyncSemaphore, AsyncSemaphoreError, AsyncSemaphoreExclusiveAllFuture,
    AsyncSemaphoreLeasesGuard, AsyncSemaphoreExclusiveAllGuard, AsyncSemaphoreLeasesFuture,
};
