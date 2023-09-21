extern crate alloc;
use crate::sync_types::{self, Lock as _};
use alloc::{collections, sync};
use core::{cell, future, marker, ops, pin, task};

#[derive(Debug)]
pub enum AsyncRwLockQueueEnqueueError {
    MemoryAllocationFailure,
}

struct AsyncRwLockQueueEntry {
    exclusive: bool,
    waker: Option<task::Waker>,
    waiter_id: u64,
}

struct AsyncRwLockQueue {
    queue: collections::VecDeque<AsyncRwLockQueueEntry>,

    granted_shared_locks: usize,
    granted_exclusive_lock: bool,

    next_waiter_id: u64,
}

impl AsyncRwLockQueue {
    fn new() -> Self {
        Self {
            queue: collections::VecDeque::new(),
            granted_shared_locks: 0,
            granted_exclusive_lock: false,
            next_waiter_id: 0,
        }
    }

    fn poll_waiter(&mut self, waiter_id: u64, waker: task::Waker) -> bool {
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

    fn cancel_waiter(&mut self, waiter_id: u64) {
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

    fn return_shared_grant(&mut self) {
        debug_assert_ne!(self.granted_shared_locks, 0);
        self.granted_shared_locks -= 1;
        if self.granted_shared_locks == 0 {
            self.wake_waiters();
        }
    }

    fn return_exclusive_grant(&mut self) {
        debug_assert!(self.granted_exclusive_lock);
        self.granted_exclusive_lock = false;
        self.wake_waiters();
    }

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

    fn try_enqueue(
        &mut self,
        exclusive: bool,
    ) -> Result<Option<u64>, AsyncRwLockQueueEnqueueError> {
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
            self.queue
                .try_reserve(1)
                .map_err(|_| AsyncRwLockQueueEnqueueError::MemoryAllocationFailure)?;
        }

        let waiter_id = self.next_waiter_id;
        self.next_waiter_id = self.next_waiter_id.wrapping_add(1);
        self.queue.push_back(AsyncRwLockQueueEntry {
            exclusive,
            waker: None,
            waiter_id,
        });
        Ok(Some(waiter_id))
    }
}

pub struct AsyncRwLock<ST: sync_types::SyncTypes, T> {
    queue: ST::Lock<AsyncRwLockQueue>,
    data: cell::UnsafeCell<T>,
}

// The very purpose of implementing a lock is getting Sync.
unsafe impl<ST: sync_types::SyncTypes, T> Sync for AsyncRwLock<ST, T> {}

impl<ST: sync_types::SyncTypes, T> AsyncRwLock<ST, T> {
    // TODO: return a Pin<Arc<...>>
    fn new(data: T) -> Self {
        Self {
            queue: ST::Lock::from(AsyncRwLockQueue::new()),
            data: cell::UnsafeCell::new(data),
        }
    }

    pub fn read(
        self: pin::Pin<sync::Arc<Self>>,
    ) -> Result<AsyncRwLockWaitReadLockFuture<ST, T>, AsyncRwLockQueueEnqueueError> {
        let mut queue = self.queue.lock();
        let waiter_id = queue.try_enqueue(false)?;
        drop(queue);
        let owns_grant = waiter_id.is_none();
        Ok(AsyncRwLockWaitReadLockFuture {
            inner: AsyncRwLockWaitLockFuture::<ST, T, false> {
                lock: WeakAsyncRwLockRef::new(self),
                waiter_id,
                owns_grant,
            },
        })
    }

    pub fn write(
        self: pin::Pin<sync::Arc<Self>>,
    ) -> Result<AsyncRwLockWaitWriteLockFuture<ST, T>, AsyncRwLockQueueEnqueueError> {
        let mut queue = self.queue.lock();
        let waiter_id = queue.try_enqueue(true)?;
        drop(queue);
        let owns_grant = waiter_id.is_none();
        Ok(AsyncRwLockWaitWriteLockFuture {
            inner: AsyncRwLockWaitLockFuture::<ST, T, true> {
                lock: WeakAsyncRwLockRef::new(self),
                waiter_id,
                owns_grant,
            },
        })
    }

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

struct WeakAsyncRwLockRef<ST: sync_types::SyncTypes, T> {
    weak_p: sync::Weak<AsyncRwLock<ST, T>>,
}

impl<ST: sync_types::SyncTypes, T> WeakAsyncRwLockRef<ST, T> {
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

    fn upgrade(&self) -> Option<pin::Pin<sync::Arc<AsyncRwLock<ST, T>>>> {
        self.weak_p.upgrade().map(|p| {
            // This is safe: self.weak_p originated from a pinned pointer.
            unsafe { pin::Pin::new_unchecked(p) }
        })
    }
}

#[derive(Debug)]
pub enum AsyncRwLockPollError {
    StaleAsyncRwLock,
    FutureCompleted,
}

struct AsyncRwLockWaitLockFuture<ST: sync_types::SyncTypes, T, const EXCL: bool> {
    lock: WeakAsyncRwLockRef<ST, T>,
    waiter_id: Option<u64>,
    owns_grant: bool,
}

impl<ST: sync_types::SyncTypes, T, const EXCL: bool> marker::Unpin
    for AsyncRwLockWaitLockFuture<ST, T, EXCL>
{
}

impl<ST: sync_types::SyncTypes, T, const EXCL: bool> future::Future
    for AsyncRwLockWaitLockFuture<ST, T, EXCL>
{
    type Output = Result<AsyncRwLockGuard<ST, T, EXCL>, AsyncRwLockPollError>;

    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let lock = match self.lock.upgrade() {
            Some(lock) => lock,
            None => {
                return task::Poll::Ready(Err(AsyncRwLockPollError::StaleAsyncRwLock));
            }
        };

        if self.owns_grant {
            debug_assert!(self.waiter_id.is_none());
            self.owns_grant = false;
            task::Poll::Ready(Ok(AsyncRwLockGuard { lock }))
        } else if let Some(waiter_id) = self.waiter_id {
            let mut queue = lock.queue.lock();
            if queue.poll_waiter(waiter_id, cx.waker().clone()) {
                drop(queue);
                self.waiter_id = None;
                task::Poll::Ready(Ok(AsyncRwLockGuard { lock }))
            } else {
                task::Poll::Pending
            }
        } else {
            task::Poll::Ready(Err(AsyncRwLockPollError::FutureCompleted))
        }
    }
}

impl<ST: sync_types::SyncTypes, T, const EXCL: bool> Drop
    for AsyncRwLockWaitLockFuture<ST, T, EXCL>
{
    fn drop(&mut self) {
        if self.owns_grant {
            debug_assert!(self.waiter_id.is_none());
            if let Some(lock) = self.lock.upgrade() {
                let mut queue = lock.queue.lock();
                if EXCL {
                    queue.return_exclusive_grant();
                } else {
                    queue.return_shared_grant();
                }
            }
        } else if let Some(waiter_id) = self.waiter_id {
            if let Some(lock) = self.lock.upgrade() {
                lock.queue.lock().cancel_waiter(waiter_id);
            }
        }
    }
}

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

pub struct AsyncRwLockWaitReadLockFuture<ST: sync_types::SyncTypes, T> {
    inner: AsyncRwLockWaitLockFuture<ST, T, false>,
}

impl<ST: sync_types::SyncTypes, T> marker::Unpin for AsyncRwLockWaitReadLockFuture<ST, T> {}

impl<ST: sync_types::SyncTypes, T> future::Future for AsyncRwLockWaitReadLockFuture<ST, T> {
    type Output = Result<AsyncRwLockReadGuard<ST, T>, AsyncRwLockPollError>;

    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        future::Future::poll(pin::Pin::new(&mut self.as_mut().inner), cx)
            .map(|result| result.map(|guard| AsyncRwLockReadGuard { guard }))
    }
}

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

pub struct AsyncRwLockWaitWriteLockFuture<ST: sync_types::SyncTypes, T> {
    inner: AsyncRwLockWaitLockFuture<ST, T, true>,
}

impl<ST: sync_types::SyncTypes, T> marker::Unpin for AsyncRwLockWaitWriteLockFuture<ST, T> {}

impl<ST: sync_types::SyncTypes, T> future::Future for AsyncRwLockWaitWriteLockFuture<ST, T> {
    type Output = Result<AsyncRwLockWriteGuard<ST, T>, AsyncRwLockPollError>;

    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        future::Future::poll(pin::Pin::new(&mut self.as_mut().inner), cx)
            .map(|result| result.map(|guard| AsyncRwLockWriteGuard { guard }))
    }
}

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
