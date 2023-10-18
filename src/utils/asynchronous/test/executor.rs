extern crate alloc;
use crate::sync_types::{self, Lock as _};
use alloc::{boxed, sync, vec};
use core::{cell, convert, future, marker, ops, pin, sync::atomic, task};

pub struct TestNopLock<T> {
    locked: atomic::AtomicBool,
    v: cell::UnsafeCell<T>,
}

impl<T> convert::From<T> for TestNopLock<T> {
    fn from(value: T) -> Self {
        Self {
            locked: atomic::AtomicBool::new(false),
            v: cell::UnsafeCell::new(value),
        }
    }
}

unsafe impl<T> marker::Send for TestNopLock<T> {}
unsafe impl<T> marker::Sync for TestNopLock<T> {}

impl<T> sync_types::Lock<T> for TestNopLock<T> {
    type Guard<'a> = TestNopLockGuard<'a, T> where Self: 'a;

    fn lock(&self) -> Self::Guard<'_> {
        assert_eq!(
            self.locked.compare_exchange(
                false,
                true,
                atomic::Ordering::Acquire,
                atomic::Ordering::Relaxed
            ),
            Ok(false),
            "Testing TestNopLocks are not expected to ever be contended."
        );
        TestNopLockGuard { lock: self }
    }
}

pub struct TestNopLockGuard<'a, T> {
    lock: &'a TestNopLock<T>,
}

impl<'a, T> Drop for TestNopLockGuard<'a, T> {
    fn drop(&mut self) {
        assert_eq!(
            self.lock.locked.compare_exchange(
                true,
                false,
                atomic::Ordering::Acquire,
                atomic::Ordering::Relaxed
            ),
            Ok(true),
            "Testing TestNopLock with active lock guard found unlocked."
        );
    }
}

impl<'a, T> ops::Deref for TestNopLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a Lock is exclusive access, so no aliasing.
        unsafe { &*p }
    }
}

impl<'a, T> ops::DerefMut for TestNopLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a Lock is exclusive access, so no aliasing.
        unsafe { &mut *p }
    }
}

pub struct TestNopRwLock<T> {
    locked: atomic::AtomicIsize,
    v: cell::UnsafeCell<T>,
}

impl<T> convert::From<T> for TestNopRwLock<T> {
    fn from(value: T) -> Self {
        Self {
            locked: atomic::AtomicIsize::new(0),
            v: cell::UnsafeCell::new(value),
        }
    }
}

unsafe impl<T> marker::Send for TestNopRwLock<T> {}
unsafe impl<T> marker::Sync for TestNopRwLock<T> {}

impl<T> sync_types::RwLock<T> for TestNopRwLock<T> {
    type ReadGuard<'a> = TestNopRwLockReadGuard<'a, T> where Self: 'a;
    type WriteGuard<'a>  = TestNopRwLockWriteGuard<'a, T> where Self: 'a;

    fn read(&self) -> Self::ReadGuard<'_> {
        assert!(
            self.locked.fetch_add(1, atomic::Ordering::Acquire) >= 0,
            "Testing TestNopRwLocks are not expected to ever be contended."
        );
        TestNopRwLockReadGuard { lock: self }
    }

    fn write(&self) -> Self::WriteGuard<'_> {
        assert_eq!(
            self.locked.fetch_sub(1, atomic::Ordering::Acquire),
            0,
            "Testing TestNopRwLocks are not expected to ever be contended."
        );
        TestNopRwLockWriteGuard { lock: self }
    }
}

pub struct TestNopRwLockReadGuard<'a, T> {
    lock: &'a TestNopRwLock<T>,
}

impl<'a, T> Drop for TestNopRwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        assert!(
            self.lock.locked.fetch_sub(1, atomic::Ordering::Release) > 0,
            "Testing TestNopRwLock with active read guard found unlocked or write locked."
        );
    }
}

impl<'a, T> ops::Deref for TestNopRwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a RwLock is exclusive Writers, so no
        // aliasing with mutable references.
        unsafe { &*p }
    }
}

pub struct TestNopRwLockWriteGuard<'a, T> {
    lock: &'a TestNopRwLock<T>,
}

impl<'a, T> Drop for TestNopRwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        assert_eq!(
            self.lock.locked.fetch_add(1, atomic::Ordering::Release),
            -1,
            "Testing TestNopRwLock with active lock write guard found unlocked or read locked."
        );
    }
}

impl<'a, T> ops::Deref for TestNopRwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a RwLock is exclusive Writers, so no
        // aliasing with mutable references.
        unsafe { &*p }
    }
}

impl<'a, T> ops::DerefMut for TestNopRwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a RwLock is exclusive Writers, so no
        // aliasing with mutable references.
        unsafe { &mut *p }
    }
}

pub struct TestNopSyncTypes {}

impl sync_types::SyncTypes for TestNopSyncTypes {
    type Lock<T> = TestNopLock<T>;
    type RwLock<T> = TestNopRwLock<T>;
}




trait QueuedTaskDispatch {
    fn poll_pinned(&mut self, cx: &mut task::Context<'_>) -> bool;
}

struct QueuedTask<F: future::Future + Send>
where
    F::Output: Send + 'static,
{
    f: F,
    result: sync::Arc<TestNopLock<Option<F::Output>>>,
}

impl<F: future::Future + Send> QueuedTaskDispatch for QueuedTask<F>
where
    F::Output: Send + 'static,
{
    fn poll_pinned(&mut self, cx: &mut task::Context<'_>) -> bool {
        // Safety: always called with actually pinned &mut self, as part of the
        // contract.
        let f = unsafe { pin::Pin::new_unchecked(&mut self.f) };
        match future::Future::poll(f, cx) {
            task::Poll::Ready(result) => {
                *self.result.lock() = Some(result);
                true
            }
            task::Poll::Pending => false,
        }
    }
}

enum TaskStatus {
    Blocked,
    Runnable,
}

struct TaskQueueEntry {
    id: u64,
    status: TaskStatus,
    task: Option<pin::Pin<boxed::Box<dyn QueuedTaskDispatch>>>,
    waiter_waker: Option<task::Waker>,
}

struct Waker {
    task_id: u64,
    executor: sync::Arc<TestAsyncExecutor>,
}

impl alloc::task::Wake for Waker {
    fn wake(self: sync::Arc<Self>) {
        let executor = self.executor.as_ref();
        let mut tasks = executor.tasks.lock();
        for t in tasks.iter_mut() {
            if t.id == self.task_id && matches!(t.status, TaskStatus::Blocked) {
                t.status = TaskStatus::Runnable
            }
        }
    }
}

enum TaskWaiterState<T> {
    Pending {
        executor: sync::Arc<TestAsyncExecutor>,
        task_id: u64,
        result: sync::Arc<TestNopLock<Option<T>>>,
    },
    Done,
}

pub struct TaskWaiter<T> {
    state: TaskWaiterState<T>,
}

impl<T> TaskWaiter<T> {
    pub fn take(mut self) -> Option<T> {
        match &mut self.state {
            TaskWaiterState::Pending {
                executor: _,
                task_id: _,
                result,
            } => {
                let result = result.lock().take();
                self.state = TaskWaiterState::Done;
                result
            }
            TaskWaiterState::Done => None,
        }
    }
}

impl<T> Drop for TaskWaiter<T> {
    fn drop(&mut self) {
        match &self.state {
            TaskWaiterState::Pending {
                executor,
                task_id,
                result,
            } => {
                if !result.lock().is_some() {
                    executor.as_ref().remove_task(*task_id);
                }
            }
            TaskWaiterState::Done => (),
        }
    }
}

impl<T> Unpin for TaskWaiter<T> {}

impl<T> future::Future for TaskWaiter<T> {
    type Output = T;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.get_mut();
        match &this.state {
            TaskWaiterState::Pending {
                executor,
                task_id,
                result,
            } => {
                let mut locked_result = result.lock();
                if let Some(result) = locked_result.take() {
                    drop(locked_result);
                    this.state = TaskWaiterState::Done;
                    task::Poll::Ready(result)
                } else {
                    let mut tasks = executor.tasks.lock();
                    let task = tasks.iter_mut().find(|task| task.id == *task_id).unwrap();
                    task.waiter_waker = Some(cx.waker().clone());
                    task::Poll::Pending
                }
            }
            TaskWaiterState::Done => unreachable!(),
        }
    }
}

pub struct TestAsyncExecutor {
    tasks: TestNopLock<vec::Vec<TaskQueueEntry>>,
    next_id: atomic::AtomicU64,
}

impl TestAsyncExecutor {
    pub fn new() -> sync::Arc<Self> {
        sync::Arc::new(Self {
            tasks: TestNopLock::from(vec::Vec::new()),
            next_id: atomic::AtomicU64::new(0),
        })
    }

    pub fn spawn<F: future::Future + Send + 'static>(
        self: &sync::Arc<Self>,
        f: F,
    ) -> TaskWaiter<F::Output>
    where
        F::Output: Send + 'static,
    {
        let id = self.next_id.fetch_add(1, atomic::Ordering::Relaxed);

        let result = sync::Arc::new(TestNopLock::from(None));
        let waiter = TaskWaiter {
            state: TaskWaiterState::Pending {
                executor: self.clone(),
                task_id: id,
                result: result.clone(),
            },
        };

        let mut tasks = self.tasks.lock();
        let task = boxed::Box::pin(QueuedTask { f, result })
            as pin::Pin<boxed::Box<dyn QueuedTaskDispatch>>;
        tasks.push(TaskQueueEntry {
            id,
            status: TaskStatus::Runnable,
            task: Some(task),
            waiter_waker: None,
        });

        waiter
    }

    fn remove_task(&self, id: u64) {
        let mut tasks = self.tasks.lock();
        if let Some(index) = tasks.iter().position(|task| task.id == id) {
            // Removing/Dropping the task might drop further TaskWaiter instances held by
            // that task, which would in turn invoke this function and try to
            // get self.tasks for writing.
            let entry = tasks.remove(index);
            drop(tasks);
            drop(entry);
        };
    }

    pub fn run_to_completion(self: &sync::Arc<Self>) {
        let mut last_polled: Option<(usize, u64)> = None;
        loop {
            let mut tasks = self.tasks.lock();
            if tasks.is_empty() {
                break;
            }

            // Determine the next task to examine: either the one with the next larger task
            // id, if any, or wrap around to the beginning.
            let mut search_begin = match last_polled {
                Some((last_index, last_task_id)) => {
                    // The saved index is ont an approximate hint, because self.tasks might have
                    // changed when its lock was released. Search downwards for
                    // the last entry before index with a task id <= the last
                    // one, and search upward from there for the one with the next higher id.
                    let last_index = last_index.min(tasks.len());
                    let last_before_leq = tasks[..last_index]
                        .iter()
                        .rposition(|entry| entry.id <= last_task_id)
                        .unwrap_or(0);
                    match tasks
                        .iter()
                        .enumerate()
                        .skip(last_before_leq)
                        .find(|(_, entry)| entry.id > last_task_id)
                    {
                        Some((index, _)) => index,
                        None => {
                            // No task with a higher id than the last one. Wrap around.
                            0
                        }
                    }
                }
                None => 0,
            };
            let index = loop {
                match tasks
                    .iter()
                    .enumerate()
                    .skip(search_begin)
                    .find(|(_, entry)| matches!(entry.status, TaskStatus::Runnable))
                {
                    Some((index, _)) => break Some(index),
                    None => {
                        // Wrap around if the search hasn't started from the beginning already.
                        if search_begin == 0 {
                            break None;
                        }
                        search_begin = 0;
                    }
                }
            };
            let index = index.expect("TestAsyncExecutor stuck with no runnable task.");

            let entry = &mut tasks[index];
            let task_id = entry.id;
            last_polled = Some((index, task_id));
            // Temporarily steal the QueueTask for invoking it below with self.tasks[]
            // unlocked.
            let mut task = match entry.task.take() {
                Some(task) => task,
                None => {
                    continue;
                }
            };
            // Set the status to blocked now, so that any wake-ups from wakers
            // won't get missed.
            entry.status = TaskStatus::Blocked;
            // Drop the tasks lock for the duration of polling the task --
            // it might want to spawn more tasks or drop some TaskWaiters.
            drop(tasks);

            let waker = task::Waker::from(sync::Arc::new(Waker {
                task_id,
                executor: self.clone(),
            }));
            let mut cx = task::Context::from_waker(&waker);
            // Safety: poll_pinned() immediately repins it.
            let done = unsafe { task.as_mut().get_unchecked_mut() }.poll_pinned(&mut cx);

            let task = if done {
                // Dropping the task might drop further TaskWaiter instances held by
                // that task, which would invoke Self::remove_task() and try to
                // get self.tasks for writing. Do it here outside the self.tasks lock.
                drop(task);
                None
            } else {
                Some(task)
            };

            let mut tasks = self.tasks.lock();
            // While the lock had been released, self.tasks[] could potentially have
            // been mutated. Find the index corresponding to the task_id saved away above.
            let updated_index = if index < tasks.len() && tasks[index].id == task_id {
                // Position is unchanged.
                index
            } else {
                match tasks.iter().position(|entry| entry.id == task_id) {
                    Some(updated_index) => updated_index,
                    None => {
                        // The task has gone, presumably because its associated TaskWaiter had
                        // been dropped.
                        continue;
                    }
                }
            };
            last_polled = Some((updated_index, task_id));

            if done {
                let waiter_waker = tasks[updated_index].waiter_waker.take();
                tasks.remove(updated_index);
                if let Some(waiter_waker) = waiter_waker {
                    drop(tasks);
                    waiter_waker.wake();
                }
            } else {
                let entry = &mut tasks[updated_index];
                // Restore the pointer to the QueuedTask, which had temporarily
                // been taken before the poll() invocation above.
                entry.task = task;
            }
        }
    }
}

#[test]
fn test_test_async_executor_simple() {
    struct SimpleTask {}

    impl future::Future for SimpleTask {
        type Output = u32;

        fn poll(
            self: pin::Pin<&mut Self>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            task::Poll::Ready(42)
        }
    }

    let executor = TestAsyncExecutor::new();
    let waiter = executor.spawn(SimpleTask {});
    executor.run_to_completion();
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync::Arc::strong_count(&executor), 1);
    assert_eq!(sync::Arc::weak_count(&executor), 0);

    let waiter = executor.spawn(async { async { 42 }.await });
    executor.run_to_completion();
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync::Arc::strong_count(&executor), 1);
    assert_eq!(sync::Arc::weak_count(&executor), 0);
}

#[test]
fn test_test_async_executor_chained_waiters() {
    struct SimpleTask {}

    impl future::Future for SimpleTask {
        type Output = u32;

        fn poll(
            self: pin::Pin<&mut Self>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            task::Poll::Ready(42)
        }
    }

    let executor = TestAsyncExecutor::new();
    let waiter = executor.spawn(SimpleTask {});
    let waiter = executor.spawn(waiter);
    let waiter = executor.spawn(waiter);
    executor.run_to_completion();
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync::Arc::strong_count(&executor), 1);
    assert_eq!(sync::Arc::weak_count(&executor), 0);
}

#[test]
fn test_test_async_executor_recursive_spawning() {
    use ops::DerefMut as _;

    enum SpawningTask {
        Init {
            executor: sync::Arc<TestAsyncExecutor>,
            n: u32,
        },
        WaitingForSpawn {
            waiter: TaskWaiter<u32>,
        },
    }

    impl Unpin for SpawningTask {}

    impl future::Future for SpawningTask {
        type Output = u32;

        fn poll(
            mut self: pin::Pin<&mut Self>,
            cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            match self.deref_mut() {
                Self::Init { executor, n } => {
                    if *n == 0 {
                        task::Poll::Ready(0)
                    } else {
                        let mut waiter = executor.spawn(SpawningTask::Init {
                            executor: executor.clone(),
                            n: *n - 1,
                        });
                        match future::Future::poll(pin::Pin::new(&mut waiter), cx) {
                            task::Poll::Ready(_) => {
                                // The task associated with the waiter did not have a chance to run
                                // yet.
                                unreachable!();
                            }
                            task::Poll::Pending => {
                                *self.deref_mut() = Self::WaitingForSpawn { waiter };
                                task::Poll::Pending
                            }
                        }
                    }
                }
                Self::WaitingForSpawn { waiter } => {
                    match future::Future::poll(pin::Pin::new(waiter), cx) {
                        task::Poll::Ready(n) => task::Poll::Ready(n + 1),
                        task::Poll::Pending => {
                            // This future's task should have been woken only once
                            // the waiter has become ready.
                            unreachable!();
                        }
                    }
                }
            }
        }
    }

    let executor = TestAsyncExecutor::new();
    let waiter = executor.spawn(SpawningTask::Init {
        executor: executor.clone(),
        n: 42,
    });
    executor.run_to_completion();
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync::Arc::strong_count(&executor), 1);
    assert_eq!(sync::Arc::weak_count(&executor), 0);
}

#[test]
fn test_test_async_executor_wake_self() {
    use ops::Deref as _;

    enum SelfWakingTask {
        Unpolled,
        PolledOnce,
    }

    impl Unpin for SelfWakingTask {}

    impl future::Future for SelfWakingTask {
        type Output = u32;

        fn poll(
            mut self: pin::Pin<&mut Self>,
            cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            match self.deref() {
                Self::Unpolled => {
                    cx.waker().wake_by_ref();
                    *self = Self::PolledOnce;
                    task::Poll::Pending
                }
                Self::PolledOnce => task::Poll::Ready(42),
            }
        }
    }

    let executor = TestAsyncExecutor::new();
    let waiter = executor.spawn(SelfWakingTask::Unpolled);
    let waiter = executor.spawn(waiter);
    executor.run_to_completion();
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync::Arc::strong_count(&executor), 1);
    assert_eq!(sync::Arc::weak_count(&executor), 0);
}
