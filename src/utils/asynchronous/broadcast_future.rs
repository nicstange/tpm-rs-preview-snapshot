//! Implementation of [`BroadcastFuture`].

extern crate alloc;
use crate::interface;
use crate::sync_types::{self, Lock as _};
use crate::utils;
use alloc::{sync, vec};
use core::{future, marker, num, ops, pin, task};
use ops::DerefMut as _;

/// Internal representation of a subscription to a [`BroadcastFuture`].
struct BroadcastFutureSubscriptionEntry {
    /// The last waker the entry's associated [`BroadcastFutureSubscription`]
    /// had been polled with.
    waker: Option<task::Waker>,
    /// Unique id allocated to the subscription entry.
    id: num::NonZeroU64,
}

/// Internal state of a [`BroadcastFuture`].
enum BroadcastFutureSharedState<F: future::Future>
where
    F::Output: Clone,
{
    Pending {
        /// The inner future to get collectively polled for.
        inner: F,

        /// The last [`BroadcastFutureSubscription`]'s id that polled and whose
        /// waker is installed at the inner future.
        registered_at_inner: Option<num::NonZeroU64>,

        /// Last id allocated to some subscription.
        last_subscription_id: u64,

        /// List of all subscriptions. Each entry is associated with
        /// exactly one [`BroadcastFutureSubscription`] instance.
        subscriptions: vec::Vec<BroadcastFutureSubscriptionEntry>,
    },

    Ready(F::Output),
}

/// Internal result of subscribing to a [`BroadcastFuture`].
enum BroadcastFutureSharedStateTrySubscribeResult<T> {
    /// The wrapped future is still pending and a subscription has
    /// indeed be registered internally.
    Pending { subscription_id: num::NonZeroU64 },
    /// The wrapped future had been completed already by the time the
    /// subscription attempt was made.
    Ready(T),
}

impl<F: future::Future> BroadcastFutureSharedState<F>
where
    F::Output: Clone + marker::Send,
{
    /// Default initialization of a [`BroadcastFutureSharedState`] instance.
    fn new(inner: F) -> Self {
        Self::Pending {
            inner,
            registered_at_inner: None,
            last_subscription_id: 0,
            subscriptions: vec::Vec::new(),
        }
    }

    /// Register a new [`BroadcastFuture`] subscription with its internal state.
    ///
    /// Either of the two variants of the
    /// [`BroadcastFutureSharedStateTrySubscribeResult`] `enum`
    /// will get returned, depending on whether or not the wrapped future had
    /// been previously completed by the time of the subscription attempt.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    fn try_subscribe(
        &mut self,
    ) -> Result<BroadcastFutureSharedStateTrySubscribeResult<F::Output>, interface::TpmErr> {
        match self {
            Self::Pending {
                inner: _,
                registered_at_inner: _,
                last_subscription_id,
                subscriptions,
            } => {
                if subscriptions.capacity() <= subscriptions.len() {
                    subscriptions
                        .try_reserve(1)
                        .map_err(|_| tpm_err_rc!(MEMORY))?;
                }

                *last_subscription_id += 1;
                let id = num::NonZeroU64::new(*last_subscription_id).unwrap();
                subscriptions.push(BroadcastFutureSubscriptionEntry { waker: None, id });
                Ok(BroadcastFutureSharedStateTrySubscribeResult::Pending {
                    subscription_id: id,
                })
            }
            Self::Ready(result) => Ok(BroadcastFutureSharedStateTrySubscribeResult::Ready(
                result.clone(),
            )),
        }
    }

    /// Deregister a [`BroadcastFuture`] subscription from its internal state.
    fn unsubscribe(&mut self, subscription_id: num::NonZeroU64) {
        match self {
            Self::Pending {
                inner: _,
                registered_at_inner,
                last_subscription_id: _,
                subscriptions,
            } => {
                let index = subscriptions
                    .iter()
                    .position(|entry| entry.id == subscription_id)
                    .unwrap();
                subscriptions.remove(index);
                if let Some(registered_at_inner_id) = registered_at_inner {
                    if *registered_at_inner_id == subscription_id {
                        *registered_at_inner = None;
                        if let Some(take_over_subscription) = subscriptions.first() {
                            // The subscription to take over has *not* installed its waker at the
                            // inner future yet. However, if this subscription is to get dropped as
                            // well, it needs to pass the stick along.
                            *registered_at_inner = Some(take_over_subscription.id);
                            if let Some(waker) = &take_over_subscription.waker {
                                // Wake some other subscription so that it will poll the inner
                                // future and install its waker there in the course.
                                waker.wake_by_ref();
                            }
                        }
                    }
                }
            }
            Self::Ready(_) => (),
        }
    }

    /// Poll the wrapped future on behalf of a registered
    /// [`BroadcastFutureSubscription`] future.
    ///
    /// If the wrapped future had been completed already, its result will get
    /// returned. Otherwise a poll on the wrapped future will get conducted
    /// and its result returned.
    fn poll_from_subscription(
        self: pin::Pin<&mut Self>,
        subscription_id: num::NonZeroU64,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<F::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            Self::Pending {
                inner,
                registered_at_inner,
                last_subscription_id: _,
                subscriptions,
            } => {
                // Only subscriptions created after the inner future has completed won't
                // get an id assigned.
                let waker = cx.waker().clone();
                // This is safe, it's just a structural pinning for future down from the pinned
                // self.
                let f = unsafe { pin::Pin::new_unchecked(inner) };
                match future::Future::poll(f, cx) {
                    task::Poll::Pending => {
                        let subscription_entry = subscriptions
                            .iter_mut()
                            .find(|entry| entry.id == subscription_id)
                            .unwrap();
                        subscription_entry.waker = Some(waker);
                        *registered_at_inner = Some(subscription_id);
                        task::Poll::Pending
                    }
                    task::Poll::Ready(result) => {
                        // Wake all the other subscriptions
                        for s in subscriptions.iter_mut() {
                            if s.id == subscription_id {
                                continue;
                            }
                            if let Some(waker) = s.waker.take() {
                                waker.wake();
                            }
                        }
                        *this = Self::Ready(result.clone());
                        task::Poll::Ready(result)
                    }
                }
            }
            Self::Ready(result) => task::Poll::Ready(result.clone()),
        }
    }
}

/// Future wrapper enabling collective polling on the wrapped
/// [`Future`](future::Future).
///
/// A [`BroadcastFuture`] wraps a given inner [`Future`](future::Future) and
/// allows for collective polling from one or more subscribers instantiated via
/// [`subscribe()`](Self::subscribe).
///
/// Once the inner future completes, the result will be made available
/// ("broadcasted") to all subscribers upon their respective next `poll()`
/// invocation, if any.
pub struct BroadcastFuture<ST: sync_types::SyncTypes, F: future::Future>
where
    F::Output: Clone + marker::Send,
{
    shared: ST::Lock<BroadcastFutureSharedState<F>>,
}

impl<ST: sync_types::SyncTypes, F: future::Future> BroadcastFuture<ST, F>
where
    F::Output: Clone + marker::Send,
{
    /// Wrap a given [`Future`](future::Future) in a [`BroadcastFuture`].
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn new(inner: F) -> Result<pin::Pin<sync::Arc<Self>>, interface::TpmErr> {
        let this = utils::arc_try_new(Self {
            shared: ST::Lock::from(BroadcastFutureSharedState::new(inner)),
        })?;
        Ok(unsafe { pin::Pin::new_unchecked(this) })
    }

    /// Subscribe to the given [`BroadcastFuture`] instance.
    ///
    /// On success, a [`BroadcastFutureSubscription`] [`Future`](future::Future)
    /// will get returned, which can then subsequently get polled to drive
    /// progress on the wrapped future forward and to eventually obtain the
    /// broadcasted result.
    ///
    /// # Errors:
    ///
    /// * [`TpmRc::MEMORY`](interface::TpmRc::MEMORY) - Memory allocation
    ///   failure.
    pub fn subscribe(
        self: &pin::Pin<sync::Arc<Self>>,
    ) -> Result<BroadcastFutureSubscription<ST, F>, interface::TpmErr> {
        let mut shared = self.shared.lock();
        match shared.try_subscribe()? {
            BroadcastFutureSharedStateTrySubscribeResult::Pending { subscription_id } => {
                Ok(BroadcastFutureSubscription::Pending {
                    id: subscription_id,
                    broadcast_future: self.clone(),
                })
            }
            BroadcastFutureSharedStateTrySubscribeResult::Ready(result) => {
                Ok(BroadcastFutureSubscription::Ready(Some(result)))
            }
        }
    }
}

/// Subscription to a [`BroadcastFuture`].
///
/// [`BroadcastFutureSubscription`], instantiated through
/// [`BroadcastFuture::subscribe()`], implements [`Future`](future::Future)
/// itself and is to be used to poll on the wrapped future and to eventually
/// obtain its result once completed.
///
/// It should be obvious, but it is explictly permitted to concurrently poll on
/// the same [`BroadcastFuture`] instance from multiple associated
/// subscriptions.
///
/// The wrapped future can only make progress upon polling on the subscriptions.
/// Once the inner future conducts a wakeup, it is guaranteed to get relayed to
/// at least one of the registered subscribers, if any.
pub enum BroadcastFutureSubscription<ST: sync_types::SyncTypes, F: future::Future>
where
    F::Output: Clone + marker::Send,
{
    Pending {
        id: num::NonZeroU64,
        broadcast_future: pin::Pin<sync::Arc<BroadcastFuture<ST, F>>>,
    },
    Ready(Option<F::Output>),
}

impl<ST: sync_types::SyncTypes, F: future::Future> future::Future
    for BroadcastFutureSubscription<ST, F>
where
    F::Output: Clone + marker::Send,
{
    type Output = F::Output;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.get_mut();
        match this {
            BroadcastFutureSubscription::Pending {
                id,
                broadcast_future,
            } => {
                let mut locked_shared = broadcast_future.shared.lock();
                // broadcast_future is pinned, and so is the content wrapped in its lock.
                let shared = unsafe { pin::Pin::new_unchecked(locked_shared.deref_mut()) };
                match BroadcastFutureSharedState::poll_from_subscription(shared, *id, cx) {
                    task::Poll::Pending => task::Poll::Pending,
                    task::Poll::Ready(result) => {
                        drop(locked_shared);
                        *this = Self::Ready(None);
                        task::Poll::Ready(result)
                    }
                }
            }
            BroadcastFutureSubscription::Ready(result) => task::Poll::Ready(result.take().unwrap()),
        }
    }
}

impl<ST: sync_types::SyncTypes, F: future::Future> Drop for BroadcastFutureSubscription<ST, F>
where
    F::Output: Clone + marker::Send,
{
    fn drop(&mut self) {
        match self {
            BroadcastFutureSubscription::Pending {
                id,
                broadcast_future,
            } => {
                broadcast_future.shared.lock().unsubscribe(*id);
            }
            BroadcastFutureSubscription::Ready(_) => (),
        }
    }
}

impl<ST: sync_types::SyncTypes, F: future::Future> marker::Unpin
    for BroadcastFutureSubscription<ST, F>
where
    F::Output: Clone + marker::Send,
{
}
