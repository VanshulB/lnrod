//! Utilities that take care of tasks that (1) need to happen periodically to keep Rust-Lightning
//! running properly, and (2) either can or should be run in the background. See docs for
//! [`BackgroundProcessor`] for more details on the nitty-gritty.

#![deny(missing_docs)]
#![deny(unsafe_code)]

use log::trace;

use anyhow::Result;
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::keysinterface::{KeysInterface, Sign};
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::msgs::{ChannelMessageHandler, RoutingMessageHandler};
use lightning::ln::peer_handler::{PeerManager, SocketDescriptor};
use lightning::util::logger::Logger;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task;
use tokio::task::JoinHandle;

/// BackgroundProcessor takes care of tasks that (1) need to happen periodically to keep
/// Rust-Lightning running properly, and (2) either can or should be run in the background. Its
/// responsibilities are:
/// * Monitoring whether the ChannelManager needs to be re-persisted to disk, and if so,
///   writing it to disk/backups by invoking the callback given to it at startup.
///   ChannelManager persistence should be done in the background.
/// * Calling `ChannelManager::timer_tick_occurred()` and
///   `PeerManager::timer_tick_occurred()` every minute (can be done in the
///   background).
///
/// Note that if ChannelManager persistence fails and the persisted manager becomes out-of-date,
/// then there is a risk of channels force-closing on startup when the manager realizes it's
/// outdated. However, as long as `ChannelMonitor` backups are sound, no funds besides those used
/// for unilateral chain closure fees are at risk.
pub struct BackgroundProcessor {
	stop_thread: Arc<AtomicBool>,
	/// May be used to retrieve and handle the error if `BackgroundProcessor`'s thread
	/// exits due to an error while persisting.
	pub thread_handle: JoinHandle<Result<(), std::io::Error>>,
}

#[cfg(not(test))]
const FRESHNESS_TIMER: u64 = 60;
#[cfg(test)]
const FRESHNESS_TIMER: u64 = 1;

impl BackgroundProcessor {
	/// Start a background thread that takes care of responsibilities enumerated in the top-level
	/// documentation.
	///
	/// If `persist_manager` returns an error, then this thread will return said error (and
	/// `start()` will need to be called again to restart the `BackgroundProcessor`). Users should
	/// wait on [`thread_handle`]'s `join()` method to be able to tell if and when an error is
	/// returned, or implement `persist_manager` such that an error is never returned to the
	/// `BackgroundProcessor`
	///
	/// `persist_manager` is responsible for writing out the [`ChannelManager`] to disk, and/or
	/// uploading to one or more backup services. See [`ChannelManager::write`] for writing out a
	/// [`ChannelManager`]. See [`FilesystemPersister::persist_manager`] for Rust-Lightning's
	/// provided implementation.
	///
	/// [`thread_handle`]: BackgroundProcessor::thread_handle
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	/// [`ChannelManager::write`]: lightning::ln::channelmanager::ChannelManager#impl-Writeable
	/// [`FilesystemPersister::persist_manager`]: lightning_persister::FilesystemPersister::persist_manager
	pub async fn start<
		PM,
		Signer,
		M,
		T,
		K,
		F,
		L,
		Descriptor: 'static + SocketDescriptor + Send,
		CM,
		RM,
	>(
		persist_channel_manager: PM,
		channel_manager: Arc<ChannelManager<Signer, Arc<M>, Arc<T>, Arc<K>, Arc<F>, Arc<L>>>,
		peer_manager: Arc<PeerManager<Descriptor, Arc<CM>, Arc<RM>, Arc<L>>>,
	) -> Self
	where
		Signer: 'static + Sign + Send + Sync,
		M: 'static + chain::Watch<Signer> + Send + Sync,
		T: 'static + BroadcasterInterface + Send + Sync,
		K: 'static + KeysInterface<Signer = Signer> + Send + Sync,
		F: 'static + FeeEstimator + Send + Sync,
		L: 'static + Logger + Send + Sync,
		CM: 'static + ChannelMessageHandler + Send + Sync,
		RM: 'static + RoutingMessageHandler + Send + Sync,
		PM: 'static
			+ Send
			+ Fn(
				&ChannelManager<Signer, Arc<M>, Arc<T>, Arc<K>, Arc<F>, Arc<L>>,
			) -> Result<(), std::io::Error>,
	{
		let stop_thread = Arc::new(AtomicBool::new(false));
		let stop_thread_clone = stop_thread.clone();
		let handle = tokio::spawn(async move {
			let mut current_time = Instant::now();
			loop {
				peer_manager.process_events();
				let channel_manager_for_await = Arc::clone(&channel_manager);
				let updates_available = task::spawn_blocking(move || {
					channel_manager_for_await
						.await_persistable_update_timeout(Duration::from_millis(100))
				})
				.await
				.unwrap();
				if updates_available {
					persist_channel_manager(&*channel_manager)?;
				}
				// Exit the loop if the background processor was requested to stop.
				if stop_thread.load(Ordering::Acquire) == true {
					trace!("Terminating background processor.");
					return Ok(());
				}
				if current_time.elapsed().as_secs() > FRESHNESS_TIMER {
					trace!("Calling ChannelManager's and PeerManager's timer_tick_occurred");
					channel_manager.timer_tick_occurred();
					peer_manager.timer_tick_occurred();
					current_time = Instant::now();
				}
			}
		});
		Self { stop_thread: stop_thread_clone, thread_handle: handle }
	}

	/// Stop `BackgroundProcessor`'s task.
	pub async fn stop(self) -> Result<(), std::io::Error> {
		self.stop_thread.store(true, Ordering::Release);
		self.thread_handle.await.unwrap()
	}
}
