use std::sync::Arc;
use lightning_background_processor::Persister;
use lightning_persister::FilesystemPersister;
use vls_protocol_client::DynSigner;
use crate::{ArcChainMonitor, BitcoindClient, ChannelManager, DynKeysInterface, LoggerAdapter, NetworkGraph};

pub(crate) struct DataPersister {
    pub(crate) data_dir: String,
}

impl Persister<
    DynSigner,
    Arc<ArcChainMonitor>,
    Arc<BitcoindClient>,
    Arc<DynKeysInterface>,
    Arc<BitcoindClient>,
    Arc<LoggerAdapter>,
> for DataPersister
{
    fn persist_manager(&self, channel_manager: &ChannelManager) -> Result<(), std::io::Error> {
        FilesystemPersister::persist_manager(self.data_dir.clone(), channel_manager)
    }

    fn persist_graph(&self, network_graph: &NetworkGraph) -> Result<(), std::io::Error> {
        if FilesystemPersister::persist_network_graph(self.data_dir.clone(), network_graph).is_err()
        {
            // Persistence errors here are non-fatal as we can just fetch the routing graph
            // again later, but they may indicate a disk error which could be fatal elsewhere.
            eprintln!("Warning: Failed to persist network graph, check your disk and permissions");
        }

        Ok(())
    }
}

