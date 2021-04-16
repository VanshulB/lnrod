use tonic::{Request, Response, Status, transport::Server};

use super::admin_api::{PingReply, PingRequest, Void, NodeInfoReply, ChannelListReply};
use super::admin_api::admin_server::{Admin, AdminServer};
use crate::cli::LdkUserInfo;
use crate::node::{build_node, Node, connect_peer_if_necessary};
use lightning::chain::keysinterface::KeysInterface;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use std::net::{SocketAddr, IpAddr, Ipv6Addr};
use crate::admin::admin_api::{Channel, ChannelNewRequest, ChannelNewReply};
use lightning::util::config::UserConfig;

struct AdminHandler {
    node: Node
}

impl AdminHandler {
    pub fn new(node: Node) -> Self {
        AdminHandler { node }
    }
}

#[tonic::async_trait]
impl Admin for AdminHandler {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let req = request.into_inner();
        let reply = PingReply {
            // We must use .into_inner() as the fields of gRPC requests and responses are private
            message: format!("Hello {}!", req.message),
        };
        Ok(Response::new(reply))
    }

    async fn node_info(&self, _request: Request<Void>) -> Result<Response<NodeInfoReply>, Status> {
        let node_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &self.node.keys_manager.get_node_secret());
        let reply = NodeInfoReply {
            node_id: node_pubkey.serialize().to_vec()
        };
        Ok(Response::new(reply))
    }

    async fn channel_list(&self, _request: Request<Void>) -> Result<Response<ChannelListReply>, Status> {
        let mut channels = Vec::new();
        for details in self.node.channel_manager.list_channels() {
            let channel = Channel {
                peer_node_id: details.remote_network_id.serialize().to_vec(),
                channel_id: details.channel_id.to_vec(),
                is_pending: details.short_channel_id.is_none(),
                value_sat: details.channel_value_satoshis,
                is_active: details.is_live,
                outbound_msat: details.outbound_capacity_msat
            };
            channels.push(channel);
        }
        let reply = ChannelListReply {
            channels
        };
        Ok(Response::new(reply))
    }

    async fn channel_new(&self, request: Request<ChannelNewRequest>) -> Result<Response<ChannelNewReply>, Status> {
        let req = request.into_inner();
        let peer_addr = req.address.parse().map_err(|_| Status::invalid_argument("address parse"))?;
        let node_id = PublicKey::from_slice(req.node_id.as_slice())
            .map_err(|_| Status::invalid_argument("failed to parse node_id"))?;
        connect_peer_if_necessary(
            node_id,
            peer_addr,
            self.node.peer_manager.clone(),
            self.node.event_ntfns.0.clone(),
        ).await.map_err(|_| Status::aborted("could not connect to peer"))?;

        println!("connected");
        let mut config = UserConfig::default();
        if req.is_public {
            config.channel_options.announced_channel = true;
        }
        // lnd's max to_self_delay is 2016, so we want to be compatible.
        config.peer_channel_config_limits.their_to_self_delay = 2016;
        self.node.channel_manager.create_channel(node_id, req.value_sat, 0, 0, None)
            .map_err(|e| {
                let msg = format!("failed to create channel {:?}", e);
                Status::aborted(msg)
            })?;
        println!("created");

        let reply = ChannelNewReply {};
        Ok(Response::new(reply))
    }
}

pub fn start(port: u16, args: LdkUserInfo) -> Result<(), Box<dyn std::error::Error>> {
    let node = build_node(args);
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
    let runtime = node.runtime.clone();
    let handler = AdminHandler::new(node);
    runtime.block_on(do_serve(addr, handler));
    Ok(())
}

async fn do_serve(addr: SocketAddr, handler: AdminHandler) {
    println!("starting server");
    Server::builder()
        .add_service(AdminServer::new(handler))
        .serve(addr).await.unwrap();
}
