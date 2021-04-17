use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use bitcoin::secp256k1::{PublicKey, Secp256k1};
use lightning::chain::keysinterface::KeysInterface;
use lightning::util::config::UserConfig;
use tonic::{Request, Response, Status, transport::Server};

use crate::admin::admin_api::{Channel, ChannelNewReply, ChannelNewRequest, InvoiceNewReply, InvoiceNewRequest, PaymentSendReply, PaymentSendRequest, Peer, PeerConnectReply, PeerConnectRequest, PeerListReply, PeerListRequest, PaymentListReply, Payment};
use crate::cli::LdkUserInfo;
use crate::node::{build_node, connect_peer_if_necessary, Node};

use super::admin_api::{ChannelListReply, NodeInfoReply, PingReply, PingRequest, Void};
use super::admin_api::admin_server::{Admin, AdminServer};
use lightning_invoice::Invoice;
use std::str::FromStr;
use crate::HTLCDirection;

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

    async fn peer_connect(&self, request: Request<PeerConnectRequest>) -> Result<Response<PeerConnectReply>, Status> {
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
        let reply = PeerConnectReply {};
        Ok(Response::new(reply))
    }

    async fn peer_list(&self, request: Request<PeerListRequest>) -> Result<Response<PeerListReply>, Status> {
        let _req = request.into_inner();
        let peers = self.node.peer_manager.get_peer_node_ids()
            .iter().map(|pkey| Peer { node_id: pkey.serialize().to_vec() }).collect();
        let reply = PeerListReply {
            peers
        };
        Ok(Response::new(reply))
    }

    async fn invoice_new(&self, request: Request<InvoiceNewRequest>) -> Result<Response<InvoiceNewReply>, Status> {
        let req = request.into_inner();
        let invoice = self.node.get_invoice(req.value_msat).map_err(|e| Status::invalid_argument(e))?;
        let reply = InvoiceNewReply {
            invoice: invoice.to_string()
        };
        Ok(Response::new(reply))
    }

    async fn payment_send(&self, request: Request<PaymentSendRequest>) -> Result<Response<PaymentSendReply>, Status> {
        let req = request.into_inner();
        let invoice = Invoice::from_str(req.invoice.as_str())
            .map_err(|_| Status::invalid_argument("invalid invoice"))?;
        self.node.send_payment(invoice).map_err(|e| Status::invalid_argument(e))?;
        let reply = PaymentSendReply {};
        Ok(Response::new(reply))
    }

    async fn payment_list(&self, request: Request<Void>) -> Result<Response<PaymentListReply>, Status> {
        let _req = request.into_inner();
        let payments = self.node.payment_info
            .lock().unwrap().iter()
            .map(|(payment_hash, (_, direction, status, value_msat))|
            Payment {
                value_msat: value_msat.0.unwrap(),
                payment_hash: payment_hash.0.to_vec(),
                is_outbound: *direction == HTLCDirection::Outbound,
                status: status.clone() as i32
            }).collect();
        let reply = PaymentListReply {
            payments
        };
        Ok(Response::new(reply))
    }
}

pub fn start(rpc_port: u16, args: LdkUserInfo) -> Result<(), Box<dyn std::error::Error>> {
    let node = build_node(args.clone());
    let node_id = PublicKey::from_secret_key(&Secp256k1::new(), &node.keys_manager.get_node_secret());

    println!("p2p {} 127.0.0.1:{}", node_id, args.ldk_peer_listening_port);
    println!("admin port {}, datadir {}", rpc_port, args.ldk_storage_dir_path);
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), rpc_port);
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
