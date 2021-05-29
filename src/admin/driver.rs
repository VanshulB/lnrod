use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use anyhow::Result;
use serde_json::json;
use tonic::{transport::Server, Request, Response, Status};

use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::PublicKey as BitcoinPublicKey;
use lightning::chain::keysinterface::KeysInterface;
use lightning::util::config::UserConfig;
use lightning::util::logger::Logger;
use lightning_invoice::Invoice;

use crate::admin::admin_api::{
	Channel, ChannelCloseRequest, ChannelNewReply, ChannelNewRequest, InvoiceNewReply,
	InvoiceNewRequest, Payment, PaymentListReply, PaymentSendReply, PaymentSendRequest, Peer,
	PeerConnectReply, PeerConnectRequest, PeerListReply, PeerListRequest,
};
use crate::node::{build_node, connect_peer_if_necessary, Node, NodeBuildArgs};
use crate::HTLCDirection;

use super::admin_api::admin_server::{Admin, AdminServer};
use super::admin_api::{ChannelListReply, NodeInfoReply, PingReply, PingRequest, Void};
use bitcoin::Address;

struct AdminHandler {
	node: Node,
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
		log_info!("ENTER ping");
		log_debug!("{}", type_and_value!(&req));
		let reply = PingReply {
			// We must use .into_inner() as the fields of gRPC requests and responses are private
			message: format!("Hello {}!", req.message),
		};
		log_debug!("{}", type_and_value!(&reply));
		log_info!("REPLY ping");
		Ok(Response::new(reply))
	}

	async fn node_info(&self, _request: Request<Void>) -> Result<Response<NodeInfoReply>, Status> {
		log_info!("ENTER node_info");
		let node_pubkey = PublicKey::from_secret_key(
			&Secp256k1::new(),
			&self.node.keys_manager.get_node_secret(),
		);
		let shutdown_pubkey = self.node.keys_manager.get_shutdown_pubkey();
		let bitcoin_pubkey = BitcoinPublicKey { compressed: true, key: shutdown_pubkey };
		let shutdown_address = Address::p2wpkh(&bitcoin_pubkey, self.node.network).unwrap().to_string();
		let reply = NodeInfoReply {
			node_id: node_pubkey.serialize().to_vec(),
			shutdown_address
		};
		log_debug!("{}", type_and_value!(&reply));
		log_info!("REPLY node_info");
		Ok(Response::new(reply))
	}

	async fn channel_list(
		&self, _request: Request<Void>,
	) -> Result<Response<ChannelListReply>, Status> {
		log_info!("ENTER channel_list");
		let mut channels = Vec::new();
		for details in self.node.channel_manager.list_channels() {
			let channel = Channel {
				peer_node_id: details.remote_network_id.serialize().to_vec(),
				channel_id: details.channel_id.to_vec(),
				is_pending: details.short_channel_id.is_none(),
				value_sat: details.channel_value_satoshis,
				is_active: details.is_live,
				outbound_msat: details.outbound_capacity_msat,
			};
			channels.push(channel);
		}
		let reply = ChannelListReply { channels };
		log_debug!("{}", type_and_value!(&reply));
		log_info!("REPLY channel_list");
		Ok(Response::new(reply))
	}

	async fn channel_new(
		&self, request: Request<ChannelNewRequest>,
	) -> Result<Response<ChannelNewReply>, Status> {
		let req = request.into_inner();
		log_info!("ENTER channel_new");
		log_debug!("{}", type_and_value!(&req));
		let node_id = PublicKey::from_slice(req.node_id.as_slice())
			.map_err(|_| Status::invalid_argument("failed to parse node_id"))?;

		let mut config = UserConfig::default();
		if req.is_public {
			config.channel_options.announced_channel = true;
		}
		// lnd's max to_self_delay is 2016, so we want to be compatible.
		config.peer_channel_config_limits.their_to_self_delay = 2016;
		self.node
			.channel_manager
			.create_channel(node_id, req.value_sat, req.push_msat, 0, Some(config))
			.map_err(|e| {
				let msg = format!("failed to create channel {:?}", e);
				Status::aborted(msg)
			})?;
		log_info!("created");

		let reply = ChannelNewReply {};
		log_debug!("{}", type_and_value!(&reply));
		log_info!("REPLY channel_new");
		Ok(Response::new(reply))
	}

	async fn peer_connect(
		&self, request: Request<PeerConnectRequest>,
	) -> Result<Response<PeerConnectReply>, Status> {
		let req = request.into_inner();
		log_info!("ENTER peer_connect");
		log_debug!("{}", type_and_value!(&req));
		let peer_addr =
			req.address.parse().map_err(|_| Status::invalid_argument("address parse"))?;
		let node_id = PublicKey::from_slice(req.node_id.as_slice())
			.map_err(|_| Status::invalid_argument("failed to parse node_id"))?;
		connect_peer_if_necessary(
			node_id,
			peer_addr,
			self.node.peer_manager.clone(),
			self.node.event_ntfn_sender.clone(),
		)
		.await
		.map_err(|_| Status::aborted("could not connect to peer"))?;

		log_info!("connected");
		let reply = PeerConnectReply {};
		log_debug!("{}", type_and_value!(&reply));
		log_info!("REPLY peer_connect");
		Ok(Response::new(reply))
	}

	async fn peer_list(
		&self, request: Request<PeerListRequest>,
	) -> Result<Response<PeerListReply>, Status> {
		let _req = request.into_inner();
		log_info!("ENTER peer_list");
		let peers = self
			.node
			.peer_manager
			.get_peer_node_ids()
			.iter()
			.map(|pkey| Peer { node_id: pkey.serialize().to_vec() })
			.collect();
		let reply = PeerListReply { peers };
		log_debug!("{}", type_and_value!(&reply));
		log_info!("REPLY peer_list");
		Ok(Response::new(reply))
	}

	async fn invoice_new(
		&self, request: Request<InvoiceNewRequest>,
	) -> Result<Response<InvoiceNewReply>, Status> {
		let req = request.into_inner();
		log_info!("ENTER invoice_new");
		log_debug!("{}", type_and_value!(&req));
		let invoice =
			self.node.new_invoice(req.value_msat).map_err(|e| Status::invalid_argument(e))?;
		let reply = InvoiceNewReply { invoice: invoice.to_string() };
		log_debug!("{}", type_and_value!(&reply));
		log_info!("REPLY invoice_new");
		Ok(Response::new(reply))
	}

	async fn payment_send(
		&self, request: Request<PaymentSendRequest>,
	) -> Result<Response<PaymentSendReply>, Status> {
		let req = request.into_inner();
		log_info!("ENTER payment_send");
		log_debug!("{}", type_and_value!(&req));
		let invoice = Invoice::from_str(req.invoice.as_str())
			.map_err(|_| Status::invalid_argument("invalid invoice"))?;
		self.node.send_payment(invoice).map_err(|e| Status::invalid_argument(e))?;
		let reply = PaymentSendReply {};
		log_debug!("{}", type_and_value!(&reply));
		log_info!("REPLY payment_send");
		Ok(Response::new(reply))
	}

	async fn payment_list(
		&self, request: Request<Void>,
	) -> Result<Response<PaymentListReply>, Status> {
		let _req = request.into_inner();
		log_info!("ENTER payment_list");
		let payments = self
			.node
			.payment_info
			.lock()
			.map_err(|_| Status::unavailable("Failed to acquire lock on payment info"))?
			.iter()
			.map(|(payment_hash, (_, direction, status, value_msat))| Payment {
				value_msat: value_msat.0.unwrap(),
				payment_hash: payment_hash.0.to_vec(),
				is_outbound: *direction == HTLCDirection::Outbound,
				status: status.clone() as i32,
			})
			.collect();
		let reply = PaymentListReply { payments };
		log_debug!("{}", type_and_value!(&reply));
		log_info!("REPLY payment_list");
		Ok(Response::new(reply))
	}

	async fn channel_close(
		&self, request: Request<ChannelCloseRequest>,
	) -> Result<Response<Void>, Status> {
		let req = request.into_inner();
		log_info!("ENTER channel_close");
		log_debug!("{}", type_and_value!(&req));
		let channel_id = req
			.channel_id
			.as_slice()
			.try_into()
			.map_err(|_| Status::invalid_argument("channel ID must be 32 bytes"))?;
		if req.is_force {
			self.node.channel_manager.force_close_channel(channel_id)
		} else {
			self.node.channel_manager.close_channel(channel_id)
		}
		.map_err(|e| Status::aborted(format!("{:?}", e)))?;
		log_info!("REPLY channel_close");
		Ok(Response::new(Void {}))
	}
}

#[tokio::main]
pub async fn start(rpc_port: u16, args: NodeBuildArgs) -> Result<(), Box<dyn std::error::Error>> {
	let node = build_node(args.clone()).await;
	let node_id =
		PublicKey::from_secret_key(&Secp256k1::new(), &node.keys_manager.get_node_secret());

	log_info!("p2p {} 127.0.0.1:{}", node_id, args.peer_listening_port);
	log_info!(
		"admin port {}, datadir {}, signer {}",
		rpc_port,
		args.storage_dir_path,
		args.signer_name
	);
	let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port);
	let handler = AdminHandler::new(node);
	log_info!("starting server");
	Server::builder().add_service(AdminServer::new(handler)).serve(addr).await?;
	Ok(())
}
