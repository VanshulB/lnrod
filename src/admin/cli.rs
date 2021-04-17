use serde_json::to_string_pretty;
use tonic::{Request, transport};

use super::admin_api::{ChannelNewRequest, Void, PingRequest};
use super::admin_api::admin_client::AdminClient;
use crate::admin::admin_api::{PeerConnectRequest, PeerListRequest};
use serde::Serialize;

pub struct CLI {
    connect: String,
}

impl CLI {
    pub fn new(connect: String) -> Self {
        CLI { connect }
    }

    fn dump_response<R: Serialize>(response: &R) {
        println!("{}", to_string_pretty(&response).unwrap());
    }

    #[tokio::main]
    pub async fn ping(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let ping_request = Request::new(PingRequest {
            message: "hello".into(),
        });

        let response = client.ping(ping_request).await?.into_inner();

        CLI::dump_response(&response);
        Ok(())
    }

    #[tokio::main]
    pub async fn node_info(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let void_request = Request::new(Void {});

        let response = client.node_info(void_request).await?.into_inner();

        println!("{}", hex::encode(response.node_id));
        Ok(())
    }

    #[tokio::main]
    pub async fn channel_list(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let void_request = Request::new(Void {});

        let response = client.channel_list(void_request).await?.into_inner();

        CLI::dump_response(&response);
        Ok(())
    }

    #[tokio::main]
    pub async fn channel_new(&self, node_id: Vec<u8>, address: String, value_sat: u64, is_public: bool) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let request = Request::new(ChannelNewRequest {
            node_id,
            address,
            value_sat,
            is_public
        });
        let response = client.channel_new(request).await?.into_inner();
        CLI::dump_response(&response);
        Ok(())
    }

    #[tokio::main]
    pub async fn peer_connect(&self, node_id: Vec<u8>, address: String) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let request = Request::new(PeerConnectRequest {
            node_id,
            address
        });
        let response = client.peer_connect(request).await?.into_inner();
        CLI::dump_response(&response);
        Ok(())
    }

    #[tokio::main]
    pub async fn peer_list(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let request = Request::new(PeerListRequest {});
        let response = client.peer_list(request).await?.into_inner();
        CLI::dump_response(&response);
        Ok(())
    }

    async fn connect(&self) -> Result<AdminClient<transport::Channel>, Box<dyn std::error::Error>> {
        Ok(AdminClient::connect(self.connect.clone()).await?)
    }
}
