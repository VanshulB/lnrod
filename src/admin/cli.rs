use serde_json::to_string_pretty;
use tonic::{Request, transport};

use super::admin_api::{ChannelNewRequest, Void, PingRequest};
use super::admin_api::admin_client::AdminClient;

pub struct CLI {
    connect: String,
}

impl CLI {
    pub fn new(connect: String) -> Self {
        CLI { connect }
    }

    #[tokio::main]
    pub async fn ping(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let ping_request = Request::new(PingRequest {
            message: "hello".into(),
        });

        let response = client.ping(ping_request).await?;

        println!("ping response={:?}", response);
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

        println!("{}", to_string_pretty(&response).unwrap());
        Ok(())
    }

    #[tokio::main]
    pub async fn channel_new(&self, node_id: Vec<u8>, address: &str, value_sat: u64, is_public: bool) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let request = Request::new(ChannelNewRequest {
            node_id,
            address: address.to_string(),
            value_sat,
            is_public
        });
        let response = client.channel_new(request).await?.into_inner();
        println!("{:?}", response);
        Ok(())
    }

    async fn connect(&self) -> Result<AdminClient<transport::Channel>, Box<dyn std::error::Error>> {
        Ok(AdminClient::connect(self.connect.clone()).await?)
    }
}
