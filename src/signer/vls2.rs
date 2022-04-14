use std::fs;
use std::sync::Arc;

use bitcoin::{Address, Network, Script, Transaction, TxOut};
use bitcoin::bech32::u5;
use bitcoin::secp256k1::{All, PublicKey, SecretKey};
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::secp256k1::Secp256k1;
use lightning::chain::keysinterface::{KeyMaterial, KeysInterface, Recipient, SpendableOutputDescriptor};
use lightning::ln::msgs::DecodeError;
use lightning::ln::script::ShutdownScript;
use lightning_signer::lightning;
use lightning_signer::persist::DummyPersister;
use log::{debug, error, info};
use vls_protocol_client::{Error, KeysManagerClient, Transport};
use vls_protocol_signer::handler::{Handler, RootHandler};
use vls_protocol_signer::vls_protocol::model::PubKey;
use vls_protocol_signer::vls_protocol::msgs;

use crate::{DynSigner, SpendableKeysInterface};
use crate::signer::vls::create_spending_transaction;

// A VLS client with a null transport.
// Actually runs VLS in-process, but still performs the protocol
struct NullTransport {
    handler: RootHandler,
}

impl NullTransport {
    pub fn new(address: Address) -> Self {
        let persister = Arc::new(DummyPersister);
        let allowlist = vec![address.to_string()];
        info!("allowlist {:?}", allowlist);
        let handler = RootHandler::new(0, None, persister, allowlist);
        NullTransport {
            handler,
        }
    }
}

impl Transport for NullTransport {
    fn node_call(&self, message_ser: Vec<u8>) -> Result<Vec<u8>, Error> {
        let message = msgs::from_vec(message_ser)?;
        debug!("ENTER node_call {:?}", message);
        let result = self.handler.handle(message)
            .map_err(|e| {
                error!("error in handle: {:?}", e);
                Error::TransportError
            })?;
        debug!("REPLY node_call {:?}", result);
        Ok(result.as_vec())
    }

    fn call(&self, dbid: u64, peer_id: PubKey, message_ser: Vec<u8>) -> Result<Vec<u8>, Error> {
        let message = msgs::from_vec(message_ser)?;
        debug!("ENTER call({}) {:?}", dbid, message);
        let handler = self.handler.for_new_client(0, peer_id, dbid);
        let result = handler.handle(message)
            .map_err(|e| {
                error!("error in handle: {:?}", e);
                Error::TransportError
            })?;
        debug!("REPLY call({}) {:?}", dbid, result);
        Ok(result.as_vec())
    }
}

struct KeysManager {
    client: KeysManagerClient,
    sweep_address: Address,
    node_id: PublicKey,
}

impl KeysInterface for KeysManager {
    type Signer = DynSigner;

    fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
        self.client.get_node_secret(recipient)
    }

    fn get_destination_script(&self) -> Script {
        self.client.get_destination_script()
    }

    fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
        self.client.get_shutdown_scriptpubkey()
    }

    fn get_channel_signer(&self, inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
        let client = self.client.get_channel_signer(inbound, channel_value_satoshis);
        DynSigner::new(client)
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.client.get_secure_random_bytes()
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        let signer = self.client.read_chan_signer(reader)?;
        Ok(DynSigner::new(signer))
    }

    fn sign_invoice(&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient) -> Result<RecoverableSignature, ()> {
        self.client.sign_invoice(hrp_bytes, invoice_data, recipient)
    }

    fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.client.get_inbound_payment_key_material()
    }
}

impl SpendableKeysInterface for KeysManager {
    fn spend_spendable_outputs(&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>, change_destination_script: Script, feerate_sat_per_1000_weight: u32, _secp_ctx: &Secp256k1<All>) -> anyhow::Result<Transaction> {
        info!("ENTER spend_spendable_outputs");
        let mut tx = create_spending_transaction(descriptors, outputs, change_destination_script, feerate_sat_per_1000_weight)?;
        let witnesses = self.client.sign_onchain_tx(&tx, descriptors);
        assert_eq!(witnesses.len(), tx.input.len());
        for (idx, w) in witnesses.into_iter().enumerate() {
            tx.input[idx].witness = w;
        }
        Ok(tx)
    }

    fn get_sweep_address(&self) -> Address {
        self.sweep_address.clone()
    }

    fn get_node_id(&self) -> PublicKey {
        self.node_id
    }
}

pub(crate) async fn make_null_signer(network: Network, ldk_data_dir: String, sweep_address: Address) -> Box<dyn SpendableKeysInterface<Signer = DynSigner>> {
    let node_id_path = format!("{}/node_id", ldk_data_dir);

    if let Ok(_node_id_hex) = fs::read_to_string(node_id_path.clone()) {
        unimplemented!("read from disk {}", node_id_path);
    } else {
        let transport = NullTransport::new(sweep_address.clone());
        let node_id = transport.handler.node.get_id();
        let client = KeysManagerClient::new(Arc::new(transport), network.to_string());
        let keys_manager = KeysManager { client, sweep_address, node_id };
        fs::write(node_id_path, node_id.to_string()).expect("write node_id");
        Box::new(keys_manager)
    }
}
