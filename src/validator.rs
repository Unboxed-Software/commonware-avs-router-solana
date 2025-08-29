use crate::wire;
use alloy::sol_types::SolValue;
use alloy_primitives::U256;
use anyhow::Result;
use commonware_codec::{DecodeExt, ReadExt};
use commonware_cryptography::sha256::Digest;
use commonware_cryptography::{Hasher, Sha256};
use std::io::Cursor;
use tracing::info;

pub struct Validator {
    counter: u64,
}

impl Validator {
    pub async fn new() -> Result<Self> {
        // TODO: get it form solana
        // let http_rpc = env::var("HTTP_RPC").expect("HTTP_RPC must be set");
        // let provider = ProviderBuilder::new().on_http(url::Url::parse(&http_rpc).unwrap());
        //
        // let deployment = AvsDeployment::load()
        //     .map_err(|e| anyhow::anyhow!("Failed to load AVS deployment: {}", e))?;
        // let counter_address = deployment
        //     .counter_address()
        //     .map_err(|e| anyhow::anyhow!("Failed to get counter address: {}", e))?;
        info!("Initializing Validator...");
        let counter = 0;
        Ok(Self { counter })
    }

    pub async fn validate_and_return_expected_hash(&self, msg: &[u8]) -> Result<Digest> {
        info!("Validating message and returning expected hash...");
        // First verify the message round
        self.verify_message_round(msg).await?;
        info!("Message round verified.");

        // Then get the payload hash
        self.get_payload_from_message(msg).await
    }

    pub async fn get_payload_from_message(&self, msg: &[u8]) -> Result<Digest> {
        info!("Getting payload from message...");
        // Decode the wire message
        let aggregation = wire::Aggregation::decode(msg)?;
        info!("Decoded aggregation: {:?}", aggregation);

        // Create the payload directly
        let payload = U256::from(aggregation.round).abi_encode();
        info!("Constructed payload: {:?}", payload);

        // Hash the payload
        let mut hasher = Sha256::new();
        info!("Hashing payload...");
        hasher.update(&payload);
        info!("Payload hashed.");
        let payload_hash = hasher.finalize();
        info!("Payload hash: {:?}", payload_hash);

        Ok(payload_hash)
    }

    async fn verify_message_round(&self, msg: &[u8]) -> Result<()> {
        info!("Verifying message round...");
        let aggregation = wire::Aggregation::read(&mut Cursor::new(msg))?;
        info!("Decoded aggregation: {:?}", aggregation);
        let current_number = self.counter;

        if aggregation.round != current_number {
            return Err(anyhow::anyhow!(
                "Invalid round number in message. Expected {}, got {}",
                current_number,
                aggregation.round
            ));
        }

        Ok(())
    }
}
