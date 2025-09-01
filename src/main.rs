mod handlers;
mod ingress;
mod validator;
mod wire;
//use alloy_primitives::{address, hex_literal::hex};
use ark_bn254::Fr;
use ark_serialize::CanonicalDeserialize;
//use ark_ff::{Fp, PrimeField};
use bn254::Bn254;
use bn254::G1PublicKey;
use bn254::PrivateKey;
use bn254::PublicKey;
use clap::{Arg, Command, value_parser};
use commonware_cryptography::Signer;
use commonware_eigenlayer::network_configuration::CommonwarePublicKeys;
use commonware_p2p::authenticated::lookup::{self, Network};
use commonware_runtime::{
    Metrics, Runner, Spawner,
    tokio::{self},
};
use commonware_utils::NZU32;
use eigen_logging::log_level::LogLevel;
use governor::Quota;
use ncn_program_core::g1_point::G1CompressedPoint;
use ncn_program_core::g1_point::G1Point;
use ncn_program_core::g2_point::G2CompressedPoint;
use ncn_program_core::g2_point::G2Point;
use serde::{Deserialize, Serialize};
use solana_sdk::msg;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::{str::FromStr, time::Duration};

use anyhow::Result;
use jito_bytemuck::{AccountDeserialize, Discriminator};
use ncn_program_core::ncn_operator_account::NCNOperatorAccount;
use solana_account_decoder::{UiAccountEncoding, UiDataSliceConfig};
use solana_client::{
    rpc_client::RpcClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
    rpc_filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType},
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};

#[derive(Debug, Clone)]
pub struct OperatorPubKeys {
    pub g1_pub_key: G1CompressedPoint,
    pub g2_pub_key: G2CompressedPoint,
}

#[derive(Debug, Clone)]
pub struct OperatorInfo {
    pub address: Pubkey,
    pub stake: u128,
    pub pub_keys: Option<CommonwarePublicKeys>,
    pub socket: Option<String>,
    pub quorum_number: u8,
}

#[derive(Debug)]
pub struct QuorumInfo {
    pub operator_count: usize,
    pub operators: Vec<OperatorInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct KeyConfig {
    privateKey: String,
}

fn get_signer(key: &str) -> Bn254 {
    let fr = Fr::from_str(key).expect("Invalid decimal string for private key");
    let key = PrivateKey::from(fr);
    Bn254::new(key).expect("Failed to create signer")
}
fn load_key_from_file(path: &str) -> String {
    let contents = fs::read_to_string(path).expect("Could not read key file");
    let config: KeyConfig = serde_json::from_str(&contents).expect("Could not parse key file");
    config.privateKey
}

fn get_commonware_keys_from_g1_g2(
    g1_compressed: &G1CompressedPoint,
    g2_compressed: &G2CompressedPoint,
) -> CommonwarePublicKeys {
    let mut g1_bytes = g1_compressed.0;
    let mut g2_bytes = g2_compressed.0;

    g1_bytes.reverse();
    g2_bytes.reverse();

    let g2_affine = ark_bn254::G2Affine::deserialize_compressed(&g2_bytes[..]).unwrap();
    let g1_affine = ark_bn254::G1Affine::deserialize_compressed(&g1_bytes[..]).unwrap();

    // let publick_key = PublicKey::try_from(g2_compressed_pubkey.0.as_slice()).unwrap();
    let publick_key = PublicKey::from(g2_affine);
    let g1_public_key = G1PublicKey::from(g1_affine);

    CommonwarePublicKeys {
        g1_pub_key: g1_public_key,
        g2_pub_key: publick_key,
    }
}

// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_AGGREGATION_";

async fn get_operator_states() -> Result<Vec<QuorumInfo>, Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let http_rpc = env::var("HTTP_RPC").expect("HTTP_RPC must be set");
    let ncn_program_id = env::var("NCN_PROGRAM_ID").expect("NCN_PROGRAM_ID must be set");
    let ncn_address = env::var("NCN").expect("NCN must be set");

    // Parse the NCN program ID and address
    let ncn_program_id = Pubkey::from_str(&ncn_program_id)?;
    let ncn_address = Pubkey::from_str(&ncn_address)?;

    // Create RPC client
    let client = RpcClient::new_with_commitment(http_rpc, CommitmentConfig::confirmed());

    // Get all NCN operator accounts using the pattern from getters.rs
    let ncn_operator_accounts =
        get_all_ncn_operator_accounts(&client, &ncn_program_id, &ncn_address).await?;

    let operators = ncn_operator_accounts
        .iter()
        .map(|(pubkey, account)| {
            let keys = get_commonware_keys_from_g1_g2(
                &G1CompressedPoint::from(*account.g1_pubkey()),
                &G2CompressedPoint::from(*account.g2_pubkey()),
            );
            let socket = format!(
                "{}:{}",
                account.ip_address().map(|b| b.to_string()).join("."),
                account.port()
            );
            OperatorInfo {
                address: *pubkey,
                // TODO: get stake
                stake: 0,
                pub_keys: Some(keys),
                socket: Some(socket),
                quorum_number: account.ncn_operator_index() as u8,
            }
        })
        .collect::<Vec<OperatorInfo>>();

    // For now, return a mock QuorumInfo structure
    // This can be enhanced later to properly convert NCN operator accounts
    let quorum_info = QuorumInfo {
        operators, // Empty for now
        operator_count: ncn_operator_accounts.len(),
    };

    Ok(vec![quorum_info])
}

async fn get_all_ncn_operator_accounts(
    client: &RpcClient,
    ncn_program_id: &Pubkey,
    ncn_address: &Pubkey,
) -> Result<Vec<(Pubkey, NCNOperatorAccount)>> {
    let ncn_operator_account_size = size_of::<NCNOperatorAccount>() + 8;

    let size_filter = RpcFilterType::DataSize(ncn_operator_account_size as u64);

    let discriminator_filter = RpcFilterType::Memcmp(Memcmp::new(
        0,                                                                     // offset
        MemcmpEncodedBytes::Bytes([NCNOperatorAccount::DISCRIMINATOR].into()), // encoded bytes
    ));

    let ncn_filter = RpcFilterType::Memcmp(Memcmp::new(
        8,
        MemcmpEncodedBytes::Bytes(ncn_address.to_bytes().as_slice().to_vec()),
    ));

    let config = RpcProgramAccountsConfig {
        filters: Some(vec![discriminator_filter, size_filter, ncn_filter]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            data_slice: Some(UiDataSliceConfig {
                offset: 0,
                length: ncn_operator_account_size,
            }),
            commitment: Some(CommitmentConfig::confirmed()),
            min_context_slot: None,
        },
        with_context: Some(false),
        sort_results: Some(false),
    };

    let results = client.get_program_accounts_with_config(ncn_program_id, config)?;

    let accounts: Vec<(Pubkey, NCNOperatorAccount)> = results
        .iter()
        .filter_map(|result| {
            NCNOperatorAccount::try_from_slice_unchecked(result.1.data.as_slice())
                .map(|account| (result.0, *account))
                .ok()
        })
        .collect();

    Ok(accounts)
}

fn main() {
    // Initialize runtime
    let runtime_cfg = tokio::Config::default();
    let runner = tokio::Runner::new(runtime_cfg.clone());

    // Parse arguments
    let matches = Command::new("orchestrator")
        .about("generate and verify BN254 Multi-Signatures")
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("key-file")
                .long("key-file")
                .required(true)
                .help("Path to the YAML file containing the private key"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .required(true)
                .help("Port to run the service on"),
        )
        .get_matches();

    // // Create logger
    // tracing_subscriber::fmt()
    //     .with_max_level(tracing::Level::DEBUG)
    //     .init();

    // Configure my identity
    let key_file = matches
        .get_one::<String>("key-file")
        .expect("Please provide key file");
    let port = matches
        .get_one::<String>("port")
        .expect("Please provide port");
    let key = load_key_from_file(key_file);
    let me = format!("{}@{}", key, port);
    let parts = me.split('@').collect::<Vec<&str>>();
    if parts.len() != 2 {
        panic!("Identity not well-formed");
    }
    let key = parts[0];
    let signer = get_signer(key);
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    tracing::info!(port, "loaded port");

    // Configure network
    const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MB
    let my_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let my_local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let p2p_cfg = lookup::Config::recommended(
        signer.clone(),
        APPLICATION_NAMESPACE,
        my_addr,
        my_local_addr,
        MAX_MESSAGE_SIZE,
    );

    eigen_logging::init_logger(LogLevel::Debug);
    tracing::info!("Orchestrator listening {}", my_addr.to_string());
    tracing::info!("my_local_addr {:?}", my_local_addr);
    tracing::info!("Message size {:?}", MAX_MESSAGE_SIZE);

    // Start runtime
    runner.start(|context| async move {
        let (mut network, mut oracle) = Network::new(context.with_label("network"), p2p_cfg);
        tracing::info!("----------- debug 1 -----------");
        let mut recipients: Vec<(bn254::PublicKey, SocketAddr)>;
        tracing::info!("----------- debug 2 -----------");
        let quorum_infos;
        tracing::info!("----------- debug 3 -----------");
        {
            // Get operator states and configure allowed peers
            quorum_infos = get_operator_states()
                .await
                .expect("Failed to get operator states");

            tracing::info!("----------- debug 4 -----------");
            recipients = Vec::new();
            let participants = quorum_infos[0].operators.clone(); //TODO: Fix hardcoded quorum_number
            if participants.is_empty() {
                panic!("Please provide at least one participant");
            }
            for participant in participants {
                let verifier = participant.pub_keys.unwrap().g2_pub_key;
                tracing::info!(key = ?verifier, "registered authorized key",);
                if let Some(socket) = participant.socket {
                    let socket_addr = SocketAddr::from_str(&socket)
                        .expect("Bootstrapper address not well-formed");
                    recipients.push((verifier, socket_addr));
                }
            }
            let orchestrator_verifier = signer.public_key();
            recipients.push((orchestrator_verifier, my_addr));
        }
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(std::io::stdout)
            .finish();
        let _ = tracing::subscriber::set_default(subscriber);

        // Provide authorized peers
        oracle.register(0, recipients).await;

        // Parse contributors from operator states
        let mut contributors = Vec::new();
        let mut contributors_map = HashMap::new();
        let operators = &quorum_infos[0].operators;
        if operators.is_empty() {
            panic!("Please provide at least one contributor");
        }
        for operator in operators {
            let verifier = operator.pub_keys.as_ref().unwrap().g2_pub_key.clone();
            let verifier_g1 = operator.pub_keys.as_ref().unwrap().g1_pub_key.clone();
            tracing::info!(key = ?verifier, "registered contributor",);
            contributors.push(verifier.clone());
            contributors_map.insert(verifier, verifier_g1);
        }

        // Infer threshold
        let threshold = 3; //hardcoded for now

        // Run as the orchestrator
        const DEFAULT_MESSAGE_BACKLOG: usize = 256;
        const AGGREGATION_FREQUENCY: Duration = Duration::from_secs(30);

        let (sender, receiver) =
            network.register(0, Quota::per_second(NZU32!(1)), DEFAULT_MESSAGE_BACKLOG);
        let orchestrator = handlers::Orchestrator::new(
            context.clone(),
            signer,
            AGGREGATION_FREQUENCY,
            contributors,
            contributors_map,
            threshold as usize,
        )
        .await;

        context.spawn(|_| async move { orchestrator.run(sender, receiver).await });

        let _ = network.start().await;
    });
}
