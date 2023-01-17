use crate::agent::create_agent;
use anyhow::{anyhow, Result};
use ic_agent::export::Principal;
use ic_utils::call::SyncCall;
use ic_utils::interfaces::http_request::HeaderField;
use ic_utils::interfaces::HttpRequestCanister;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

mod agent;

fn get_current_time() -> u128 {
    let start = SystemTime::now();

    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let Some(replica_address) = args.get(1) else {
        return Err(anyhow!("The replica_address arg was not provided: `cargo run [replica_address] [canister_id]`"));
    };

    let Some(canister_id) = args.get(2) else {
        return Err(anyhow!("The canister_id arg was not provided: `cargo run [replica_address] [canister_id]`"));
    };

    let agent = create_agent(replica_address)?;
    let canister_id = Principal::from_text(canister_id)?;
    let canister_id_bytes = canister_id.as_slice();
    let canister_interface = HttpRequestCanister::create(&agent, canister_id);

    let (response,) = canister_interface
        .http_request("GET", "/", [], &[])
        .call()
        .await?;

    let request = ic_response_verification::types::Request {
        headers: vec![],
        url: "/".into(),
    };
    let response = ic_response_verification::types::Response {
        headers: response
            .headers
            .iter()
            .map(|HeaderField(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        body: response.body,
    };
    let current_time_ns = get_current_time();
    let max_cert_time_offset_ns = 300_000_000_000; // 5 mins

    let result = ic_response_verification::verify_request_response_pair(
        request,
        response,
        canister_id_bytes,
        current_time_ns,
        max_cert_time_offset_ns,
    )?;

    assert!(result);

    Ok(())
}
