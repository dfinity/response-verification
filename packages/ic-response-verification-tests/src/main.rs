use crate::agent::create_agent;
use anyhow::{anyhow, Result};
use ic_agent::export::Principal;
use ic_agent::Agent;
use ic_response_verification::types::{Request, Response, VerificationResult};
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

    let Ok(replica_address) = env::var("DFX_REPLICA_ADDRESS") else {
        return Err(anyhow!("The `DFX_REPLICA_ADDRESS` env variable not provided`"));
    };

    let Some(canister_id) = args.get(1) else {
        return Err(anyhow!("The canister_id arg was not provided: `cargo run [canister_id]`"));
    };

    let agent = create_agent(replica_address.as_str()).await?;

    v1_test(canister_id, &agent).await?;
    v2_test(canister_id, &agent).await?;

    Ok(())
}

async fn v1_test(canister_id: &str, agent: &Agent) -> Result<()> {
    let result = perform_test(canister_id, "GET", "/", None, agent).await?;
    assert!(matches!(
        result,
        VerificationResult::Passed {
            verification_version,
            response: _,
        } if verification_version == 1
    ));

    let result = perform_test(canister_id, "GET", "/sample-asset.txt", None, agent).await?;
    assert!(matches!(
        result,
        VerificationResult::Passed {
            verification_version,
            response: _,
        } if verification_version == 1
    ));

    Ok(())
}

async fn v2_test(canister_id: &str, agent: &Agent) -> Result<()> {
    let result = perform_test(canister_id, "GET", "/", Some(&2), agent).await?;
    assert!(matches!(
        result,
        VerificationResult::Passed {
            verification_version,
            response: _,
        } if verification_version == 2
    ));

    let result = perform_test(canister_id, "GET", "/sample-asset.txt", Some(&2), agent).await?;
    assert!(matches!(
        result,
        VerificationResult::Passed {
            verification_version,
            response: _,
        } if verification_version == 2
    ));

    Ok(())
}

async fn perform_test(
    canister_id: &str,
    http_method: &str,
    path: &str,
    certificate_version: Option<&u16>,
    agent: &Agent,
) -> Result<VerificationResult> {
    let canister_id = Principal::from_text(canister_id)?;
    let canister_interface = HttpRequestCanister::create(agent, canister_id);

    let (response,) = canister_interface
        .http_request(http_method, path, [], &[], certificate_version)
        .call()
        .await?;

    let request = Request {
        method: "GET".into(),
        headers: vec![],
        url: path.into(),
    };
    let response = Response {
        headers: response
            .headers
            .iter()
            .map(|HeaderField(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        body: response.body,
        status_code: response.status_code,
    };
    let current_time_ns = get_current_time();
    let max_cert_time_offset_ns = 300_000_000_000; // 5 mins

    let result = ic_response_verification::verify_request_response_pair(
        request,
        response,
        canister_id.as_slice(),
        current_time_ns,
        max_cert_time_offset_ns,
        agent.read_root_key()?.as_slice(),
        ic_response_verification::MIN_VERIFICATION_VERSION,
    )?;

    Ok(result)
}
