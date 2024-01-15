use crate::agent::create_agent;
use anyhow::{anyhow, Result};
use ic_agent::export::Principal;
use ic_agent::Agent;
use ic_http_certification::{HttpRequest, HttpResponse};
use ic_response_verification::types::VerificationInfo;
use ic_utils::call::SyncCall;
use ic_utils::interfaces::http_request::HeaderField;
use ic_utils::interfaces::HttpRequestCanister;
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

mod agent;

fn get_current_time() -> u128 {
    let start = SystemTime::now();

    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos()
}

fn read_file(file_path: &str) -> Result<Vec<u8>> {
    let file = fs::read(format!(
        "packages/ic-response-verification-tests/dfx-project/{}",
        file_path
    ))?;

    Ok(file)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let Ok(replica_address) = env::var("DFX_REPLICA_ADDRESS") else {
        return Err(anyhow!(
            "The `DFX_REPLICA_ADDRESS` env variable not provided`"
        ));
    };

    let Some(canister_id) = args.get(1) else {
        return Err(anyhow!(
            "The canister_id arg was not provided: `cargo run [canister_id]`"
        ));
    };

    let agent = create_agent(replica_address.as_str()).await?;

    v1_test(canister_id, &agent).await?;
    v2_test(canister_id, &agent).await?;

    Ok(())
}

async fn v1_test(canister_id: &str, agent: &Agent) -> Result<()> {
    let (result, _response) = perform_test(canister_id, "GET", "/", None, agent).await?;
    assert!(matches!(
        result,
        VerificationInfo {
            verification_version,
            response: _,
        } if verification_version == 1
    ));

    let (result, _response) =
        perform_test(canister_id, "GET", "/sample-asset.txt", None, agent).await?;
    assert!(matches!(
        result,
        VerificationInfo {
            verification_version,
            response: _,
        } if verification_version == 1
    ));

    Ok(())
}

async fn v2_test(canister_id: &str, agent: &Agent) -> Result<()> {
    let test_cases = [
        ["GET", "/index.html", "dist/frontend/index.html"], // load index.html when requesting /index.html
        ["GET", "/", "dist/frontend/index.html"], // load index.html when requesting trailing slash
        [
            "GET",
            "/hello",
            "canisters/frontend/assets/hello/index.html",
        ], // load hello/index.html when requesting /hello
        [
            "GET",
            "/hello/",
            "canisters/frontend/assets/hello/index.html",
        ], // load hello/index.html when requesting /hello/ with trailing slash
        [
            "GET",
            "/hello/index.html",
            "canisters/frontend/assets/hello/index.html",
        ], // load hello/index.html when requesting full file path
        // *** /world.html ***
        ["GET", "/world", "canisters/frontend/assets/world.html"], // load world/index.html when requesting /world
        ["GET", "/world.html", "canisters/frontend/assets/world.html"], // load world.html when requesting full file path
        [
            "GET",
            "/sample-asset.txt",
            "canisters/frontend/assets/sample-asset.txt",
        ], // load sample text asset when requesting /sample-asset.txt
        [
            "GET",
            "/%73ample-asset.txt",
            "canisters/frontend/assets/sample-asset.txt",
        ], // load sample text asset when requesting /sample-asset.txt with encoding
        ["GET", "/index.js", "dist/frontend/index.js"], // load sample js asset when requesting /index.js
        ["GET", "/not-found", "dist/frontend/index.html"], // fallback to index.html on not found path
        ["GET", "/not/found", "dist/frontend/index.html"], // fallback to index.html on not found path
        ["GET", "/a/b/not-found", "dist/frontend/index.html"], // fallback to index.html on not found path
        ["GET", "/world/", "dist/frontend/index.html"], // load hello/index.html when requesting /hello/ with trailing slash
        ["GET", "/world/not-found", "dist/frontend/index.html"], // fallback to index.html on not found path that has an existing asset on a sub path
        ["GET", "/hello/not-found", "dist/frontend/index.html"], // fallback to index.html on not found path that has an existing asset on a sub path
    ];

    for [http_method, http_path, file_path] in test_cases.into_iter() {
        // validates if the returned response is the same as the file content for the given path
        v2_load_asset(canister_id, agent, http_method, http_path, file_path).await?;
    }

    Ok(())
}

async fn v2_load_asset(
    canister_id: &str,
    agent: &Agent,
    http_method: &str,
    path: &str,
    file_path: &str,
) -> Result<()> {
    let asset = read_file(file_path)?;
    let (result, response) = perform_test(canister_id, http_method, path, Some(&2), agent).await?;

    assert!(matches!(
        result,
        VerificationInfo {
            verification_version,
            response: _,
        } if verification_version == 2
    ));
    assert_eq!(asset, response.body);

    Ok(())
}

async fn perform_test(
    canister_id: &str,
    http_method: &str,
    path: &str,
    certificate_version: Option<&u16>,
    agent: &Agent,
) -> Result<(VerificationInfo, HttpResponse)> {
    let canister_id = Principal::from_text(canister_id)?;
    let canister_interface = HttpRequestCanister::create(agent, canister_id);

    let (response,) = canister_interface
        .http_request(http_method, path, [], &[], certificate_version)
        .call()
        .await?;

    let request = HttpRequest {
        method: "GET".into(),
        headers: vec![],
        url: path.into(),
        body: vec![],
    };
    let response = HttpResponse {
        headers: response
            .headers
            .iter()
            .map(|HeaderField(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        body: response.body,
        status_code: response.status_code,
        upgrade: None,
    };
    let current_time_ns = get_current_time();
    let max_cert_time_offset_ns = 300_000_000_000; // 5 mins

    let result = ic_response_verification::verify_request_response_pair(
        request,
        response.clone(),
        canister_id.as_slice(),
        current_time_ns,
        max_cert_time_offset_ns,
        agent.read_root_key().as_slice(),
        ic_response_verification::MIN_VERIFICATION_VERSION,
    )?;

    Ok((result, response))
}
