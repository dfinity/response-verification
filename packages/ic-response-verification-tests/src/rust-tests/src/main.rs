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
use std::println;
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
    let path = format!(
        "packages/ic-response-verification-tests/src/frontend/{}",
        file_path
    );
    match fs::read(path.clone()) {
        Ok(file) => {
            println!("Read file: {}", path);
            Ok(file)
        }
        Err(e) => {
            println!("Error reading file: {} from {}", e, path);
            Err(e.into())
        }
    }
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
        ["GET", "/index.html", "dist/index.html"], // load index.html when requesting /index.html
        ["GET", "/", "dist/index.html"],           // load index.html when requesting trailing slash
        ["GET", "/assets/hello", "dist/assets/hello/index.html"], // load hello/index.html when requesting /hello
        ["GET", "/assets/hello/", "dist/assets/hello/index.html"], // load hello/index.html when requesting /hello/ with trailing slash
        [
            "GET",
            "/assets/hello/index.html",
            "dist/assets/hello/index.html",
        ], // load hello/index.html when requesting full file path
        // *** /world.html ***
        ["GET", "/assets/world", "dist/assets/world.html"], // load world/index.html when requesting /world
        ["GET", "/assets/world.html", "dist/assets/world.html"], // load world.html when requesting full file path
        [
            "GET",
            "/assets/sample-asset.txt",
            "dist/assets/sample-asset.txt",
        ], // load sample text asset when requesting /sample-asset.txt
        [
            "GET",
            "/assets/%73ample-asset.txt",
            "dist/assets/sample-asset.txt",
        ], // load sample text asset when requesting /sample-asset.txt with encoding
        ["GET", "/not-found", "dist/index.html"], // fallback to index.html on not found path
        ["GET", "/not/found", "dist/index.html"], // fallback to index.html on not found path
        ["GET", "/a/b/not-found", "dist/index.html"], // fallback to index.html on not found path
        ["GET", "/assets/world/", "dist/index.html"], // load hello/index.html when requesting /hello/ with trailing slash
        ["GET", "/assets/world/not-found", "dist/index.html"], // fallback to index.html on not found path that has an existing asset on a sub path
        ["GET", "/assets/hello/not-found", "dist/index.html"], // fallback to index.html on not found path that has an existing asset on a sub path
        [
            "GET",
            "/assets/capture-d%E2%80%99%C3%A9cran-2023-10-26-%C3%A0.txt",
            "dist/assets/capture-d’écran-2023-10-26-à.txt",
        ], // Load an asset with special characters encoded
        [
            "GET",
            "/assets/another%20sample%20asset.txt",
            "dist/assets/another sample asset.txt",
        ], // Load an asset with spaces
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
    assert_eq!(asset, response.body().to_vec());

    Ok(())
}

async fn perform_test(
    canister_id: &str,
    http_method: &str,
    path: &str,
    certificate_version: Option<&u16>,
    agent: &Agent,
) -> Result<(VerificationInfo, HttpResponse<'static>)> {
    let canister_id = Principal::from_text(canister_id)?;
    let canister_interface = HttpRequestCanister::create(agent, canister_id);

    let (response,) = canister_interface
        .http_request(http_method, path, [], &[], certificate_version)
        .call()
        .await?;

    let request = HttpRequest::get(path).build();
    let response = HttpResponse::builder()
        .with_status_code(response.status_code.try_into().unwrap())
        .with_body(response.body)
        .with_headers(
            response
                .headers
                .iter()
                .map(|HeaderField(key, value)| (key.to_string(), value.to_string()))
                .collect::<Vec<_>>(),
        )
        .build();
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
