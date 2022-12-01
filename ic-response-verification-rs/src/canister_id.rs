use http::Uri;
use crate::principal::Principal;

fn resolve_canister_id_from_query_params(uri: &Uri) -> Option<Principal> {
    if let Some(query_params) = uri.query() {
        return form_urlencoded::parse(query_params.as_bytes())
            .find(|(name, _)| name == "canisterId")
            .and_then(|(_, canister_id)| Principal::from_text(canister_id).ok());
    }

    None
}

fn resolve_canister_id_from_hostname(hostname: &str) -> Option<Principal> {
    for host_part in hostname.split('.').rev() {
        if let Ok(canister_id) = Principal::from_text(host_part) {
            return Some(canister_id);
        }
    }

    None
}

fn resolve_canister_id_from_host_header(host: Option<&Uri>) -> Option<Principal> {
    host.and_then(|host| resolve_canister_id_from_url(host))
        .or(None)
}

fn resolve_canister_id_from_url(uri: &Uri) -> Option<Principal> {
    if let Some(host) = uri.host() {
        return resolve_canister_id_from_hostname(&String::from(host));
    }

    None
}

pub fn resolve_canister_id(request_uri: &Uri, host_uri: Option<&Uri>) -> Option<Principal> {
    resolve_canister_id_from_url(request_uri)
        .or_else(|| resolve_canister_id_from_host_header(host_uri))
        .or_else(|| resolve_canister_id_from_query_params(request_uri))
}

#[cfg(test)]
mod tests {
    use super::*;

    static CANISTER_ID: &str = "r7inp-6aaaa-aaaaa-aaabq-cai";

    macro_rules! resolve_canister_id_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (request_uri, host_uri) = $value;

                let principal = Principal::from_text(CANISTER_ID).expect("Failed to create principal");
                let request_uri = request_uri.parse::<Uri>().expect("Failed to create request URI");
                let host_uri = host_uri.and_then(|host_uri| host_uri.parse::<Uri>().ok());

                let result = resolve_canister_id(&request_uri, host_uri.as_ref()).expect("Failed to resolve canister ID");

                assert_eq!(result, principal);
            }
        )*
        }
    }

    resolve_canister_id_tests! {
        resolve_canister_id_from_query_params: (format!("https://ic0.app?canisterId={}", CANISTER_ID), None::<String>),
        resolve_canister_id_from_hostname: (format!("https://{}.ic0.dev", CANISTER_ID), None::<String>),
        resolve_canister_id_from_hostname_with_prefix_subdomain: (format!("https://app.{}.ic0.dev", CANISTER_ID), None::<String>),
        resolve_canister_id_from_hostname_with_suffix_subdomain: (format!("https://{}.app.ic0.dev", CANISTER_ID), None::<String>),
        resolve_canister_id_from_host_header: ("/api/v2/status", Some(format!("https://{}.ic0.dev", CANISTER_ID))),
    }
}
