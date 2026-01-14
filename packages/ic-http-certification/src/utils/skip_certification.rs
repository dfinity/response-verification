use super::add_v2_certificate_header;
use crate::{
    DefaultCelBuilder, Hash, HttpCertificationPath, HttpResponse,
    CERTIFICATE_EXPRESSION_HEADER_NAME,
};
use ic_certification::{hash_tree::leaf, labeled, HashTree};
use ic_representation_independent_hash::hash;

/// Adds the `IC-Certificate` and `IC-Certificate-Expression` headers to a given [`HttpResponse`]. These headers are used by the HTTP Gateway
/// to verify the authenticity of query call responses. In this case, the headers are pre-configured to instruct
/// the HTTP Gateway to skip certification verification in a secure way. Secure in this context means that
/// the decision to skip certification is made by the canister itself, and not by the replica, API boundary nodes
/// or any other intermediate party.
///
/// # Arguments
///
/// * `data_certificate` - A certificate used by the HTTP Gateway to verify a response.
///   Retrieved using `ic_cdk::api::data_certificate`.
/// * `response` - The [`HttpResponse`] to add the certificate header to.
///   Created using [`HttpResponse::builder()`](crate::HttpResponse::builder).
///
/// # Examples
///
/// ```
/// use ic_http_certification::{HttpResponse, DefaultCelBuilder, utils::add_skip_certification_header, CERTIFICATE_EXPRESSION_HEADER_NAME, CERTIFICATE_HEADER_NAME};
///
/// let mut response = HttpResponse::builder().build();
///
/// // this should normally be retrieved using `ic_cdk::api::data_certificate()`.
/// let data_certificate = vec![1, 2, 3];
///
/// add_skip_certification_header(data_certificate, &mut response);
///
/// assert_eq!(
///     response.headers(),
///     vec![
///         (
///             CERTIFICATE_HEADER_NAME.to_string(),
///             "certificate=:AQID:, tree=:2dn3gwJJaHR0cF9leHBygwJDPCo+gwJYIMMautvQsFn51GT9bfTani3Ah659C0BGjTNyJtQTszcjggNA:, expr_path=:2dn3gmlodHRwX2V4cHJjPCo+:, version=2".to_string(),
///         ),
///         (
///             CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(),
///             DefaultCelBuilder::skip_certification().to_string()
///         ),
///     ]
/// );
/// ```
pub fn add_skip_certification_header(data_certificate: Vec<u8>, response: &mut HttpResponse) {
    add_v2_certificate_header(
        &data_certificate,
        response,
        &skip_certification_asset_tree(),
        &HttpCertificationPath::wildcard("").to_expr_path(),
    );

    response.add_header((
        CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(),
        DefaultCelBuilder::skip_certification().to_string(),
    ));
}

/// Returns the hash of the certified data that can be used to instruct HTTP Gateways to skip certification.
///
/// # Examples
///
/// ```ignore
/// use ic_http_certification::utils::skip_certification_certified_data;
/// use ic_cdk::api::set_certified_data;
///
/// let certified_data = skip_certification_certified_data();
///
/// set_certified_data(&certified_data);
/// ```
pub fn skip_certification_certified_data() -> Hash {
    skip_certification_asset_tree().digest()
}

fn skip_certification_asset_tree() -> HashTree {
    let cel_expr_hash = hash(
        DefaultCelBuilder::skip_certification()
            .to_string()
            .as_bytes(),
    );

    labeled(
        "http_expr",
        labeled("<*>", labeled(cel_expr_hash, leaf(vec![]))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_certification_certified_data() {
        let certified_data = skip_certification_certified_data();

        assert_eq!(
            certified_data,
            [
                85, 236, 195, 28, 62, 128, 71, 252, 21, 143, 32, 234, 10, 160, 96, 154, 172, 199,
                181, 126, 6, 234, 64, 220, 65, 134, 2, 114, 167, 214, 66, 145
            ]
        );
    }
}
