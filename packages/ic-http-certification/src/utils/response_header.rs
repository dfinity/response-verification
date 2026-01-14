use crate::{HttpResponse, CERTIFICATE_HEADER_NAME};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ic_certification::HashTree;
use serde::Serialize;

/// Adds the [`IC-Certificate` header](https://internetcomputer.org/docs/references/http-gateway-protocol-spec/#the-certificate-header)
/// to a given [`HttpResponse`]. This header is used by the HTTP Gateway to verify the authenticity of query call responses made to the
/// `http_request` method of the target canister.
///
/// # Arguments
///
/// * `data_certificate` - A certificate used by the HTTP Gateway to verify a response.
///   Retrieved using `ic_cdk::api::data_certificate`. This value is not validated by this function
///   and is expected to be a valid certificate. The function will not fail if the certificate is invalid,
///   but verification of the certificate by the HTTP Gateway will fail.
/// * `response` - The [`HttpResponse`] to add the certificate header to.
///   Created using [`HttpResponse::builder()`](crate::HttpResponse::builder).
/// * `witness` - A pruned merkle tree revealing the relevant certification for the current response.
///   Created using [`HttpCertificationTree::witness()`](crate::HttpCertificationTree::witness).
///   The witness is not validated to be correct for the given response, and the function will not fail
///   if the witness is invalid. The HTTP Gateway will fail to verify the response if the witness is invalid.
/// * `expr_path` - An expression path for the current response informing the HTTP Gateway where the
///   relevant certification is present in the merkle tree. Created using
///   [`HttpCertificationPath::to_expr_path()`](crate::HttpCertificationPath::to_expr_path). The expression path
///   is not validated to be correct for the given response, and the function will not fail if the expression path is invalid.
///
/// # Examples
///
/// ```
/// use ic_http_certification::{HttpCertification, HttpRequest, HttpResponse, DefaultCelBuilder, DefaultResponseCertification, HttpCertificationTree, HttpCertificationTreeEntry, HttpCertificationPath, CERTIFICATE_EXPRESSION_HEADER_NAME, CERTIFICATE_HEADER_NAME, utils::add_v2_certificate_header};
///
/// let cel_expr = DefaultCelBuilder::full_certification().build();
///
/// let request = HttpRequest::get("/index.html?foo=a&bar=b&baz=c").build();
///
/// let mut response = HttpResponse::builder()
///     .with_headers(vec![(CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_expr.to_string())])
///     .build();
///
/// let request_url = "/example.json";
/// let path = HttpCertificationPath::exact(request_url);
/// let expr_path = path.to_expr_path();
///
/// let certification = HttpCertification::full(&cel_expr, &request, &response, None).unwrap();
/// let entry = HttpCertificationTreeEntry::new(&path, &certification);
///
/// let mut http_certification_tree = HttpCertificationTree::default();
/// http_certification_tree.insert(&entry);
///
/// // this should normally be retrieved using `ic_cdk::api::data_certificate()`.
/// let data_certificate = vec![1, 2, 3];
///
/// let witness = http_certification_tree.witness(&entry, request_url).unwrap();
/// add_v2_certificate_header(
///     &data_certificate,
///     &mut response,
///     &witness,
///     &expr_path
/// );
///
/// assert_eq!(
///     response.headers(),
///     vec![
///         (CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_expr.to_string()),
///         (
///             CERTIFICATE_HEADER_NAME.to_string(),
///             "certificate=:AQID:, tree=:2dn3gwJJaHR0cF9leHBygwJMZXhhbXBsZS5qc29ugwJDPCQ+gwJYIFJ2k+R/YYbgGPADidRdRwDurH06HXACVHlTIVrv1q4WgwJYIGvHTtoVXrGXb4aD1BvH+OW26d0CtLUdA43LP+42N6xpgwJYIM7zUx3VibIaHEUF14Kx813l3Xlilg43Y5uGaABAA/i9ggNA:, expr_path=:2dn3g2lodHRwX2V4cHJsZXhhbXBsZS5qc29uYzwkPg==:, version=2".to_string(),
///         ),
///     ]
/// );
/// ```
pub fn add_v2_certificate_header(
    data_certificate: &[u8],
    response: &mut HttpResponse,
    witness: &HashTree,
    expr_path: &[String],
) {
    let witness = cbor_encode(witness);
    let expr_path = cbor_encode(&expr_path);

    response.add_header((
        CERTIFICATE_HEADER_NAME.to_string(),
        format!(
            "certificate=:{}:, tree=:{}:, expr_path=:{}:, version=2",
            BASE64.encode(data_certificate),
            BASE64.encode(witness),
            BASE64.encode(expr_path)
        ),
    ));
}

fn cbor_encode(value: &impl Serialize) -> Vec<u8> {
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer
        .self_describe()
        .expect("Failed to self describe CBOR");
    value
        .serialize(&mut serializer)
        .expect("Failed to serialize value");
    serializer.into_inner()
}
