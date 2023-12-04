use super::{body::decode_body, certificate_header::CertificateHeader};
use crate::{
    cel,
    error::{ResponseVerificationError, ResponseVerificationResult},
    hash,
    hash::filter_response_headers,
    types::{Certification, VerificationInfo, VerifiedResponse},
    validation::{
        validate_body, validate_expr_hash, validate_expr_path, validate_hashes, validate_tree,
    },
};
use ic_cbor::{parse_cbor_string_array, CertificateToCbor, HashTreeToCbor};
use ic_certificate_verification::{validate_certificate_time, VerifyCertificate};
use ic_certification::{hash_tree::Hash, Certificate, HashTree};
use ic_http_certification::{HttpRequest, HttpResponse};
use ic_representation_independent_hash::hash;

/// The minimum verification version supported by this package.
pub const MIN_VERIFICATION_VERSION: u8 = 1;
/// The maximum verification version supported by this package.
pub const MAX_VERIFICATION_VERSION: u8 = 2;

/// The primary entry point for verifying a request and response pair. This will verify the response
/// with respect to the request, according the [Response Verification Spec]().
pub fn verify_request_response_pair(
    request: HttpRequest,
    response: HttpResponse,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    ic_public_key: &[u8],
    min_requested_verification_version: u8,
) -> ResponseVerificationResult<VerificationInfo> {
    let mut encoding: Option<String> = None;
    let mut tree: Option<HashTree> = None;
    let mut certificate: Option<Certificate> = None;
    let mut version = MIN_VERIFICATION_VERSION;
    let mut expr_path: Option<Vec<String>> = None;
    let mut certification: Option<Certification> = None;
    let mut expr_hash: Option<Hash> = None;

    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("Ic-Certificate") {
            let certificate_header = CertificateHeader::from(value.as_str())?;

            tree = certificate_header
                .tree
                .map(|tree| HashTree::from_cbor(&tree))
                .transpose()?;

            certificate = certificate_header
                .certificate
                .map(|certificate| Certificate::from_cbor(&certificate))
                .transpose()?;

            version = certificate_header
                .version
                .unwrap_or(MIN_VERIFICATION_VERSION);

            expr_path = certificate_header
                .expr_path
                .map(|expr_path| parse_cbor_string_array(&expr_path))
                .transpose()?;
        }

        if name.eq_ignore_ascii_case("Ic-CertificateExpression") {
            certification = cel::cel_to_certification(value)?;
            expr_hash = Some(hash(value.as_bytes()));
        }

        if name.eq_ignore_ascii_case("Content-Encoding") {
            encoding = Some(value.into());
        }
    }

    if version < min_requested_verification_version {
        return Err(
            ResponseVerificationError::RequestedVerificationVersionMismatch {
                requested_version: version,
                min_requested_verification_version,
            },
        );
    }

    verification(
        version,
        request,
        response,
        canister_id,
        current_time_ns,
        max_cert_time_offset_ns,
        tree,
        certificate,
        encoding,
        expr_path,
        expr_hash,
        certification,
        ic_public_key,
    )
}

fn verification(
    version: u8,
    request: HttpRequest,
    response: HttpResponse,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    tree: Option<HashTree>,
    certificate: Option<Certificate>,
    encoding: Option<String>,
    expr_path: Option<Vec<String>>,
    expr_hash: Option<Hash>,
    certification: Option<Certification>,
    ic_public_key: &[u8],
) -> ResponseVerificationResult<VerificationInfo> {
    match version {
        1 => v1_verification(
            request,
            response,
            canister_id,
            current_time_ns,
            max_cert_time_offset_ns,
            tree,
            certificate,
            encoding,
            ic_public_key,
        ),
        2 => v2_verification(
            request,
            response,
            canister_id,
            current_time_ns,
            max_cert_time_offset_ns,
            tree,
            certificate,
            expr_path,
            expr_hash,
            certification,
            ic_public_key,
        ),
        _ => Err(ResponseVerificationError::UnsupportedVerificationVersion {
            min_supported_version: MIN_VERIFICATION_VERSION,
            max_supported_version: MAX_VERIFICATION_VERSION,
            requested_version: version,
        }),
    }
}

fn v1_verification(
    request: HttpRequest,
    response: HttpResponse,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    tree: Option<HashTree>,
    certificate: Option<Certificate>,
    encoding: Option<String>,
    ic_public_key: &[u8],
) -> ResponseVerificationResult<VerificationInfo> {
    match (tree, certificate) {
        (Some(tree), Some(certificate)) => {
            validate_certificate_time(&certificate, &current_time_ns, &max_cert_time_offset_ns)?;
            certificate.verify(canister_id, ic_public_key)?;

            let request_path = &request.get_path()?;
            let decoded_body = decode_body(&response.body, &encoding)?;
            let decoded_body_sha = hash(decoded_body.as_slice());

            if !validate_tree(canister_id, &certificate, &tree) {
                return Err(ResponseVerificationError::InvalidTree);
            }

            let mut valid_body = validate_body(&tree, request_path, &decoded_body_sha);
            if encoding.is_some() && !valid_body {
                let body_sha = hash(response.body.as_slice());
                valid_body = validate_body(&tree, request_path, &body_sha);
            }

            if !valid_body {
                return Err(ResponseVerificationError::InvalidResponseBody);
            }

            Ok(VerificationInfo {
                response: Some(VerifiedResponse {
                    status_code: None,
                    headers: Vec::new(),
                    body: response.body,
                }),
                verification_version: 1,
            })
        }
        (None, Some(_certificate)) => Err(ResponseVerificationError::MissingTree),
        (Some(_tree), None) => Err(ResponseVerificationError::MissingCertificate),
        _ => Err(ResponseVerificationError::MissingCertification),
    }
}

fn v2_verification(
    request: HttpRequest,
    response: HttpResponse,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    tree: Option<HashTree>,
    certificate: Option<Certificate>,
    expr_path: Option<Vec<String>>,
    expr_hash: Option<Hash>,
    certification: Option<Certification>,
    ic_public_key: &[u8],
) -> ResponseVerificationResult<VerificationInfo> {
    let request_path = request.get_path()?;

    let (expr_path, expr_hash, certificate, tree) = match (expr_path, expr_hash, certificate, tree)
    {
        (Some(expr_path), Some(expr_hash), Some(certificate), Some(tree)) => {
            (expr_path, expr_hash, certificate, tree)
        }
        (Some(_), Some(_), Some(_), None) => return Err(ResponseVerificationError::MissingTree),
        (Some(_), Some(_), None, Some(_)) => {
            return Err(ResponseVerificationError::MissingCertificate)
        }
        (Some(_), None, Some(_), Some(_)) => {
            return Err(ResponseVerificationError::MissingCertificateExpression)
        }
        (None, Some(_), Some(_), Some(_)) => {
            return Err(ResponseVerificationError::MissingCertificateExpressionPath)
        }
        _ => return Err(ResponseVerificationError::MissingCertification),
    };

    validate_certificate_time(&certificate, &current_time_ns, &max_cert_time_offset_ns)?;
    certificate.verify(canister_id, ic_public_key)?;

    if !validate_tree(canister_id, &certificate, &tree) {
        return Err(ResponseVerificationError::InvalidTree);
    }

    if !validate_expr_path(&expr_path, &request_path, &tree) {
        return Err(ResponseVerificationError::InvalidExpressionPath);
    }

    let Some(certification) = certification else {
        return match validate_expr_hash(&expr_path, &expr_hash, &tree).is_some() {
            true => Ok(VerificationInfo {
                response: None,
                verification_version: 2,
            }),
            false => Err(ResponseVerificationError::InvalidExpressionPath)
        };
    };

    let request_hash = certification
        .request_certification
        .as_ref()
        .map(|request_certification| hash::request_hash(&request, request_certification))
        .transpose()?;

    let body_hash = hash(&response.body);
    let response_headers =
        filter_response_headers(&response, &certification.response_certification);
    let response_headers_hash =
        hash::response_headers_hash(&response.status_code.into(), &response_headers);
    let response_hash = hash([response_headers_hash, body_hash].concat().as_slice());

    let are_hashes_valid = validate_hashes(
        &expr_hash,
        &request_hash,
        &response_hash,
        &expr_path,
        &tree,
        &certification,
    );

    match are_hashes_valid {
        true => Ok(VerificationInfo {
            response: Some(VerifiedResponse {
                status_code: Some(response.status_code),
                headers: response_headers.headers,
                body: response.body,
            }),
            verification_version: 2,
        }),
        false => Err(ResponseVerificationError::InvalidResponseHashes),
    }
}
