use crate::CertificateVerificationError;
use ic_verify_bls_signature::verify_bls_signature;

#[cfg(feature = "cached")]
mod signature_cache;

#[cfg(test)]
mod reproducible_rng;

#[cfg(test)]
mod tests;

#[cfg(feature = "cached")]
pub fn verify_signature(
    pk: &[u8],
    sig: &[u8],
    msg: &[u8],
) -> Result<(), CertificateVerificationError> {
    use self::signature_cache::{SignatureCache, SignatureCacheEntry};

    let entry = SignatureCacheEntry::new(pk, sig, msg);

    if SignatureCache::global().contains(&entry) {
        return Ok(());
    }

    if verify_bls_signature(sig, msg, pk).is_err() {
        return Err(CertificateVerificationError::SignatureVerificationFailed);
    }

    SignatureCache::global().insert(&entry);
    Ok(())
}

#[cfg(not(feature = "cached"))]
pub fn verify_signature(
    pk: &[u8],
    sig: &[u8],
    msg: &[u8],
) -> Result<(), CertificateVerificationError> {
    verify_bls_signature(sig, msg, pk).map_err(|_| CertificateVerificationError::SignatureVerificationFailed)
}
