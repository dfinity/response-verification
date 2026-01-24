use self::signature_cache::{SignatureCache, SignatureCacheEntry};
use crate::CertificateVerificationError;
use ic_verify_bls_signature::verify_bls_signature;

mod signature_cache;

#[cfg(test)]
mod reproducible_rng;

#[cfg(test)]
mod tests;

pub fn verify_signature(
    pk: &[u8],
    sig: &[u8],
    msg: &[u8],
) -> Result<(), CertificateVerificationError> {
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
