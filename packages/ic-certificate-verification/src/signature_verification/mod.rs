use self::signature_cache::{SignatureCache, SignatureCacheEntry};
use crate::CertificateVerificationError;
use miracl_core_bls12381::bls12381::bls::{core_verify, BLS_OK};

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

    let result = core_verify(sig, msg, pk);

    if !matches!(result, BLS_OK) {
        return Err(CertificateVerificationError::SignatureVerificationFailed);
    }

    SignatureCache::global().insert(&entry);
    Ok(())
}
