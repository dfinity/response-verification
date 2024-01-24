use crate::error::{CertificationTestError, CertificationTestResult};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::{
    api::{combined_public_key, generate_threshold_key, public_key_to_der, sign_message},
    types::SecretKeyBytes,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::{
    bls12_381::PublicKeyBytes, CspThresholdSigPublicKey,
};
use ic_crypto_tree_hash::MixedHashTree;
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{
        threshold_sig::ThresholdSigPublicKey, CombinedThresholdSig, CombinedThresholdSigOf,
        CryptoHash, Signable,
    },
    messages::Blob,
    CryptoHashOfPartialState, NumberOfNodes,
};
use rand::{thread_rng, Rng};

#[derive(Debug, Clone)]
pub(crate) struct KeyPair {
    pub(crate) public_key: Vec<u8>,
    pub(crate) private_key: SecretKeyBytes,
}

pub(crate) fn generate_keypair() -> CertificationTestResult<KeyPair> {
    let mut seed: [u8; 32] = [0; 32];
    thread_rng().fill(&mut seed);

    let (public_coefficients, secret_key_bytes) = generate_threshold_key(
        Seed::from_bytes(&seed),
        NumberOfNodes::new(1),
        NumberOfNodes::new(1),
    )
    .unwrap();

    let private_key = secret_key_bytes.first().unwrap().clone();
    let public_key = ThresholdSigPublicKey::from(CspThresholdSigPublicKey::from(
        combined_public_key(&public_coefficients).unwrap(),
    ));

    let public_key = public_key_to_der(PublicKeyBytes(public_key.into_bytes()))
        .map_err(|_| CertificationTestError::PublicKeyEncodingFailed)?;

    Ok(KeyPair {
        public_key,
        private_key,
    })
}

pub(crate) fn get_tree_signature(
    mixed_hash_tree: &MixedHashTree,
    private_key: &SecretKeyBytes,
) -> CertificationTestResult<Blob> {
    let root_hash = CryptoHashOfPartialState::from(CryptoHash(mixed_hash_tree.digest().to_vec()));

    let signature = sign_message(
        CertificationContent::new(root_hash)
            .as_signed_bytes()
            .as_slice(),
        private_key,
    )?;
    let signature: CombinedThresholdSigOf<CombinedThresholdSig> =
        CombinedThresholdSigOf::from(CombinedThresholdSig(signature.0.to_vec()));

    Ok(Blob(signature.get().0))
}
