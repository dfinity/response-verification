use crate::{
    certificate::{create_certificate_tree, create_delegation_tree},
    encoding::{leb_encode_timestamp, serialize_to_cbor},
    error::{CertificationTestError, CertificationTestResult},
    signature::{generate_keypair, get_tree_signature, KeyPair},
    tree::get_mixed_hash_tree,
};
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_types::{
    crypto::CombinedThresholdSig,
    messages::{Blob, Certificate, CertificateDelegation},
    CanisterId, PrincipalId, SubnetId,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

const DEFAULT_CERTIFICATE_TIME: u128 = 1651142233000005031;

#[derive(Debug, Clone)]
pub struct CertificateData {
    pub certificate: Certificate,

    pub root_key: Vec<u8>,

    pub cbor_encoded_certificate: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanisterIdRange {
    pub low: u64,
    pub high: u64,
}

#[derive(Debug, Clone)]
struct SubnetData {
    subnet_id: SubnetId,
    canister_id_ranges: Vec<(CanisterId, CanisterId)>,
}

#[derive(Debug, Clone)]
pub struct CanisterData {
    canister_id: CanisterId,
    certified_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CertificateBuilder {
    time: Option<u128>,
    canister: Option<CanisterData>,
    subnet: Option<SubnetData>,
    signature: Option<Blob>,
    custom_tree: Option<LabeledTree<Vec<u8>>>,
}

impl CertificateBuilder {
    pub fn new(
        canister_id: &str,
        certified_data: &[u8],
    ) -> CertificationTestResult<CertificateBuilder> {
        let canister_id = CanisterId::from_str(canister_id)
            .map_err(|_| CertificationTestError::CanisterIdParsingFailed)?;

        Ok(CertificateBuilder {
            time: None,
            canister: Some(CanisterData {
                canister_id,
                certified_data: certified_data.to_vec(),
            }),
            subnet: None,
            signature: None,
            custom_tree: None,
        })
    }

    pub fn from_custom_tree(custom_tree: LabeledTree<Vec<u8>>) -> Self {
        CertificateBuilder {
            time: None,
            canister: None,
            subnet: None,
            signature: None,
            custom_tree: Some(custom_tree),
        }
    }

    pub fn with_delegation(
        &mut self,
        subnet_id: u64,
        canister_id_ranges: Vec<(u64, u64)>,
    ) -> &mut Self {
        let canister_id_ranges = canister_id_ranges
            .into_iter()
            .map(|(low, high)| (CanisterId::from_u64(low), CanisterId::from_u64(high)))
            .collect();

        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(subnet_id));

        self.subnet = Some(SubnetData {
            subnet_id,
            canister_id_ranges,
        });

        self
    }

    pub fn with_time(&mut self, time: u128) -> &mut Self {
        self.time = Some(time);

        self
    }

    pub fn with_invalid_signature(&mut self) -> &mut Self {
        let signature =
            CombinedThresholdSig(b"invalid sig -----padding to get to 48 bytes-----".to_vec());
        self.signature = Some(Blob(signature.0));

        self
    }

    pub fn build(&self) -> CertificationTestResult<CertificateData> {
        let time = self.time.unwrap_or(DEFAULT_CERTIFICATE_TIME);
        let encoded_time = leb_encode_timestamp(time)?;

        let tree = (match (&self.custom_tree, &self.canister) {
            (Some(custom_tree), None) => Ok(custom_tree.clone()),
            (None, Some(canister)) => Ok(create_certificate_tree(
                &canister.canister_id,
                &canister.certified_data,
                &encoded_time,
            )),
            (Some(_), Some(_)) => {
                Err(CertificationTestError::BothCanisterParamsAndCustomTreeProvided)
            }
            (None, None) => Err(CertificationTestError::CanisterParamsOrCustomTreeRequired),
        })?;

        let (keypair, tree, signature) = build_certificate(&tree)?;
        let delegation = None;
        let delegation_data = self.build_delegation(&keypair, &encoded_time)?;
        let signature = self.signature.as_ref().unwrap_or(&signature);

        if let Some((delegation, keypair)) = delegation_data {
            let certificate = Certificate {
                tree,
                signature: signature.clone(),
                delegation: Some(delegation),
            };
            let certificate_cbor = serialize_to_cbor(&certificate);

            return Ok(CertificateData {
                certificate,
                root_key: keypair.public_key,
                cbor_encoded_certificate: certificate_cbor,
            });
        };

        let certificate = Certificate {
            tree,
            signature: signature.clone(),
            delegation,
        };

        let certificate_cbor = serialize_to_cbor(&certificate);

        Ok(CertificateData {
            certificate,
            root_key: keypair.public_key,
            cbor_encoded_certificate: certificate_cbor,
        })
    }

    fn build_delegation(
        &self,
        delegatee_keypair: &KeyPair,
        encoded_time: &[u8],
    ) -> CertificationTestResult<Option<(CertificateDelegation, KeyPair)>> {
        if let Some(subnet) = &self.subnet {
            let tree = create_delegation_tree(
                &delegatee_keypair.public_key,
                encoded_time,
                &subnet.subnet_id,
                &subnet.canister_id_ranges,
            )?;
            let (keypair, tree, signature) = build_certificate(&tree)?;
            let certificate = Certificate {
                tree,
                signature,
                delegation: None,
            };

            return Ok(Some((
                CertificateDelegation {
                    certificate: Blob(serialize_to_cbor(&certificate)),
                    subnet_id: Blob(subnet.subnet_id.get().to_vec()),
                },
                keypair,
            )));
        }

        Ok(None)
    }
}

fn build_certificate(
    tree: &LabeledTree<Vec<u8>>,
) -> CertificationTestResult<(KeyPair, MixedHashTree, Blob)> {
    let keypair = generate_keypair()?;
    let tree = get_mixed_hash_tree(tree)?;
    let signature = get_tree_signature(&tree, &keypair.private_key)?;

    Ok((keypair, tree, signature))
}
