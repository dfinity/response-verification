use crate::{
    certificate::{create_certificate_tree, create_delegation_tree},
    encoding::{leb_encode_timestamp, serialize_to_cbor},
    error::{CertificationTestError, CertificationTestResult},
    signature::{generate_keypair, get_tree_signature, KeyPair},
    tree::get_mixed_hash_tree,
};
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_types::{
    messages::{Blob, Certificate, CertificateDelegation},
    CanisterId, PrincipalId, SubnetId,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

const DEFAULT_CERTIFICATE_TIME: u128 = 1651142233000005031;

#[wasm_bindgen(inspectable, getter_with_clone)]
#[derive(Debug, Clone)]
pub struct CertificateData {
    #[wasm_bindgen]
    pub certificate: JsValue,

    #[wasm_bindgen(js_name = rootKey)]
    pub root_key: Vec<u8>,

    #[wasm_bindgen(js_name = cborEncodedCertificate)]
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
struct CanisterData {
    canister_id: CanisterId,
    certified_data: Vec<u8>,
}

#[wasm_bindgen(inspectable, getter_with_clone)]
#[derive(Debug, Clone)]
pub struct CertificateBuilder {
    time: Option<u128>,
    canister: CanisterData,
    subnet: Option<SubnetData>,
}

#[wasm_bindgen]
impl CertificateBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        canister_id: &str,
        certified_data: &[u8],
    ) -> CertificationTestResult<CertificateBuilder> {
        console_error_panic_hook::set_once();
        log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Info);

        let canister_id = CanisterId::from_str(canister_id)
            .map_err(|_| CertificationTestError::CanisterIdParsingFailed)?;

        Ok(CertificateBuilder {
            time: None,
            canister: CanisterData {
                canister_id,
                certified_data: certified_data.to_vec(),
            },
            subnet: None,
        })
    }

    #[wasm_bindgen(js_name = withDelegation)]
    pub fn with_delegation(
        mut self,
        subnet_id: u64,
        canister_id_ranges: Vec<JsValue>,
    ) -> CertificationTestResult<CertificateBuilder> {
        let canister_id_ranges = canister_id_ranges
            .into_iter()
            .map(|v| serde_wasm_bindgen::from_value::<CanisterIdRange>(v))
            .map(|v| v.map(|v| (CanisterId::from_u64(v.low), CanisterId::from_u64(v.high))))
            .collect::<Result<_, _>>()?;

        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(subnet_id));

        self.subnet = Some(SubnetData {
            subnet_id,
            canister_id_ranges,
        });

        Ok(self)
    }

    #[wasm_bindgen(js_name = withTime)]
    pub fn with_time(mut self, time: u64) -> Self {
        self.time = Some(u128::from(time) * 1_000_000);

        self
    }

    pub fn build(self) -> CertificationTestResult<CertificateData> {
        let time = self.time.unwrap_or(DEFAULT_CERTIFICATE_TIME);
        let encoded_time = leb_encode_timestamp(time)?;

        let tree = create_certificate_tree(
            &self.canister.canister_id,
            &self.canister.certified_data,
            &encoded_time,
        );
        let (keypair, tree, signature) = build_certificate(&tree)?;
        let delegation = None;
        let delegation_data = self.build_delegation(&keypair, &encoded_time)?;

        if let Some((delegation, keypair)) = delegation_data {
            let certificate = Certificate {
                tree,
                signature,
                delegation: Some(delegation),
            };
            let certificate_json = serde_wasm_bindgen::to_value(&certificate)?;
            let certificate_cbor = serialize_to_cbor(&certificate);

            return Ok(CertificateData {
                certificate: certificate_json,
                root_key: keypair.public_key,
                cbor_encoded_certificate: certificate_cbor,
            });
        };

        let certificate = Certificate {
            tree,
            signature,
            delegation,
        };
        let certificate_json = serde_wasm_bindgen::to_value(&certificate)?;
        let certificate_cbor = serialize_to_cbor(&certificate);

        return Ok(CertificateData {
            certificate: certificate_json,
            root_key: keypair.public_key,
            cbor_encoded_certificate: certificate_cbor,
        });
    }

    fn build_delegation(
        self,
        delegatee_keypair: &KeyPair,
        encoded_time: &[u8],
    ) -> CertificationTestResult<Option<(CertificateDelegation, KeyPair)>> {
        if let Some(subnet) = self.subnet {
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
    let tree = get_mixed_hash_tree(&tree)?;
    let signature = get_tree_signature(&tree, &keypair.private_key)?;

    Ok((keypair, tree, signature))
}
