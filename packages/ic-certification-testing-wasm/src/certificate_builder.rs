use ic_certification_testing::{
    CanisterIdRange, CertificateBuilder as CertificateBuilderImpl, CertificationTestResult,
};
use std::borrow::BorrowMut;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone)]
#[wasm_bindgen(inspectable, getter_with_clone)]
pub struct CertificateData {
    pub certificate: JsValue,

    #[wasm_bindgen(js_name = rootKey)]
    pub root_key: Vec<u8>,

    #[wasm_bindgen(js_name = cborEncodedCertificate)]
    pub cbor_encoded_certificate: Vec<u8>,
}

#[wasm_bindgen]
pub struct CertificateBuilder {
    builder: CertificateBuilderImpl,
}

#[wasm_bindgen]
impl CertificateBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        canister_id: &str,
        certified_data: &[u8],
    ) -> CertificationTestResult<CertificateBuilder> {
        CertificateBuilderImpl::new(canister_id, certified_data)
            .map(|builder| CertificateBuilder { builder })
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
            .map(|v| v.map(|v| (v.low, v.high)))
            .collect::<Result<_, _>>()?;

        self.builder.with_delegation(subnet_id, canister_id_ranges);

        Ok(self)
    }

    #[wasm_bindgen(js_name = withTime)]
    pub fn with_time_js(mut self, time: u64) -> Self {
        self.builder
            .borrow_mut()
            .with_time(u128::from(time) * 1_000_000);

        self
    }

    #[wasm_bindgen(js_name = withInvalidSignature)]
    pub fn with_invalid_signature(mut self) -> Self {
        self.builder.with_invalid_signature();

        self
    }

    pub fn build(self) -> CertificationTestResult<CertificateData> {
        let certificate_data = self.builder.build()?;

        Ok(CertificateData {
            certificate: serde_wasm_bindgen::to_value(&certificate_data.certificate)?,
            root_key: certificate_data.root_key,
            cbor_encoded_certificate: certificate_data.cbor_encoded_certificate,
        })
    }
}
