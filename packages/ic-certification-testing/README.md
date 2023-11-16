# Certification Testing

[Certificate verification](https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures) on the [Internet Computer](https://dfinity.org) is the process of verifying that a canister's response to a [query call](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-query) has gone through consensus with other replicas hosting the same canister.

This package provides a set of utilities to create these certificates for the purpose of testing in any Rust client that may need to verify them.

## Usage

First, a hash tree must be created containing the data that needs to be certified. This can be done using the [ic-certification](https://docs.rs/ic_certification/latest/ic_certification/) library. The root hash of this tree is then used to create the certificate.

The [ic-certification](https://docs.rs/ic-certification/latest/ic_certification/), [ic-cbor](https://docs.rs/ic-cbor/latest/ic_cbor/) and [ic-certificate-verification](https://docs.rs/ic-certificate-verification/latest/ic_certificate_verification/) libraries can then be used to decode the certificate and verify it.

```rust
use ic_certification_testing::{CertificateBuilder, CertificateData};
use ic_cbor::CertificateToCbor;
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{Certificate, AsHashTree, RbTree};
use ic_types::CanisterId;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type Hash = [u8; 32];

fn hash<T>(data: T) -> Hash
where
  T: AsRef<[u8]>,
{
  let mut hasher = Sha256::new();
  hasher.update(data);
  hasher.finalize().into()
}

fn get_timestamp() -> u128 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_nanos()
}

fn usage_example() {
  let canister_id = CanisterId::from_u64(42);
  let mut rb_tree = RbTree::<&'static str, Hash>::new();

  let data_key = "key1";
  let data_hash = hash("value1");
  rb_tree.insert(data_key, data_hash);

  let certified_data = rb_tree.root_hash();

  let current_timestamp = get_timestamp();

  let mut certificate_builder =
      CertificateBuilder::new(&canister_id.get().0.to_text(), &certified_data)
          .expect("Failed to parse canister id");

  let CertificateData {
    cbor_encoded_certificate,
    root_key,
    certificate: _,
  } = certificate_builder
    .with_time(current_timestamp)
    .build()
    .expect("Invalid certificate params provided");

  let certificate = Certificate::from_cbor(&cbor_encoded_certificate)
    .expect("Failed to deserialize certificate");

  certificate
    .verify(&canister_id.get().to_vec(), &root_key)
    .expect("Failed to verify certificate");
}
```
