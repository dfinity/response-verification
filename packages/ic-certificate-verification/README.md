# Certificate Verification

[Certificate verification](https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures) on the [Internet Computer](https://dfinity.org) is the process of verifying that a canister's response to a [query call](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-query) has gone through consensus with other replicas hosting the same canister.

This package partially encapsulates the protocol for such verification. It performs the following actions:

- [Decoding](https://internetcomputer.org/docs/current/references/ic-interface-spec#certification-encoding) of the certificate and the canister provided tree
- Verification of the certificate's [root of trust](https://internetcomputer.org/docs/current/references/ic-interface-spec#root-of-trust)
- Verification of the certificate's [delegations](https://internetcomputer.org/docs/current/references/ic-interface-spec#certification-delegation) (if any)
- Decoding of a canister provided merkle tree
- Verification that the canister provided merkle tree's root hash matches the canister's [certified data](https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api-certified-data)
