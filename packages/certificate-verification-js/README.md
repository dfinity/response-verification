# Certificate Verification

[Certificate verification](https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures) on the [Internet Computer](https://dfinity.org) is the process of verifying that a canister's response to a [query call](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-query) has gone through consensus with other replicas hosting the same canister.

This package partially encapsulates the protocol for such verification. It performs the following actions:

- [Decoding](https://internetcomputer.org/docs/current/references/ic-interface-spec#certification-encoding) of the certificate and the canister provided tree
- Verification of the certificate's [root of trust](https://internetcomputer.org/docs/current/references/ic-interface-spec#root-of-trust)
- Verification of the certificate's [delegations](https://internetcomputer.org/docs/current/references/ic-interface-spec#certification-delegation) (if any)
- Decoding of a canister provided merkle tree
- Verification that the canister provided merkle tree's root hash matches the canister's [certified data](https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api-certified-data)

## Usage

In the following example, `canister` is an actor created with `@dfinity/agent-js` for a canister with the following candid:

```candid
type certified_response = record {
  "data" : nat32;
  "certificate" : blob;
  "witness" : blob;
};

service : {
  "get_data" : () -> (certified_response) query;
};
```

Check [ic-certification](https://docs.rs/ic_certification/latest/ic_certification/) for details on how to create `certificate` and `witness` inside your canister.

`calculateDataHash` is a userland provided function that can calculate the hash of the data returned from the canister. This must be calculated in the same way on the canister and the frontend.

```javascript
const { data, certificate, witness } = await canister.get_data();

const tree = await verifyCertification({
  canisterId: Principal.fromText(canisterId),
  encodedCertificate: new Uint8Array(certificate).buffer,
  encodedTree: new Uint8Array(witness).buffer,
  rootKey: agent.rootKey,
  maxCertificateTimeOffsetMs: 50000,
});

const treeDataHash = lookup_path(['count'], tree);
const responseDataHash = calculateDataHash(data);

if (treeDataHash !== responseDataHash) {
  // The data returned from the canister does not match the certified data.
}
```

## Examples

See the [certified counter example](https://github.com/dfinity/response-verification/tree/main/examples/certification/certified-counter) for a full e2e example of how to create a certification and verify it using this package.
