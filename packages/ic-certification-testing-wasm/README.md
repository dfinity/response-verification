# Certification Testing

[Certificate verification](https://internetcomputer.org/docs/references/ic-interface-spec#canister-signatures) on the [Internet Computer](https://dfinity.org) is the process of verifying that a canister's response to a [query call](https://internetcomputer.org/docs/references/ic-interface-spec#http-query) has gone through consensus with other replicas hosting the same canister.

This package provides a set of utilities to create these certificates for the purpose of testing in any Javascript client with `wasm` support that may need to verify them.

## Usage

First, a hash tree must be created containing the data that needs to be certified. This can be done using the [@icp-sdk/core](https://www.npmjs.com/package/@icp-sdk/core) library. The root hash of this tree is then used to create the certificate.

The [@dfinity/certificate-verification](https://www.npmjs.com/package/@dfinity/certificate-verification) library can then be used to decode the certificate and verify it.

```typescript
import { describe, expect, it } from 'vitest';
import {
  type HashTree,
  type NodeLabel,
  type NodeValue,
  NodeType,
  reconstruct,
  Cbor,
} from '@icp-sdk/core/agent';
import { CertificateBuilder } from '@dfinity/certification-testing';
import { verifyCertification } from '@dfinity/certificate-verification';
import { Principal } from '@icp-sdk/core/principal';
import { createHash } from 'node:crypto';

const userId = '1234';

const username = 'testuser';
const usernameHash = new Uint8Array(
  createHash('sha256').update(username).digest(),
);

const hashTree: HashTree = [
  NodeType.Labeled,
  new Uint8Array(Buffer.from(userId)) as NodeLabel,
  [NodeType.Leaf, usernameHash as NodeValue],
];
const rootHash = await reconstruct(hashTree);
const cborEncodedTree = Cbor.encode(hashTree);

const canisterId = Principal.fromUint8Array(
  new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1]),
);
const time = BigInt(Date.now());
const MAX_CERT_TIME_OFFSET_MS = 300_000;

let certificate = new CertificateBuilder(canisterId.toString(), rootHash)
  .withTime(time)
  .build();

const decodedHashTree = await verifyCertification({
  canisterId,
  encodedCertificate: certificate.cborEncodedCertificate,
  encodedTree: cborEncodedTree,
  maxCertificateTimeOffsetMs: MAX_CERT_TIME_OFFSET_MS,
  rootKey: certificate.rootKey,
});
expect(decodedHashTree).toEqual(hashTree);
```
