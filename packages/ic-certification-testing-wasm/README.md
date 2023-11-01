# Certification Testing

[Certificate verification](https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures) on the [Internet Computer](https://dfinity.org) is the process of verifying that a canister's response to a [query call](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-query) has gone through consensus with other replicas hosting the same canister.

This package provides a set of utilities to create these certificates for the purpose of testing in any Javascript client with `wasm` support that may need to verify them.

## Usage

First, a hash tree must be created containing the data that needs to be certified. This can be done using the [@dfinity/agent](https://www.npmjs.com/package/@dfinity/agent) library. The root hash of this tree is then used to create the certificate.

The [@dfinity/certificate-verification](https://www.npmjs.com/package/@dfinity/certificate-verification) library can then be used to decode the certificate and verify it.

```typescript
import { describe, expect, it } from 'vitest';
import { HashTree, reconstruct, Cbor } from '@dfinity/agent';
import { CertificateBuilder } from '@dfinity/certification-testing';
import { verifyCertification } from '@dfinity/certificate-verification';
import { Principal } from '@dfinity/principal';
import { createHash, webcrypto } from 'node:crypto';

globalThis.crypto = webcrypto as Crypto;

const userId = '1234';

const username = 'testuser';
const usernameHash = new Uint8Array(
  createHash('sha256').update(username).digest(),
);

const hashTree: HashTree = [
  2,
  new Uint8Array(Buffer.from(userId)),
  [3, usernameHash],
];
const rootHash = await reconstruct(hashTree);
const cborEncodedTree = Cbor.encode(hashTree);

const canisterId = Principal.fromUint8Array(
  new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1]),
);
const time = BigInt(Date.now());
const MAX_CERT_TIME_OFFSET_MS = 300_000;

let certificate = new CertificateBuilder(
  canisterId.toString(),
  new Uint8Array(rootHash),
)
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
