import { describe, expect, it } from 'vitest';
import { HashTree, reconstruct, Cbor } from '@dfinity/agent';
import { CertificateBuilder } from '@dfinity/certification-test-utils';
import { Principal } from '@dfinity/principal';
import { createHash, webcrypto } from 'node:crypto';
import { verifyCertification } from './index';

globalThis.crypto = webcrypto as Crypto;

describe('verifyCertification', () => {
  it('should verify a valid certificate with delegation', async () => {
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

    const certificate = new CertificateBuilder(
      canisterId.toString(),
      new Uint8Array(rootHash),
    )
      .withTime(time)
      .withDelegation(123n, [{ high: 10, low: 0 }])
      .build();

    const decodedHashTree = await verifyCertification({
      canisterId,
      encodedCertificate: certificate.cborEncodedCertificate,
      encodedTree: cborEncodedTree,
      maxCertificateTimeOffsetMs: 5000,
      rootKey: certificate.rootKey,
    });
    expect(decodedHashTree).toEqual(hashTree);
  });
});
