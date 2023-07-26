import { describe, expect, it } from 'vitest';
import { HashTree, reconstruct, Cbor } from '@dfinity/agent';
import { CertificateBuilder } from '@dfinity/certification-testing';
import { Principal } from '@dfinity/principal';
import { createHash, webcrypto } from 'node:crypto';
import { verifyCertification } from './index';

globalThis.crypto = webcrypto as Crypto;

describe('verifyCertification', async () => {
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

  it.each([
    {
      scenario: 'with a valid signature',
    },
    {
      withDelegation: true,
      scenario: 'with a delegation',
    },
    {
      timeOverride: BigInt(Date.now() - 10_000),
      scenario: 'with a time in the past',
    },
    {
      withDelegation: true,
      timeOverride: BigInt(Date.now() - 10_000),
      scenario: 'with a delegation and a time in the past',
    },
    {
      timeOverride: BigInt(Date.now() + 10_000),
      scenario: 'with a time in the future',
    },
    {
      withDelegation: true,
      timeOverride: BigInt(Date.now() + 10_000),
      scenario: 'with a delegation and a time in the future',
    },
  ])(
    'should verify a certificate $scenario',
    async ({ withDelegation, timeOverride }) => {
      let certificateBuilder = new CertificateBuilder(
        canisterId.toString(),
        new Uint8Array(rootHash),
      ).withTime(timeOverride ?? time);

      if (withDelegation) {
        certificateBuilder = certificateBuilder.withDelegation(123n, [
          { high: 10, low: 0 },
        ]);
      }

      const certificate = certificateBuilder.build();

      const decodedHashTree = await verifyCertification({
        canisterId,
        encodedCertificate: certificate.cborEncodedCertificate,
        encodedTree: cborEncodedTree,
        maxCertificateTimeOffsetMs: MAX_CERT_TIME_OFFSET_MS,
        rootKey: certificate.rootKey,
      });
      expect(decodedHashTree).toEqual(hashTree);
    },
  );

  it.each([
    {
      withInvalidSignature: true,
      scenario: 'with an invalid signature',
    },
    {
      withInvalidSignature: true,
      withDelegation: true,
      scenario: 'with a delegation and an invalid signature',
    },
    {
      timeOverride: BigInt(Date.now() - MAX_CERT_TIME_OFFSET_MS - 10_000),
      scenario: 'with a time too far in the past',
    },
    {
      withDelegation: true,
      timeOverride: BigInt(Date.now() - MAX_CERT_TIME_OFFSET_MS - 10_000),
      scenario: 'with a delegation a time too far in the past',
    },
    {
      timeOverride: BigInt(Date.now() + MAX_CERT_TIME_OFFSET_MS + 10_000),
      scenario: 'with a time too far in the future',
    },
    {
      withDelegation: true,
      timeOverride: BigInt(Date.now() + MAX_CERT_TIME_OFFSET_MS + 10_000),
      scenario: 'with a delegation a time too far in the future',
    },
    {
      rootHashOverride: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).buffer,
      scenario: 'with a root hash mismatch',
    },
  ])(
    'should fail to verify a certificate $scenario',
    async ({
      withDelegation,
      withInvalidSignature,
      timeOverride,
      rootHashOverride,
    }) => {
      let certificateBuilder = new CertificateBuilder(
        canisterId.toString(),
        new Uint8Array(rootHashOverride ?? rootHash),
      ).withTime(timeOverride ?? time);

      if (withDelegation) {
        certificateBuilder = certificateBuilder.withDelegation(123n, [
          { high: 10, low: 0 },
        ]);
      }

      if (withInvalidSignature) {
        certificateBuilder = certificateBuilder.withInvalidSignature();
      }

      const certificate = certificateBuilder.build();

      await expect(() =>
        verifyCertification({
          canisterId,
          encodedCertificate: certificate.cborEncodedCertificate,
          encodedTree: cborEncodedTree,
          maxCertificateTimeOffsetMs: 5000,
          rootKey: certificate.rootKey,
        }),
      ).rejects.toThrowError();
    },
  );
});
