import {
  Cbor,
  Certificate,
  type HashTree,
  reconstruct,
  uint8Equals,
  lookupResultToBuffer,
} from '@icp-sdk/core/agent';
import { Principal } from '@icp-sdk/core/principal';
import { PipeArrayBuffer, lebDecode } from '@icp-sdk/core/candid';
import { CertificateTimeError, CertificateVerificationError } from './error';

export interface VerifyCertificationParams {
  canisterId: Principal;
  encodedCertificate: Uint8Array;
  encodedTree: Uint8Array;
  rootKey: Uint8Array;
  maxCertificateTimeOffsetMs: number;
}

export async function verifyCertification({
  canisterId,
  encodedCertificate,
  encodedTree,
  rootKey,
  maxCertificateTimeOffsetMs,
}: VerifyCertificationParams): Promise<HashTree> {
  const nowMs = Date.now();
  const certificate = await Certificate.create({
    certificate: encodedCertificate,
    principal: { canisterId },
    rootKey,
    // The built-in check bounds certificate time in the future by a hardcoded
    // 5 minutes, which would override a wider `maxCertificateTimeOffsetMs`.
    // `validateCertificateTime` below is the authority instead.
    disableTimeVerification: true,
  });
  const tree = Cbor.decode<HashTree>(encodedTree);

  validateCertificateTime(certificate, maxCertificateTimeOffsetMs, nowMs);
  await validateTree(tree, certificate, canisterId);

  return tree;
}

function validateCertificateTime(
  certificate: Certificate,
  maxCertificateTimeOffsetMs: number,
  nowMs: number,
): void {
  const timeBuf = lookupResultToBuffer(certificate.lookup_path(['time']));
  if (!timeBuf) {
    throw new CertificateTimeError('Could not find time in the certificate.');
  }
  const certificateTimeNs = lebDecode(new PipeArrayBuffer(timeBuf));
  const certificateTimeMs = Number(certificateTimeNs / BigInt(1_000_000));

  if (certificateTimeMs - maxCertificateTimeOffsetMs > nowMs) {
    throw new CertificateTimeError(
      `Invalid certificate: time ${certificateTimeMs} is too far in the future (current time: ${nowMs})`,
    );
  }

  if (certificateTimeMs + maxCertificateTimeOffsetMs < nowMs) {
    throw new CertificateTimeError(
      `Invalid certificate: time ${certificateTimeMs} is too far in the past (current time: ${nowMs})`,
    );
  }
}

async function validateTree(
  tree: HashTree,
  certificate: Certificate,
  canisterId: Principal,
): Promise<void> {
  const treeRootHash = await reconstruct(tree);
  const certifiedData = lookupResultToBuffer(
    certificate.lookup_path([
      'canister',
      canisterId.toUint8Array(),
      'certified_data',
    ]),
  );

  if (!certifiedData) {
    throw new CertificateVerificationError(
      'Could not find certified data in the certificate.',
    );
  }

  if (!uint8Equals(certifiedData, treeRootHash)) {
    throw new CertificateVerificationError(
      'Tree root hash did not match the certified data in the certificate.',
    );
  }
}
