import {
  Cbor,
  Certificate,
  HashTree,
  reconstruct,
  lookup_path,
  lookupResultToBuffer,
} from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import { PipeArrayBuffer, lebDecode } from '@dfinity/candid';
import { CertificateTimeError, CertificateVerificationError } from './error';

// Helper functions for buffer operations
function uint8Equals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function uint8FromBufLike(buf: ArrayBuffer | Uint8Array): Uint8Array {
  return buf instanceof Uint8Array ? buf : new Uint8Array(buf);
}

export interface VerifyCertificationParams {
  canisterId: Principal;
  encodedCertificate: ArrayBuffer;
  encodedTree: ArrayBuffer;
  rootKey: ArrayBuffer;
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
    certificate: uint8FromBufLike(encodedCertificate),
    canisterId,
    rootKey: uint8FromBufLike(rootKey),
  });
  const tree = Cbor.decode<HashTree>(uint8FromBufLike(encodedTree));

  validateCertificateTime(certificate, maxCertificateTimeOffsetMs, nowMs);
  await validateTree(tree, certificate, canisterId);

  return tree;
}

function validateCertificateTime(
  certificate: Certificate,
  maxCertificateTimeOffsetMs: number,
  nowMs: number,
): void {
  const timeResult = lookup_path(['time'], certificate.cert.tree);
  const timeValue = lookupResultToBuffer(timeResult);
  
  if (!timeValue) {
    throw new CertificateTimeError('Could not find time in certificate');
  }
  
  const certificateTimeNs = lebDecode(new PipeArrayBuffer(timeValue));
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
  const certifiedDataResult = lookup_path(
    ['canister', canisterId.toUint8Array(), 'certified_data'],
    certificate.cert.tree,
  );
  const certifiedData = lookupResultToBuffer(certifiedDataResult);

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
