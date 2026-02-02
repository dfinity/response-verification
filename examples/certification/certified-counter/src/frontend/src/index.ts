import { verifyCertification } from '@dfinity/certificate-verification';
import { Actor, HttpAgent, lookup_path, lookupResultToBuffer } from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import {
  idlFactory,
  _SERVICE,
} from '../../declarations/certification_certified_counter_backend.did';

const canisterId =
  process.env.CANISTER_ID_CERTIFICATION_CERTIFIED_COUNTER_BACKEND ?? '';
const dfxNetwork = process.env.DFX_NETWORK ?? '';

const agent = new HttpAgent();

if (dfxNetwork !== 'ic') {
  agent.fetchRootKey().catch(err => {
    console.warn(
      'Unable to fetch root key. Check to ensure that your local replica is running',
    );
    console.error(err);
  });
}

// Creates an actor with using the candid interface and the HttpAgent
const backend = Actor.createActor<_SERVICE>(idlFactory, {
  agent,
  canisterId,
});

const buttonElement = document.querySelector<HTMLButtonElement>('#counter-inc');
if (!buttonElement) {
  throw new Error('Counter inc element not found');
}

const countElement = document.querySelector<HTMLDivElement>('#counter-count');
if (!countElement) {
  throw new Error('Counter count element not found');
}

async function hashUInt32(
  value: number,
  littleEndian = false,
): Promise<Uint8Array> {
  const buffer = new ArrayBuffer(4);
  const view = new DataView(buffer);
  view.setUint32(0, value, littleEndian);
  const hash = await crypto.subtle.digest('SHA-256', view);
  return new Uint8Array(hash);
}

function uint8Equals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

buttonElement.addEventListener('click', async event => {
  event.preventDefault();

  buttonElement.setAttribute('disabled', String(true));
  await backend.inc_count();
  const { count, certificate, witness } = await backend.get_count();
  buttonElement.removeAttribute('disabled');

  const agent = new HttpAgent();
  await agent.fetchRootKey();
  
  if (!agent.rootKey) {
    throw new Error('Root key not available');
  }
  
  const tree = await verifyCertification({
    canisterId: Principal.fromText(canisterId),
    encodedCertificate: new Uint8Array(certificate).buffer,
    encodedTree: new Uint8Array(witness).buffer,
    rootKey: agent.rootKey.buffer,
    maxCertificateTimeOffsetMs: 50000,
  });

  const treeHashResult = lookup_path(['count'], tree);
  const treeHash = lookupResultToBuffer(treeHashResult);
  
  if (!treeHash) {
    throw new Error('Count not found in tree');
  }

  const responseHash = await hashUInt32(count);
  if (!uint8Equals(responseHash, treeHash)) {
    throw new Error('Count hash does not match');
  }

  countElement.innerText = String(count);

  return false;
});
