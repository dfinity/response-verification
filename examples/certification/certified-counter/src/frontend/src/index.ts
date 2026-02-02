import { verifyCertification } from '@dfinity/certificate-verification';
import { Actor, HttpAgent, compare, lookup_path } from '@dfinity/agent';
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
): Promise<ArrayBuffer> {
  const buffer = new ArrayBuffer(4);
  const view = new DataView(buffer);
  view.setUint32(0, value, littleEndian);
  return await crypto.subtle.digest('SHA-256', view);
}

buttonElement.addEventListener('click', async event => {
  event.preventDefault();

  buttonElement.setAttribute('disabled', String(true));
  await backend.inc_count();
  const { count, certificate, witness } = await backend.get_count();
  buttonElement.removeAttribute('disabled');

  const agent = new HttpAgent();
  await agent.fetchRootKey();
  const tree = await verifyCertification({
    canisterId: Principal.fromText(canisterId),
    encodedCertificate: new Uint8Array(certificate).buffer,
    encodedTree: new Uint8Array(witness).buffer,
    rootKey: agent.rootKey,
    maxCertificateTimeOffsetMs: 50000,
  });

  const treeHash = lookup_path(['count'], tree);
  if (!treeHash) {
    throw new Error('Count not found in tree');
  }

  const responseHash = await hashUInt32(count);
  if (!(treeHash instanceof ArrayBuffer) || !equal(responseHash, treeHash)) {
    throw new Error('Count hash does not match');
  }

  countElement.innerText = String(count);

  return false;
});

function equal(a: ArrayBuffer, b: ArrayBuffer): boolean {
  return compare(a, b) === 0;
}
