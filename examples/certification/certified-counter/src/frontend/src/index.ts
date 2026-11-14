import { verifyCertification } from '@dfinity/certificate-verification';
import {
  Actor,
  HttpAgent,
  uint8Equals,
  lookup_path,
  lookupResultToBuffer,
} from '@icp-sdk/core/agent';
import { Principal } from '@icp-sdk/core/principal';
import { idlFactory, _SERVICE } from '../../declarations/backend.did';

const canisterId =
  process.env.CANISTER_ID_CERTIFICATION_CERTIFIED_COUNTER_BACKEND ?? '';
const dfxNetwork = process.env.DFX_NETWORK ?? '';

const agent = new HttpAgent();

// Only a local replica's root key has to be fetched. On the IC the agent
// already holds the built-in root key, which must not be replaced by one
// served over the network.
if (dfxNetwork !== 'ic') {
  try {
    await agent.fetchRootKey();
  } catch (err) {
    console.warn(
      'Unable to fetch root key. Check to ensure that your local replica is running',
    );
    console.error(err);
  }
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
  return new Uint8Array(await crypto.subtle.digest('SHA-256', view));
}

buttonElement.addEventListener('click', async event => {
  event.preventDefault();

  buttonElement.setAttribute('disabled', String(true));
  await backend.inc_count();
  const { count, certificate, witness } = await backend.get_count();
  buttonElement.removeAttribute('disabled');

  if (!agent.rootKey) {
    throw new Error('The agent is missing a root key');
  }

  const tree = await verifyCertification({
    canisterId: Principal.fromText(canisterId),
    encodedCertificate: new Uint8Array(certificate),
    encodedTree: new Uint8Array(witness),
    rootKey: agent.rootKey,
    maxCertificateTimeOffsetMs: 50000,
  });

  const treeHash = lookupResultToBuffer(lookup_path(['count'], tree));
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
