import { AnonymousIdentity, Identity } from '@dfinity/agent';
import { Ed25519KeyIdentity } from '@dfinity/identity';

export function createIdentity(seedPhrase: string): Identity {
  const hash = new Bun.CryptoHasher('sha256');
  hash.update(seedPhrase);
  const digest = hash.digest('hex').slice(0, 32);
  const encodedDigest = new TextEncoder().encode(digest);

  return Ed25519KeyIdentity.generate(encodedDigest);
}

export const ANONYMOUS_IDENTITY = new AnonymousIdentity();
export const DEFAULT_IDENTITY = createIdentity('@Password!1234');
