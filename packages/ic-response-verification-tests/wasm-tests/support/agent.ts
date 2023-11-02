import { HttpAgent, Identity } from '@dfinity/agent';
import { ANONYMOUS_IDENTITY } from './identity';

export async function createAgent(
  host: string,
  identity: Identity = ANONYMOUS_IDENTITY,
): Promise<HttpAgent> {
  const agent = new HttpAgent({
    identity,
    host,
  });

  await agent.fetchRootKey();

  return agent;
}
