import { beforeAll, afterAll } from 'bun:test';
import { resolve } from 'path';
import { dfxDeploy, getReplicaUrl, restartDfx, stopDfx } from './support';

beforeAll(async () => {
  restartDfx();

  const replicaUrl = getReplicaUrl();
  const canisterId = dfxDeploy(
    'frontend',
    resolve(import.meta.dir, '..', 'dfx-project'),
  );

  process.env['REPLICA_URL'] = replicaUrl;
  process.env['CANISTER_ID'] = canisterId;
});

afterAll(async () => {
  stopDfx();
});
