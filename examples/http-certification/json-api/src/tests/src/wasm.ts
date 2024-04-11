import { type CanisterFixture, type PocketIc } from '@hadronous/pic';
import { resolve } from 'node:path';
import { type _SERVICE, idlFactory } from '../../declarations/backend.did';

export const BACKEND_WASM_PATH = resolve(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  '..',
  '..',
  'target',
  'wasm32-unknown-unknown',
  'release',
  'http_certification_json_api_backend.wasm',
);

export async function setupBackendCanister(
  pic: PocketIc,
  initialDate: Date,
): Promise<CanisterFixture<_SERVICE>> {
  await pic.setTime(initialDate.getTime());

  return await pic.setupCanister<_SERVICE>({
    idlFactory,
    wasm: BACKEND_WASM_PATH,
  });
}
