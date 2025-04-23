import { type CanisterFixture, type PocketIc } from '@dfinity/pic';
import { resolve } from 'node:path';
import {
  type _SERVICE,
  idlFactory,
} from '../../declarations/http_certification_skip_certification_backend.did';

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
  'http_certification_skip_certification_backend.wasm',
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
