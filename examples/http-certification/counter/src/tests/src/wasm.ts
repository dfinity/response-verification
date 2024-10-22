import { type CanisterFixture, type PocketIc } from '@hadronous/pic';
import { resolve } from 'node:path';
import {
  type _SERVICE,
  idlFactory,
} from '../../declarations/http_certification_counter_backend.did';

const wasm = resolve(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  '..',
  '..',
  '.dfx',
  'local',
  'canisters',
  'http_certification_counter_backend',
  'http_certification_counter_backend.wasm.gz',
);

export async function setupBackendCanister(
  pic: PocketIc,
  initialDate: Date,
): Promise<CanisterFixture<_SERVICE>> {
  await pic.setTime(initialDate.getTime());

  return await pic.setupCanister<_SERVICE>({
    idlFactory,
    wasm,
  });
}
