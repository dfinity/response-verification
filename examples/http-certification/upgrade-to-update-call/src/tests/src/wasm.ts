import { type CanisterFixture, type PocketIc } from '@dfinity/pic';
import { resolve } from 'node:path';
import {
  type _SERVICE as RUST_SERVICE,
  idlFactory as rustIdlFactory,
} from '../../declarations/rust-backend/backend.did';
import {
  type _SERVICE as MOTOKO_SERVICE,
  idlFactory as motokoIdlFactory,
} from '../../declarations/motoko-backend/backend.did';

const RUST_BACKEND_WASM_PATH = resolve(
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
  'http_certification_upgrade_to_update_call_rust_backend.wasm',
);

const Motoko_BACKEND_WASM_PATH = resolve(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  '..',
  '..',
  '.mops',
  '.build',
  'http_certification_upgrade_to_update_call_motoko_backend.wasm',
);

export async function setupRustBackendCanister(
  pic: PocketIc,
): Promise<CanisterFixture<RUST_SERVICE>> {
  return await pic.setupCanister<RUST_SERVICE>({
    idlFactory: rustIdlFactory,
    wasm: RUST_BACKEND_WASM_PATH,
  });
}

export async function setupMotokoBackendCanister(
  pic: PocketIc,
): Promise<CanisterFixture<MOTOKO_SERVICE>> {
  return await pic.setupCanister<MOTOKO_SERVICE>({
    idlFactory: motokoIdlFactory,
    wasm: Motoko_BACKEND_WASM_PATH,
  });
}
