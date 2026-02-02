import { type CanisterFixture, type PocketIc } from '@dfinity/pic';
import { resolve } from 'node:path';
import {
  type _SERVICE as RUST_SERVICE,
  idlFactory as rustIdlFactory,
} from '../../declarations/rust-backend/http_certification_upgrade_to_update_call_rust_backend.did';
import {
  type _SERVICE as MOTOKO_SERVICE,
  idlFactory as motokoIdlFactory,
} from '../../declarations/motoko-backend/http_certification_upgrade_to_update_call_motoko_backend.did';

const RUST_BACKEND_WASM_PATH = resolve(
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
  'http_certification_upgrade_to_update_call_rust_backend',
  'http_certification_upgrade_to_update_call_rust_backend.wasm.gz',
);

const Motoko_BACKEND_WASM_PATH = resolve(
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
  'http_certification_upgrade_to_update_call_motoko_backend',
  'http_certification_upgrade_to_update_call_motoko_backend.wasm.gz',
);

export async function setupRustBackendCanister(
  pic: PocketIc,
): Promise<CanisterFixture<RUST_SERVICE>> {
  return await pic.setupCanister<RUST_SERVICE>({
    idlFactory: rustIdlFactory as any,
    wasm: RUST_BACKEND_WASM_PATH,
  });
}

export async function setupMotokoBackendCanister(
  pic: PocketIc,
): Promise<CanisterFixture<MOTOKO_SERVICE>> {
  return await pic.setupCanister<MOTOKO_SERVICE>({
    idlFactory: motokoIdlFactory as any,
    wasm: Motoko_BACKEND_WASM_PATH,
  });
}
