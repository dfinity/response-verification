import { Actor, PocketIc } from '@hadronous/pic';

import {
  _SERVICE as RUST_SERVICE,
  HttpRequest,
} from '../../declarations/rust-backend/http_certification_upgrade_to_update_call_rust_backend.did';
import { _SERVICE as MOTOKO_SERVICE } from '../../declarations/motoko-backend/http_certification_upgrade_to_update_call_motoko_backend.did';
import { setupMotokoBackendCanister, setupRustBackendCanister } from './wasm';

describe('HTTP', () => {
  let pic: PocketIc;
  let rustActor: Actor<RUST_SERVICE>;
  let motokoActor: Actor<MOTOKO_SERVICE>;

  beforeEach(async () => {
    pic = await PocketIc.create();

    const rustFixture = await setupRustBackendCanister(pic);
    rustActor = rustFixture.actor;

    const motokoFixture = await setupMotokoBackendCanister(pic);
    motokoActor = motokoFixture.actor;
  });

  afterEach(async () => {
    await pic.tearDown();
  });

  it('should upgrade to an update call', async () => {
    const request: HttpRequest = {
      url: '/',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const rustResponse = await rustActor.http_request(request);
    expect(rustResponse.upgrade).toEqual([true]);

    const motokoResponse = await motokoActor.http_request(request);
    expect(motokoResponse.upgrade).toEqual([true]);

    const rustUpdateResponse = await rustActor.http_request_update(request);
    expect(rustUpdateResponse.status_code).toBe(418);
    expect(rustUpdateResponse.body).toEqual(
      new TextEncoder().encode("I'm a teapot"),
    );

    const motokoUpdateResponse = await motokoActor.http_request_update(request);
    expect(motokoUpdateResponse.status_code).toBe(418);
    expect(motokoUpdateResponse.body).toEqual(
      new TextEncoder().encode("I'm a teapot"),
    );
  });
});
