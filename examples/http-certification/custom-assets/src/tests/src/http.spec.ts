import { Actor, PocketIc } from '@hadronous/pic';
import { Principal } from '@dfinity/principal';
import {
  verifyRequestResponsePair,
  Request,
} from '@dfinity/response-verification';

import { _SERVICE } from '../../declarations/backend.did';
import { setupBackendCanister } from './wasm';
import { CERTIFICATE_VERSION, mapToCanisterRequest } from './request';
import { mapFromCanisterResponse } from './response';

const NS_PER_MS = 1e6;
const MS_PER_S = 1e3;
const S_PER_MIN = 60;

describe('HTTP', () => {
  let pic: PocketIc;
  let actor: Actor<_SERVICE>;
  let canisterId: Principal;

  let rootKey: ArrayBufferLike;

  const currentDate = new Date(2021, 6, 10, 0, 0, 0, 0);
  const currentTimeNs = BigInt(currentDate.getTime() * NS_PER_MS);
  const maxCertTimeOffsetNs = BigInt(5 * S_PER_MIN * MS_PER_S * NS_PER_MS);

  beforeEach(async () => {
    pic = await PocketIc.create();
    const fixture = await setupBackendCanister(pic, currentDate);
    actor = fixture.actor;
    canisterId = fixture.canisterId;

    const subnets = pic.getApplicationSubnets();
    rootKey = await pic.getPubKey(subnets[0].id);
  });

  afterEach(async () => {
    await pic.tearDown();
  });

  it('should successfully skip verification', async () => {
    const request: Request = {
      url: '/uncertified',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
    };
    const canisterRequest = mapToCanisterRequest(request);

    const canisterResponse = await actor.http_request(canisterRequest);
    const response = mapFromCanisterResponse(canisterResponse);
    expect(response.statusCode).toBe(200);

    let verificationResult = verifyRequestResponsePair(
      request,
      response,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      new Uint8Array(rootKey),
      CERTIFICATE_VERSION,
    );

    expect(verificationResult.verificationVersion).toEqual(CERTIFICATE_VERSION);
    expect(verificationResult.response).toBeUndefined();
  });
});
