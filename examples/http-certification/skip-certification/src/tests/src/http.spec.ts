import { Actor, PocketIc, PocketIcServer } from '@dfinity/pic';
import { Principal } from '@icp-sdk/core/principal';
import { verifyRequestResponsePair } from '@dfinity/response-verification';

import {
  _SERVICE,
  HeaderField,
  type HttpRequest,
} from '../../declarations/backend.did';
import { setupBackendCanister } from './wasm';

const CERTIFICATE_VERSION = 2;
const NS_PER_MS = 1e6;
const MS_PER_S = 1e3;
const S_PER_MIN = 60;

interface Metrics {
  cycle_balance: number;
}

describe('HTTP', () => {
  let picServer: PocketIcServer;
  let pic: PocketIc;
  let actor: Actor<_SERVICE>;
  let canisterId: Principal;

  let rootKey: Uint8Array;

  const currentDate = new Date(2021, 6, 10, 0, 0, 0, 0);
  const currentTimeNs = BigInt(currentDate.getTime() * NS_PER_MS);
  const maxCertTimeOffsetNs = BigInt(5 * S_PER_MIN * MS_PER_S * NS_PER_MS);

  beforeAll(async () => {
    picServer = await PocketIcServer.start();
  });

  afterAll(async () => {
    picServer.stop();
  });

  beforeEach(async () => {
    pic = await PocketIc.create(picServer.getUrl());
    const fixture = await setupBackendCanister(pic, currentDate);
    actor = fixture.actor;
    canisterId = fixture.canisterId;

    const subnets = await pic.getApplicationSubnets();
    rootKey = await pic.getPubKey(subnets[0].id);
  });

  afterEach(async () => {
    await pic.tearDown();
  });

  it('should serve uncertified metrics', async () => {
    const request: HttpRequest = {
      url: '/',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const response = await actor.http_request(request);
    const textBody = new TextDecoder().decode(Uint8Array.from(response.body));
    const jsonBody = JSON.parse(textBody) as Metrics;
    const currentCycles = await pic.getCyclesBalance(canisterId);

    expect(response.status_code).toBe(200);
    // The canister serializes its `u128` balance as a JSON number, so the
    // bigint from PocketIC is narrowed to match what `JSON.parse` produces.
    expect(jsonBody).toEqual({
      cycle_balance: Number(currentCycles),
    });
    expectSecurityHeaders(response.headers);
    expectHeader(response.headers, ['content-type', 'application/json']);
    expectHeader(response.headers, [
      'cache-control',
      'public, no-cache, no-store',
    ]);

    let verificationResult = verifyRequestResponsePair(
      request,
      response,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      rootKey,
      CERTIFICATE_VERSION,
    );

    expect(verificationResult.verificationVersion).toEqual(CERTIFICATE_VERSION);
    expect(verificationResult.response).toBeUndefined();
  });

  function expectSecurityHeaders(headers: HeaderField[] = []): void {
    expectHeader(headers, [
      'strict-transport-security',
      'max-age=31536000; includeSubDomains',
    ]);
    expectHeader(headers, ['x-frame-options', 'DENY']);
    expectHeader(headers, ['x-content-type-options', 'nosniff']);
    expectHeader(headers, [
      'content-security-policy',
      "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content",
    ]);
    expectHeader(headers, ['referrer-policy', 'no-referrer']);
    expectHeader(headers, [
      'permissions-policy',
      'accelerometer=(),ambient-light-sensor=(),autoplay=(),battery=(),camera=(),display-capture=(),document-domain=(),encrypted-media=(),fullscreen=(),gamepad=(),geolocation=(),gyroscope=(),layout-animations=(self),legacy-image-formats=(self),magnetometer=(),microphone=(),midi=(),oversized-images=(self),payment=(),picture-in-picture=(),publickey-credentials-get=(),speaker-selection=(),sync-xhr=(self),unoptimized-images=(self),unsized-media=(self),usb=(),screen-wake-lock=(),web-share=(),xr-spatial-tracking=()',
    ]);
    expectHeader(headers, ['cross-origin-embedder-policy', 'require-corp']);
    expectHeader(headers, ['cross-origin-opener-policy', 'same-origin']);
  }

  function expectHeader(
    headers: HeaderField[] = [],
    header: HeaderField,
  ): void {
    expect(headers).toContainEqual(header);
  }
});
