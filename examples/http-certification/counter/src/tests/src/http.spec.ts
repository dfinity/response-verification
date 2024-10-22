import { Actor, PocketIc } from '@hadronous/pic';
import {
  _SERVICE,
  HttpRequest,
} from '../../declarations/http_certification_counter_backend.did';
import { setupBackendCanister } from './wasm';
import {
  Response,
  VerifiedResponse,
  verifyRequestResponsePair,
} from '@dfinity/response-verification';
import { Principal } from '@dfinity/principal';

const CERTIFICATE_VERSION = 2;
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

  it('should fetch and increment the counter', async () => {
    const fetchRequest: HttpRequest = {
      url: '/',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const firstFetchResponse = await actor.http_request(fetchRequest);
    expect(firstFetchResponse.status_code).toBe(200);
    expect(firstFetchResponse.body).toEqual(new TextEncoder().encode('0'));

    const firstFetchVerificationResult = verifyRequestResponsePair(
      fetchRequest,
      firstFetchResponse,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      new Uint8Array(rootKey),
      CERTIFICATE_VERSION,
    );
    expect(firstFetchVerificationResult.verificationVersion).toEqual(
      CERTIFICATE_VERSION,
    );
    expectResponseEqual(
      firstFetchVerificationResult.response,
      firstFetchResponse,
    );

    const incrementRequest: HttpRequest = {
      url: '/',
      method: 'POST',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const incrementResponse = await actor.http_request(incrementRequest);
    expect(incrementResponse.upgrade).toEqual([true]);

    const incrementUpdateResponse =
      await actor.http_request_update(incrementRequest);
    expect(incrementUpdateResponse.status_code).toBe(200);
    expect(incrementUpdateResponse.body).toEqual(new TextEncoder().encode('1'));

    const secondFetchResponse = await actor.http_request(fetchRequest);
    expect(secondFetchResponse.status_code).toBe(200);
    expect(secondFetchResponse.body).toEqual(new TextEncoder().encode('1'));

    const secondFetchVerificationResult = verifyRequestResponsePair(
      fetchRequest,
      secondFetchResponse,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      new Uint8Array(rootKey),
      CERTIFICATE_VERSION,
    );
    expect(secondFetchVerificationResult.verificationVersion).toEqual(
      CERTIFICATE_VERSION,
    );
    expectResponseEqual(
      secondFetchVerificationResult.response,
      secondFetchResponse,
    );
  });
});

function expectResponseEqual(
  actual: VerifiedResponse | undefined,
  expected: Response,
): void {
  expect(actual).toBeDefined();
  expect(actual?.statusCode).toBe(expected.status_code);
  expect(actual?.body).toEqual(expected.body);
  expect(actual?.headers.length).toEqual(expected.headers.length);

  actual?.headers.forEach(([actualKey, actualValue]) => {
    const expectedHeader = expected.headers.find(
      ([expectedKey]) => expectedKey.toLowerCase() === actualKey.toLowerCase(),
    );

    expect(expectedHeader).toBeDefined();
    expect(actualValue).toEqual(expectedHeader?.[1]);
  });
}
