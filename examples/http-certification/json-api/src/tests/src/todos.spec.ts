import { Actor, PocketIc } from '@hadronous/pic';
import { Principal } from '@dfinity/principal';
import {
  verifyRequestResponsePair,
  Request,
  VerifiedResponse,
  Response,
} from '@dfinity/response-verification';
import {
  _SERVICE,
  ListTodoItemsResponse,
  CreateTodoItemRequest,
  CreateTodoItemResponse,
  UpdateTodoItemRequest,
  UpdateTodoItemResponse,
} from '../../declarations/http_certification_json_api_backend.did';
import { setupBackendCanister } from './wasm';
import { CERTIFICATE_VERSION, jsonEncode } from './request';
import {
  Ok,
  extractErrResponse,
  extractOkResponse,
  jsonDecode,
} from './response';

const NS_PER_MS = 1e6;
const MS_PER_S = 1e3;
const S_PER_MIN = 60;

describe('Todos', () => {
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

  it('should initially have an empty array of todos', async () => {
    const request: Request = {
      url: '/todos',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const response = await actor.http_request(request);
    const responseBody = extractOkResponse<Ok<ListTodoItemsResponse>>(
      response.body,
    );
    expect(response.status_code).toBe(200);
    expect(responseBody).toEqual([]);

    let verificationResult = verifyRequestResponsePair(
      request,
      response,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      new Uint8Array(rootKey),
      CERTIFICATE_VERSION,
    );
    const verificationResultBody = extractOkResponse<Ok<ListTodoItemsResponse>>(
      verificationResult.response?.body,
    );

    expect(verificationResult.verificationVersion).toEqual(CERTIFICATE_VERSION);
    expectResponseEqual(verificationResult.response, response);
    expect(verificationResultBody).toEqual(responseBody);
  });

  it('should create, update and delete a todo', async () => {
    const todoTitle = 'Buy milk';
    const createRequest: Request = {
      url: '/todos',
      method: 'POST',
      headers: [],
      body: jsonEncode<CreateTodoItemRequest>({
        title: todoTitle,
      }),
      certificate_version: [],
    };

    const createResponse = await actor.http_request(createRequest);
    expect(createResponse.upgrade).toEqual([true]);

    const createUpdateResponse = await actor.http_request_update(createRequest);
    const createUpdateResponseBody = extractOkResponse<
      Ok<CreateTodoItemResponse>
    >(createUpdateResponse.body);

    expect(createUpdateResponseBody.title).toBe(todoTitle);
    expect(createUpdateResponseBody.completed).toBe(false);
    expect(createUpdateResponseBody.id).toBeDefined();
    expect(createUpdateResponseBody.id).toEqual(expect.any(Number));

    const afterCreateRequest: Request = {
      url: '/todos',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const afterCreateResponse = await actor.http_request(afterCreateRequest);
    const afterCreateResponseBody = jsonDecode<ListTodoItemsResponse>(
      afterCreateResponse.body,
    );
    expect(afterCreateResponseBody).toEqual({
      ok: { data: [createUpdateResponseBody] },
    });

    let verificationResult = verifyRequestResponsePair(
      afterCreateRequest,
      afterCreateResponse,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      new Uint8Array(rootKey),
      CERTIFICATE_VERSION,
    );
    const verificationResultBody = jsonDecode<ListTodoItemsResponse>(
      verificationResult.response?.body,
    );

    expect(verificationResult.verificationVersion).toEqual(CERTIFICATE_VERSION);
    expectResponseEqual(verificationResult.response, afterCreateResponse);
    expect(verificationResultBody).toEqual(afterCreateResponseBody);

    const updateRequest: Request = {
      url: `/todos/${createUpdateResponseBody.id}`,
      method: 'PATCH',
      headers: [],
      body: jsonEncode<UpdateTodoItemRequest>({
        completed: true,
      }),
      certificate_version: [],
    };

    const updateResponse = await actor.http_request(updateRequest);
    expect(updateResponse.upgrade).toEqual([true]);

    const updateUpdateResponse = await actor.http_request_update(updateRequest);
    const updateUpdateResponseBody = extractOkResponse<
      Ok<UpdateTodoItemResponse>
    >(updateUpdateResponse.body);
    expect(updateUpdateResponseBody).toBe(null);

    const afterUpdateRequest: Request = {
      url: '/todos',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const afterUpdateResponse = await actor.http_request(afterUpdateRequest);
    const afterUpdateResponseBody = jsonDecode<ListTodoItemsResponse>(
      afterUpdateResponse.body,
    );
    expect(afterUpdateResponseBody).toEqual({
      ok: { data: [{ ...createUpdateResponseBody, completed: true }] },
    });

    let afterUpdateVerificationResult = verifyRequestResponsePair(
      afterUpdateRequest,
      afterUpdateResponse,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      new Uint8Array(rootKey),
      CERTIFICATE_VERSION,
    );
    const afterUpdateVerificationResultBody = jsonDecode<ListTodoItemsResponse>(
      afterUpdateVerificationResult.response?.body,
    );
    expect(afterUpdateVerificationResult.verificationVersion).toEqual(
      CERTIFICATE_VERSION,
    );
    expectResponseEqual(
      afterUpdateVerificationResult.response,
      afterUpdateResponse,
    );
    expect(afterUpdateVerificationResultBody).toEqual(afterUpdateResponseBody);

    const deleteRequest: Request = {
      url: `/todos/${createUpdateResponseBody.id}`,
      method: 'DELETE',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const deleteResponse = await actor.http_request(deleteRequest);
    expect(deleteResponse.upgrade).toEqual([true]);

    const deleteUpdateResponse = await actor.http_request_update(deleteRequest);
    const deleteUpdateResponseBody = extractOkResponse<
      Ok<CreateTodoItemResponse>
    >(deleteUpdateResponse.body);
    expect(deleteUpdateResponse.status_code).toEqual(204);
    expect(deleteUpdateResponseBody).toEqual(null);

    const afterDeleteRequest: Request = {
      url: '/todos',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const afterDeleteResponse = await actor.http_request(afterDeleteRequest);
    const afterDeleteResponseBody = jsonDecode<ListTodoItemsResponse>(
      afterDeleteResponse.body,
    );
    expect(afterDeleteResponseBody).toEqual({
      ok: { data: [] },
    });

    let afterDeleteVerificationResult = verifyRequestResponsePair(
      afterDeleteRequest,
      afterDeleteResponse,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      new Uint8Array(rootKey),
      CERTIFICATE_VERSION,
    );
    const afterDeleteVerificationResultBody = jsonDecode<ListTodoItemsResponse>(
      afterDeleteVerificationResult.response?.body,
    );
    expect(afterDeleteVerificationResult.verificationVersion).toEqual(
      CERTIFICATE_VERSION,
    );
    expectResponseEqual(
      afterDeleteVerificationResult.response,
      afterDeleteResponse,
    );
    expect(afterDeleteVerificationResultBody).toEqual(afterDeleteResponseBody);
  });

  ['HEAD', 'PUT', 'OPTIONS', 'TRACE', 'CONNECT'].forEach(method => {
    it(`should return 405 for ${method} method`, async () => {
      const request: Request = {
        url: '/todos',
        method,
        headers: [],
        body: new Uint8Array(),
        certificate_version: [],
      };

      const response = await actor.http_request(request);
      const responseBody = extractErrResponse(response.body);
      expect(response.status_code).toBe(405);
      expect(responseBody).toEqual({
        code: 405,
        message: 'Method not allowed',
      });

      let verificationResult = verifyRequestResponsePair(
        request,
        response,
        canisterId.toUint8Array(),
        currentTimeNs,
        maxCertTimeOffsetNs,
        new Uint8Array(rootKey),
        CERTIFICATE_VERSION,
      );
      let verificationResultBody = extractErrResponse(
        verificationResult.response?.body,
      );

      expect(verificationResult.verificationVersion).toEqual(
        CERTIFICATE_VERSION,
      );
      expectResponseEqual(verificationResult.response, response);
      expect(verificationResultBody).toEqual(responseBody);
    });
  });

  it('should return 404 for unknown route', async () => {
    const request: Request = {
      url: '/unknown',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const response = await actor.http_request(request);
    const responseBody = extractErrResponse(response.body);
    expect(response.status_code).toBe(404);
    expect(responseBody).toEqual({
      code: 404,
      message: 'Not found',
    });

    let verificationResult = verifyRequestResponsePair(
      request,
      response,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      new Uint8Array(rootKey),
      CERTIFICATE_VERSION,
    );
    let verificationResultBody = extractErrResponse(
      verificationResult.response?.body,
    );

    expect(verificationResult.verificationVersion).toEqual(CERTIFICATE_VERSION);
    expectResponseEqual(verificationResult.response, response);
    expect(verificationResultBody).toEqual(responseBody);
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
