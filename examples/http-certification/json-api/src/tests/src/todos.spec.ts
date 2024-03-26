import { Actor, PocketIc } from '@hadronous/pic';
import { Principal } from '@dfinity/principal';
import {
  verifyRequestResponsePair,
  Request,
} from '@dfinity/response-verification';
import {
  _SERVICE,
  ListTodoItemsResponse,
  CreateTodoItemRequest,
  CreateTodoItemResponse,
  UpdateTodoItemRequest,
  UpdateTodoItemResponse,
} from '../../declarations/backend.did';
import { setupBackendCanister } from './wasm';
import {
  CERTIFICATE_VERSION,
  jsonEncode,
  mapToCanisterRequest,
} from './request';
import {
  Ok,
  extractErrResponse,
  extractOkResponse,
  filterCertificateHeaders,
  jsonDecode,
  mapFromCanisterResponse,
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
    };
    const canisterRequest = mapToCanisterRequest(request);

    const canisterResponse = await actor.http_request(canisterRequest);
    const response = mapFromCanisterResponse(canisterResponse);
    const responseBody = extractOkResponse<Ok<ListTodoItemsResponse>>(
      response.body,
    );
    expect(response.statusCode).toBe(200);
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
    expect(verificationResult.response).toEqual(
      filterCertificateHeaders(response),
    );
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
    };

    const canisterCreateRequest = mapToCanisterRequest(createRequest);

    const canisterCreateResponse = await actor.http_request(
      canisterCreateRequest,
    );
    expect(canisterCreateResponse.upgrade).toEqual([true]);

    const canisterCreateUpdateResponse = await actor.http_request_update(
      canisterCreateRequest,
    );
    const createUpdateResponse = mapFromCanisterResponse(
      canisterCreateUpdateResponse,
    );
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
    };
    const canisterAfterCreateRequest = mapToCanisterRequest(afterCreateRequest);

    const canisterAfterCreateResponse = await actor.http_request(
      canisterAfterCreateRequest,
    );
    const afterCreateResponse = mapFromCanisterResponse(
      canisterAfterCreateResponse,
    );
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
    expect(verificationResult.response).toEqual(
      filterCertificateHeaders(afterCreateResponse),
    );
    expect(verificationResultBody).toEqual(afterCreateResponseBody);

    const updateRequest: Request = {
      url: `/todos/${createUpdateResponseBody.id}`,
      method: 'PATCH',
      headers: [],
      body: jsonEncode<UpdateTodoItemRequest>({
        completed: true,
      }),
    };

    const canisterUpdateRequest = mapToCanisterRequest(updateRequest);

    const canisterUpdateResponse = await actor.http_request(
      canisterUpdateRequest,
    );
    expect(canisterUpdateResponse.upgrade).toEqual([true]);

    const canisterUpdateUpdateResponse = await actor.http_request_update(
      canisterUpdateRequest,
    );
    const updateUpdateResponse = mapFromCanisterResponse(
      canisterUpdateUpdateResponse,
    );
    const updateUpdateResponseBody = extractOkResponse<
      Ok<UpdateTodoItemResponse>
    >(updateUpdateResponse.body);
    expect(updateUpdateResponseBody).toBe(null);

    const afterUpdateRequest: Request = {
      url: '/todos',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
    };
    const canisterAfterUpdateRequest = mapToCanisterRequest(afterUpdateRequest);

    const canisterAfterUpdateResponse = await actor.http_request(
      canisterAfterUpdateRequest,
    );
    const afterUpdateResponse = mapFromCanisterResponse(
      canisterAfterUpdateResponse,
    );
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
    expect(afterUpdateVerificationResult.response).toEqual(
      filterCertificateHeaders(afterUpdateResponse),
    );
    expect(afterUpdateVerificationResultBody).toEqual(afterUpdateResponseBody);

    const deleteRequest: Request = {
      url: `/todos/${createUpdateResponseBody.id}`,
      method: 'DELETE',
      headers: [],
      body: new Uint8Array(),
    };
    const canisterDeleteRequest = mapToCanisterRequest(deleteRequest);

    const canisterDeleteResponse = await actor.http_request(
      canisterDeleteRequest,
    );
    expect(canisterDeleteResponse.upgrade).toEqual([true]);

    const canisterDeleteUpdateResponse = await actor.http_request_update(
      canisterDeleteRequest,
    );
    const deleteUpdateResponse = mapFromCanisterResponse(
      canisterDeleteUpdateResponse,
    );
    const deleteUpdateResponseBody = extractOkResponse<
      Ok<CreateTodoItemResponse>
    >(deleteUpdateResponse.body);
    expect(canisterDeleteUpdateResponse.status_code).toEqual(204);
    expect(deleteUpdateResponseBody).toEqual(null);

    const afterDeleteRequest: Request = {
      url: '/todos',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
    };
    const canisterAfterDeleteRequest = mapToCanisterRequest(afterDeleteRequest);

    const canisterAfterDeleteResponse = await actor.http_request(
      canisterAfterDeleteRequest,
    );
    const afterDeleteResponse = mapFromCanisterResponse(
      canisterAfterDeleteResponse,
    );
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
    expect(afterDeleteVerificationResult.response).toEqual(
      filterCertificateHeaders(afterDeleteResponse),
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
      };
      const canisterRequest = mapToCanisterRequest(request);

      const canisterResponse = await actor.http_request(canisterRequest);
      const response = mapFromCanisterResponse(canisterResponse);
      const responseBody = extractErrResponse(response.body);
      expect(response.statusCode).toBe(405);
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
      expect(verificationResult.response).toEqual(
        filterCertificateHeaders(response),
      );
      expect(verificationResultBody).toEqual(responseBody);
    });
  });

  it('should return 404 for unknown route', async () => {
    const request: Request = {
      url: '/unknown',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
    };
    const canisterRequest = mapToCanisterRequest(request);

    const canisterResponse = await actor.http_request(canisterRequest);
    const response = mapFromCanisterResponse(canisterResponse);
    const responseBody = extractErrResponse(response.body);
    expect(response.statusCode).toBe(404);
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
    expect(verificationResult.response).toEqual(
      filterCertificateHeaders(response),
    );
    expect(verificationResultBody).toEqual(responseBody);
  });
});
