import { ErrResponse } from '../../declarations/http_certification_json_api_backend.did';

export function jsonDecode<T>(body?: Uint8Array | number[]): T {
  body = body ? Uint8Array.from(body) : body;

  return JSON.parse(new TextDecoder().decode(body));
}

export interface ApiOkResponse<T> {
  ok: {
    data: T;
  };
}

export interface ApiErrResponse {
  err: ErrResponse;
}

export type ApiResponse<T> = ApiOkResponse<T> | ApiErrResponse;

export type Ok<T> = T extends ApiOkResponse<infer U> ? U : never;

export function isOk<T>(res: ApiResponse<T>): res is ApiOkResponse<T> {
  return 'ok' in res;
}

export function isErr<T>(res: ApiResponse<T>): res is ApiErrResponse {
  return 'err' in res;
}

export function extractOkResponse<T>(res?: Uint8Array | number[]): T {
  const decodedRes = jsonDecode<ApiResponse<T>>(res);

  if (isErr(decodedRes)) {
    throw new Error(`${decodedRes.err.code}: ${decodedRes.err.message}`);
  }

  return decodedRes.ok.data;
}

export function extractErrResponse(res?: Uint8Array | number[]): ErrResponse {
  const decodedRes = jsonDecode<ApiResponse<unknown>>(res);

  if (isErr(decodedRes)) {
    return decodedRes.err;
  }

  throw new Error('Expected Err response but got Ok response');
}
