import { Response } from '@dfinity/response-verification';
import { ErrResponse, HttpResponse } from '../../declarations/backend.did';

export function mapFromCanisterResponse(response: HttpResponse): Response {
  return {
    statusCode: response.status_code,
    headers: response.headers,
    body: Uint8Array.from(response.body),
  };
}

export function jsonDecode<T>(body?: Uint8Array): T {
  return JSON.parse(new TextDecoder().decode(body));
}

export function filterCertificateHeaders(response: Response): Response {
  return {
    ...response,
    headers: response.headers.filter(
      ([key]) =>
        key.toLowerCase() !== 'ic-certificateexpression' &&
        key.toLowerCase() !== 'ic-certificate',
    ),
  };
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

export function extractOkResponse<T>(res?: Uint8Array): T {
  const decodedRes = jsonDecode<ApiResponse<T>>(res);

  if (isErr(decodedRes)) {
    throw new Error(`${decodedRes.err.code}: ${decodedRes.err.message}`);
  }

  return decodedRes.ok.data;
}

export function extractErrResponse(res?: Uint8Array): ErrResponse {
  const decodedRes = jsonDecode<ApiResponse<unknown>>(res);

  if (isErr(decodedRes)) {
    return decodedRes.err;
  }

  throw new Error('Expected Err response but got Ok response');
}
