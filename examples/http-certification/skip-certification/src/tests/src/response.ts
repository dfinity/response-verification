import { Response } from '@dfinity/response-verification';
import { HttpResponse } from '../../declarations/http_certification_skip_certification_backend.did';

export function mapFromCanisterResponse(response: HttpResponse): Response {
  return {
    statusCode: response.status_code,
    headers: response.headers,
    body: Uint8Array.from(response.body),
  };
}
