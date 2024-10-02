import { Request } from '@dfinity/response-verification';
import { HttpRequest } from '../../declarations/http_certification_skip_certification_backend.did';

export const CERTIFICATE_VERSION = 2;

export function mapToCanisterRequest(request: Request): HttpRequest {
  return {
    url: request.url,
    method: request.method,
    headers: request.headers,
    body: request.body,
    certificate_version: [CERTIFICATE_VERSION],
  };
}
