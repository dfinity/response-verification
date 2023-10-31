import {
  HttpCanisterClient,
  HttpRequest,
  HttpResponse,
} from '@dfinity/http-canister-client';
import { Principal } from '@dfinity/principal';
import {
  VerificationInfo,
  getMinVerificationVersion,
  verifyRequestResponsePair,
  Request,
  Response,
} from '@dfinity/response-verification';

export interface RequestOptions {
  method: string;
  url: string;
  certificateVersion?: number;
}

export async function request(
  httpCanisterClient: HttpCanisterClient,
  { method, url, certificateVersion }: RequestOptions,
): Promise<[HttpRequest, HttpResponse]> {
  const httpRequest: HttpRequest = {
    method,
    body: new Uint8Array(),
    certificate_version: certificateVersion ? [certificateVersion] : [],
    headers: [],
    url,
  };

  const httpResponse = await httpCanisterClient.httpRequest(httpRequest);

  return [httpRequest, httpResponse];
}

export interface VerifyOptions {
  httpRequest: HttpRequest;
  httpResponse: HttpResponse;
  certificateVersion?: number;
  rootKey: Uint8Array;
  canisterId: Principal;
}

export function verify({
  httpRequest,
  httpResponse,
  certificateVersion,
  rootKey,
  canisterId,
}: VerifyOptions): VerificationInfo {
  let request: Request = {
    headers: httpRequest.headers,
    method: httpRequest.method,
    url: httpRequest.url,
    body: Uint8Array.from(httpRequest.body),
  };
  let response: Response = {
    body: Uint8Array.from(httpResponse.body),
    headers: httpResponse.headers,
    statusCode: httpResponse.status_code,
  };

  const currentTimeNs = BigInt.asUintN(64, BigInt(Date.now() * 1_000_000)); // from ms to nanoseconds
  const maxCertTimeOffsetNs = BigInt.asUintN(64, BigInt(300_000_000_000));

  return verifyRequestResponsePair(
    request,
    response,
    canisterId.toUint8Array(),
    currentTimeNs,
    maxCertTimeOffsetNs,
    rootKey,
    certificateVersion ?? getMinVerificationVersion(),
  );
}
