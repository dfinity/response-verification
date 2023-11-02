import { beforeEach, describe, expect, it } from 'bun:test';
import { HttpCanisterClient } from '@dfinity/http-canister-client';
import { Principal } from '@dfinity/principal';
import { HttpAgent } from '@dfinity/agent';
import {
  TEST_CASES,
  createAgent,
  readAsset,
  request,
  verify,
} from '../support';

describe('Response Verification v1', () => {
  let agent: HttpAgent;
  let httpCanisterClient: HttpCanisterClient;
  let rootKey: Uint8Array;
  let canisterId: Principal;

  beforeEach(async () => {
    const replicaUrl = process.env.REPLICA_URL;
    canisterId = Principal.fromText(process.env.CANISTER_ID);

    agent = await createAgent(replicaUrl);
    rootKey = new Uint8Array(agent.rootKey);

    httpCanisterClient = new HttpCanisterClient(canisterId, agent);
  });

  TEST_CASES.forEach(({ url, responsePath }) => {
    it(`should verify a valid response on URL ${url}`, async () => {
      const certificateVersion = 1;

      const [httpRequest, httpResponse] = await request(httpCanisterClient, {
        url,
        method: 'GET',
        certificateVersion,
      });

      const result = verify({
        httpRequest,
        httpResponse,
        certificateVersion,
        rootKey,
        canisterId,
      });

      const expectedResponse = await readAsset(responsePath);

      expect(result.verificationVersion).toEqual(1);
      expect(result.response).toBeDefined();

      expect(result.response.statusCode).not.toBeDefined();

      expect(result.response.headers).toBeArray();
      expect(result.response.headers).toBeArrayOfSize(0);

      expect(result.response.body).toBeInstanceOf(Uint8Array);
      expect(result.response.body).toEqual(expectedResponse);
    });
  });
});
