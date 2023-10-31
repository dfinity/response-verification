import { beforeEach, describe, expect, it } from 'bun:test';
import { HttpCanisterClient } from '@dfinity/http-canister-client';
import { Principal } from '@dfinity/principal';
import { HttpAgent } from '@dfinity/agent';
import {
  createAgent,
  readAsset,
  request,
  verify,
  TEST_CASES,
} from '../support';

describe('Response Verification v2', () => {
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
      const certificateVersion = 2;

      const [httpRequest, httpResponse] = await request(httpCanisterClient, {
        url,
        method: 'GET',
        certificateVersion,
      });

      console.log('httpRequest', httpRequest);
      console.log('httpResponse', httpResponse);

      const result = verify({
        httpRequest,
        httpResponse,
        certificateVersion,
        rootKey,
        canisterId,
      });

      const expectedResponse = await readAsset(responsePath);

      expect(result.verificationVersion).toEqual(2);
      expect(result.response).toBeDefined();

      expect(result.response.statusCode).toEqual(200);

      expect(result.response.headers).toBeArray();
      expect(result.response.headers).toBeArrayOfSize(9);

      expect(result.response.body).toBeInstanceOf(Uint8Array);
      expect(result.response.body).toEqual(expectedResponse);
    });
  });
});
