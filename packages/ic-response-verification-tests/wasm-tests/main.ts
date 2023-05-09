import {
  VerificationResult,
  Request,
  Response,
  getMinVerificationVersion,
  verifyRequestResponsePair,
} from "../../../pkg";

import fetch from "isomorphic-fetch";
import { idlFactory } from "./http-interface/canister_http_interface";
import {
  HttpRequest,
  _SERVICE,
} from "./http-interface/canister_http_interface_types";
import { HttpAgent, ActorSubclass, Actor, Agent } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";
import assert from "node:assert";

async function createAgentAndActor(
  gatewayUrl: string,
  canisterId: Principal
): Promise<[HttpAgent, ActorSubclass<_SERVICE>]> {
  const agent = new HttpAgent({ host: gatewayUrl, fetch });
  await agent.fetchRootKey();

  const actor = Actor.createActor<_SERVICE>(idlFactory, {
    agent,
    canisterId: canisterId,
  });
  return [agent, actor];
}

async function main(): Promise<void> {
  const replicaAddress = process.env["DFX_REPLICA_ADDRESS"];
  if (!replicaAddress) {
    throw "The `DFX_REPLICA_ADDRESS` env variable was not provided";
  }

  if (process.argv.length === 2) {
    throw "The canister ID arg was not provided";
  }
  const canisterId = process.argv[3];
  const principal = Principal.fromText(canisterId);

  const [agent, actor] = await createAgentAndActor(replicaAddress, principal);

  await v1Test(principal, agent, actor);
  await v2Test(principal, agent, actor);
}

async function v1Test(
  canisterId: Principal,
  agent: Agent,
  actor: ActorSubclass<_SERVICE>
): Promise<void> {
  const resultOne = await performTest(
    canisterId,
    "GET",
    "/",
    null,
    agent,
    actor
  );
  assert(resultOne.passed);
  assert.equal(resultOne.verificationVersion, 1);

  const resultTwo = await performTest(
    canisterId,
    "GET",
    "/",
    null,
    agent,
    actor
  );
  assert(resultTwo.passed);
  assert.equal(resultTwo.verificationVersion, 1);
}

async function v2Test(
  canisterId: Principal,
  agent: Agent,
  actor: ActorSubclass<_SERVICE>
): Promise<void> {
  const resultOne = await performTest(canisterId, "GET", "/", 2, agent, actor);
  assert(resultOne.passed);
  assert.equal(resultOne.verificationVersion, 2);

  const resultTwo = await performTest(canisterId, "GET", "/", 2, agent, actor);
  assert(resultTwo.passed);
  assert.equal(resultTwo.verificationVersion, 2);
}

async function performTest(
  canisterId: Principal,
  method: string,
  url: string,
  certificateVersion: number | null,
  agent: Agent,
  actor: ActorSubclass<_SERVICE>
): Promise<VerificationResult> {
  let httpRequest: HttpRequest = {
    method,
    body: new Uint8Array(),
    certificate_version: certificateVersion ? [certificateVersion] : [],
    headers: [],
    url,
  };

  let httpResponse = await actor.http_request(httpRequest);

  let request: Request = {
    headers: httpRequest.headers,
    method: httpRequest.method,
    url: httpRequest.url,
  };
  let response: Response = {
    body: httpResponse.body,
    headers: httpResponse.headers,
    statusCode: httpResponse.status_code,
  };

  const currentTimeNs = BigInt.asUintN(64, BigInt(Date.now() * 1_000_000)); // from ms to nanoseconds
  const maxCertTimeOffsetNs = BigInt.asUintN(64, BigInt(300_000_000_000));

  if (!agent.rootKey) {
    throw "Agent does not have root key";
  }

  return verifyRequestResponsePair(
    request,
    response,
    canisterId.toUint8Array(),
    currentTimeNs,
    maxCertTimeOffsetNs,
    new Uint8Array(agent.rootKey),
    certificateVersion ?? getMinVerificationVersion()
  );
}

main();
