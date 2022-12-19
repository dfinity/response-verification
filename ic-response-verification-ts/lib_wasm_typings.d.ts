export * from "./lib_wasm_web_opt/lib_wasm_web";
import init, { Request, Response } from "./lib_wasm_web_opt/lib_wasm_web";

export function verifyRequestResponsePair(
  request: Request,
  response: Response,
  canister_id: Uint8Array,
  current_time_ns: bigint,
  max_cert_time_offset_ns: bigint
): boolean;

export default init;
