export * from './lib_wasm_web_opt/lib_wasm_web';
import init, { Request, Response } from './lib_wasm_web_opt/lib_wasm_web';

export function verifyRequestResponsePair(
  request: Request,
  response: Response,
  canister_id: Uint8Array,
): boolean;

export default init;
