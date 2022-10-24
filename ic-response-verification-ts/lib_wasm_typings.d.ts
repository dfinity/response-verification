export * from './lib_wasm_web';
import init, { Request, Response } from './lib_wasm_web';

export function verifyRequestResponsePair(
  request: Request,
  response: Response,
): boolean;

export default init;
