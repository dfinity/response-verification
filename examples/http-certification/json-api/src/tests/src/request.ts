export const CERTIFICATE_VERSION = 2;

export function jsonEncode<T>(data: T): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(data));
}
