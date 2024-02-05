import initResponseVerification, {
  verifyRequestResponsePair,
  Request,
  Response,
  ResponseVerificationError,
  ResponseVerificationErrorCode,
  getMinVerificationVersion,
} from '@dfinity/response-verification';
import { Principal } from '@dfinity/principal';

const request: Request = {
  url: '/',
  method: 'GET',
  headers: [['Host', 'rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app']],
  body: new Uint8Array([]),
};

const IC_ROOT_KEY =
  '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae';

function fromHex(hex: string): Uint8Array {
  const buffer = [...hex]
    .reduce((acc, curr, i) => {
      // tslint:disable-next-line:no-bitwise
      acc[(i / 2) | 0] = (acc[(i / 2) | 0] || '') + curr;
      return acc;
    }, [] as string[])
    .map(x => Number.parseInt(x, 16));

  return new Uint8Array(buffer);
}

const response: Response = {
  statusCode: 200,
  headers: [
    [
      'Ic-Certificate',
      'certificate=:2dn3o2R0cmVlgwGDAYMBgwJIY2FuaXN0ZXKDAkoAAAAAAAAABwEBgwGDAYMBgwJOY2VydGlmaWVkX2RhdGGCA1gg2e9+GWTYWw6giMkxjJE7dxUuFMOmoEJ30FFRTOYmZ+6CBFgg/VtZRZdYyK/sr3KF2jWeS1rblF+4ajwfDv2ZbCGpaTiCBFgg6HKEMFmYn9j0sFHRxCCDNXWTLnDMbw4tDvk9Rh2gPymCBFggKBqd8UfSTdcsbnzQLZPXVYsJLM6dc/fi+RlcW9D/WJGCBFgggAG4QoPuBpdUD9ifMs40Cvn9vn0wahLjSTMOBsMV4iCCBFggoawiEDD+DnBTi5j9NjLHMWHFAlWaVk4+26+ulwFUYJ6DAYIEWCALLxLPg6ijOWkcDTm+OEMs7hpk2o44mLtpr9tpcII8XoMCRHRpbWWCA0mvsY3usNqMlRdpc2lnbmF0dXJlWDCGny0r7KOVEzQsoU4URu/jteB+cO4uw8x59WgP3akcM4hQZ2FLVtbWwKgX2OXKBBVqZGVsZWdhdGlvbqJpc3VibmV0X2lkWB1D3K8RgNuC/acIzjrHoDpgYKveE+lUbGDozOZdAmtjZXJ0aWZpY2F0ZVkCbtnZ96JkdHJlZYMBggRYIOdSJxF174WaX2n7+PrVTskgyInEKI4+qd19HkTmpD4ugwGDAkZzdWJuZXSDAYMBgwGCBFggJn/lURG1bjw5dVMuozc/e3Lp+CBy/o5gftNEhkeKWzmDAYIEWCBGanAobPms6YAcpT4ir27gWaCU/WBJhgbUhLaFQFgwfYMBgwGCBFggiy9sFQeK5NO5NHCRXKU+NzMn836nS6G4F32Ya7ebMa6DAlgdQ9yvEYDbgv2nCM46x6A6YGCr3hPpVGxg6MzmXQKDAYMCT2NhbmlzdGVyX3Jhbmdlc4IDWDLZ2feCgkoAAAAAAAAABwEBSgAAAAAAAAAHAQGCSgAAAAACEAAAAQFKAAAAAAIf//8BAYMCSnB1YmxpY19rZXmCA1iFMIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIZ1tjSkPjlyYjjP45yVGLw+MiXLb1qEeb/PK2CPum+FJNy4DzWorkS0fyYvCmYg1BJ58G/gxTpzn8ygGkiSb+ZRo1GbWzKf++zJ8MuQiwmN0+iEXPuZxWN54EmsRl7IBoIEWCCHzSE2R03mBIh5w7cCAFNWUXA9yXLKy5T6Bl/+LuY2ioIEWCBKHXbAjmQuPbaYLmZTvoxzbydaJKwiEINDCy1bRBznVIIEWCAthWu6e2yAFxzo5dEhu35EULNWWmRNkTXp/liEKBwfuYMCRHRpbWWCA0m10ovcy4SWlBdpc2lnbmF0dXJlWDCt6yOQsJ6yXcx8WbPabC32P4fss5zCAYh1/Jal1encJWqqxbAD9Svz7bsCIYWs1Ec=:, tree=:2dn3gwGDAktodHRwX2Fzc2V0c4MBgwGDAkEvggNYIHhMD4Jak4qn9HFYfN98d5b4KPk2JJXiuchJDyIyNZvbggRYINfNCmz1KiBw3FH+HXtqhweIiHGeFoScdIw15/x7aflcggRYIFgrUyEzZkbUjG+L8ZEzM7tOv2XAn/v4IHwBLh9UBxJhggRYICEzSyZoHXIg49LX3LI6iczbGx4ETrNeu+SR9m1AgNB4:',
    ],
  ],
  // prettier-ignore
  body: new Uint8Array([60, 33, 100, 111, 99, 116, 121, 112, 101, 32, 104, 116, 109, 108, 62, 60, 104, 116, 109, 108, 32, 108, 97, 110, 103, 61, 34, 101, 110, 34, 62, 60, 104, 101, 97, 100, 62, 60, 109, 101, 116, 97, 32, 99, 104, 97, 114, 115, 101, 116, 61, 34, 85, 84, 70, 45, 56, 34, 47, 62, 60, 109, 101, 116, 97, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 88, 45, 85, 65, 45, 67, 111, 109, 112, 97, 116, 105, 98, 108, 101, 34, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 73, 69, 61, 101, 100, 103, 101, 34, 47, 62, 60, 109, 101, 116, 97, 32, 110, 97, 109, 101, 61, 34, 118, 105, 101, 119, 112, 111, 114, 116, 34, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 119, 105, 100, 116, 104, 61, 100, 101, 118, 105, 99, 101, 45, 119, 105, 100, 116, 104, 44, 105, 110, 105, 116, 105, 97, 108, 45, 115, 99, 97, 108, 101, 61, 49, 34, 47, 62, 60, 109, 101, 116, 97, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 83, 101, 99, 117, 114, 105, 116, 121, 45, 80, 111, 108, 105, 99, 121, 34, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 100, 101, 102, 97, 117, 108, 116, 45, 115, 114, 99, 32, 39, 110, 111, 110, 101, 39, 59, 99, 111, 110, 110, 101, 99, 116, 45, 115, 114, 99, 32, 39, 115, 101, 108, 102, 39, 32, 104, 116, 116, 112, 115, 58, 47, 47, 105, 99, 48, 46, 97, 112, 112, 32, 104, 116, 116, 112, 115, 58, 47, 47, 42, 46, 105, 99, 48, 46, 97, 112, 112, 59, 105, 109, 103, 45, 115, 114, 99, 32, 39, 115, 101, 108, 102, 39, 32, 100, 97, 116, 97, 58, 59, 115, 99, 114, 105, 112, 116, 45, 115, 114, 99, 32, 39, 115, 104, 97, 50, 53, 54, 45, 97, 101, 79, 100, 111, 77, 76, 122, 86, 43, 113, 109, 107, 73, 100, 97, 89, 105, 51, 100, 81, 74, 43, 97, 80, 120, 85, 81, 76, 70, 68, 97, 73, 106, 52, 49, 47, 99, 120, 57, 68, 99, 65, 61, 39, 32, 39, 117, 110, 115, 97, 102, 101, 45, 105, 110, 108, 105, 110, 101, 39, 32, 39, 117, 110, 115, 97, 102, 101, 45, 101, 118, 97, 108, 39, 32, 39, 115, 116, 114, 105, 99, 116, 45, 100, 121, 110, 97, 109, 105, 99, 39, 32, 104, 116, 116, 112, 115, 58, 59, 98, 97, 115, 101, 45, 117, 114, 105, 32, 39, 110, 111, 110, 101, 39, 59, 102, 111, 114, 109, 45, 97, 99, 116, 105, 111, 110, 32, 39, 110, 111, 110, 101, 39, 59, 115, 116, 121, 108, 101, 45, 115, 114, 99, 32, 39, 115, 101, 108, 102, 39, 32, 39, 117, 110, 115, 97, 102, 101, 45, 105, 110, 108, 105, 110, 101, 39, 32, 104, 116, 116, 112, 115, 58, 47, 47, 102, 111, 110, 116, 115, 46, 103, 111, 111, 103, 108, 101, 97, 112, 105, 115, 46, 99, 111, 109, 59, 115, 116, 121, 108, 101, 45, 115, 114, 99, 45, 101, 108, 101, 109, 32, 39, 115, 101, 108, 102, 39, 32, 39, 117, 110, 115, 97, 102, 101, 45, 105, 110, 108, 105, 110, 101, 39, 32, 104, 116, 116, 112, 115, 58, 47, 47, 102, 111, 110, 116, 115, 46, 103, 111, 111, 103, 108, 101, 97, 112, 105, 115, 46, 99, 111, 109, 59, 102, 111, 110, 116, 45, 115, 114, 99, 32, 104, 116, 116, 112, 115, 58, 47, 47, 102, 111, 110, 116, 115, 46, 103, 115, 116, 97, 116, 105, 99, 46, 99, 111, 109, 59, 117, 112, 103, 114, 97, 100, 101, 45, 105, 110, 115, 101, 99, 117, 114, 101, 45, 114, 101, 113, 117, 101, 115, 116, 115, 59, 34, 32, 47, 62, 60, 116, 105, 116, 108, 101, 62, 73, 110, 116, 101, 114, 110, 101, 116, 32, 73, 100, 101, 110, 116, 105, 116, 121, 60, 47, 116, 105, 116, 108, 101, 62, 60, 108, 105, 110, 107, 32, 114, 101, 108, 61, 34, 115, 104, 111, 114, 116, 99, 117, 116, 32, 105, 99, 111, 110, 34, 32, 116, 121, 112, 101, 61, 34, 105, 109, 97, 103, 101, 47, 106, 112, 103, 34, 32, 104, 114, 101, 102, 61, 34, 46, 47, 102, 97, 118, 105, 99, 111, 110, 46, 105, 99, 111, 34, 47, 62, 60, 108, 105, 110, 107, 32, 114, 101, 108, 61, 34, 115, 116, 121, 108, 101, 115, 104, 101, 101, 116, 34, 32, 104, 114, 101, 102, 61, 34, 46, 47, 105, 110, 100, 101, 120, 46, 99, 115, 115, 34, 47, 62, 60, 47, 104, 101, 97, 100, 62, 60, 98, 111, 100, 121, 62, 60, 109, 97, 105, 110, 32, 105, 100, 61, 34, 112, 97, 103, 101, 67, 111, 110, 116, 101, 110, 116, 34, 32, 99, 108, 97, 115, 115, 61, 34, 108, 45, 119, 114, 97, 112, 34, 32, 97, 114, 105, 97, 45, 108, 105, 118, 101, 61, 34, 112, 111, 108, 105, 116, 101, 34, 62, 60, 47, 109, 97, 105, 110, 62, 60, 100, 105, 118, 32, 105, 100, 61, 34, 110, 111, 116, 105, 102, 105, 99, 97, 116, 105, 111, 110, 34, 62, 60, 47, 100, 105, 118, 62, 60, 100, 105, 118, 32, 105, 100, 61, 34, 108, 111, 97, 100, 101, 114, 67, 111, 110, 116, 97, 105, 110, 101, 114, 34, 62, 60, 47, 100, 105, 118, 62, 60, 115, 99, 114, 105, 112, 116, 32, 100, 97, 116, 97, 45, 99, 97, 110, 105, 115, 116, 101, 114, 45, 105, 100, 61, 34, 114, 100, 109, 120, 54, 45, 106, 97, 97, 97, 97, 45, 97, 97, 97, 97, 97, 45, 97, 97, 97, 100, 113, 45, 99, 97, 105, 34, 32, 105, 100, 61, 34, 115, 101, 116, 117, 112, 74, 115, 34, 62, 108, 101, 116, 32, 115, 32, 61, 32, 100, 111, 99, 117, 109, 101, 110, 116, 46, 99, 114, 101, 97, 116, 101, 69, 108, 101, 109, 101, 110, 116, 40, 39, 115, 99, 114, 105, 112, 116, 39, 41, 59, 115, 46, 97, 115, 121, 110, 99, 32, 61, 32, 116, 114, 117, 101, 59, 115, 46, 115, 114, 99, 32, 61, 32, 39, 105, 110, 100, 101, 120, 46, 106, 115, 39, 59, 100, 111, 99, 117, 109, 101, 110, 116, 46, 104, 101, 97, 100, 46, 97, 112, 112, 101, 110, 100, 67, 104, 105, 108, 100, 40, 115, 41, 59, 60, 47, 115, 99, 114, 105, 112, 116, 62, 60, 47, 98, 111, 100, 121, 62, 60, 47, 104, 116, 109, 108, 62]),
};

const canister_id = Principal.fromText(
  'rdmx6-jaaaa-aaaaa-aaadq-cai',
).toUint8Array();

const current_time_ns = BigInt(1669202493944584367);
const max_cert_time_offset_ns = BigInt(300_000_000_000);

window.addEventListener('load', async () => {
  await initResponseVerification();

  try {
    const result = verifyRequestResponsePair(
      request,
      response,
      canister_id,
      current_time_ns,
      max_cert_time_offset_ns,
      fromHex(IC_ROOT_KEY),
      getMinVerificationVersion(),
    );

    console.log('Result', result);
  } catch (error) {
    console.log('Error', error);

    if (error instanceof ResponseVerificationError) {
      switch (error.code) {
        case ResponseVerificationErrorCode.CborDecodingFailed:
          console.log(`Error parsing cbor: ${error.message}`);
          break;

        case ResponseVerificationErrorCode.CertificateVerificationFailed:
          console.log(`Certificate verification failed: ${error.message}`);
          break;
      }
    }
  }
});
