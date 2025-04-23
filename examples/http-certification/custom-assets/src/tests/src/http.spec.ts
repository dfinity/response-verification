import { Actor, PocketIc, PocketIcServer } from '@dfinity/pic';
import { Principal } from '@dfinity/principal';
import {
  verifyRequestResponsePair,
  Request,
} from '@dfinity/response-verification';
import { resolve } from 'path';
import { readFile } from 'fs/promises';

import {
  _SERVICE,
  HeaderField,
} from '../../declarations/http_certification_custom_assets_backend.did';
import { setupBackendCanister } from './wasm';

const CERTIFICATE_VERSION = 2;
const NS_PER_MS = 1e6;
const MS_PER_S = 1e3;
const S_PER_MIN = 60;

interface Metrics {
  cycle_balance: number;
}

describe('Assets', () => {
  let picServer: PocketIcServer;
  let pic: PocketIc;
  let actor: Actor<_SERVICE>;
  let canisterId: Principal;

  let rootKey: ArrayBufferLike;

  const currentDate = new Date(2021, 6, 10, 0, 0, 0, 0);
  const currentTimeNs = BigInt(currentDate.getTime() * NS_PER_MS);
  const maxCertTimeOffsetNs = BigInt(5 * S_PER_MIN * MS_PER_S * NS_PER_MS);

  beforeAll(async () => {
    picServer = await PocketIcServer.start();
  });

  afterAll(async () => {
    picServer.stop();
  });

  beforeEach(async () => {
    pic = await PocketIc.create(picServer.getUrl());
    const fixture = await setupBackendCanister(pic, currentDate);
    actor = fixture.actor;
    canisterId = fixture.canisterId;

    const subnets = await pic.getApplicationSubnets();
    rootKey = await pic.getPubKey(subnets[0].id);
  });

  afterEach(async () => {
    await pic.tearDown();
  });

  it('should serve uncertified metrics', async () => {
    const request: Request = {
      url: '/metrics',
      method: 'GET',
      headers: [],
      body: new Uint8Array(),
      certificate_version: [],
    };

    const response = await actor.http_request(request);
    const textBody = new TextDecoder().decode(Uint8Array.from(response.body));
    const jsonBody = JSON.parse(textBody) as Metrics;
    const currentCycles = await pic.getCyclesBalance(canisterId);

    expect(response.status_code).toBe(200);
    expect(jsonBody).toEqual({
      cycle_balance: currentCycles,
    });
    expectSecurityHeaders(response.headers);
    expectHeader(response.headers, ['content-type', 'application/json']);
    expectHeader(response.headers, [
      'cache-control',
      'public, no-cache, no-store',
    ]);

    let verificationResult = verifyRequestResponsePair(
      request,
      response,
      canisterId.toUint8Array(),
      currentTimeNs,
      maxCertTimeOffsetNs,
      new Uint8Array(rootKey),
      CERTIFICATE_VERSION,
    );

    expect(verificationResult.verificationVersion).toEqual(CERTIFICATE_VERSION);
    expect(verificationResult.response).toBeUndefined();
  });

  // paths must be updated if the asset content changes
  [
    // root path
    {
      url: '/',
      asset: 'index.html',
      encoding: 'identity',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/',
      asset: 'index.html.br',
      encoding: 'identity, gzip, br',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/',
      asset: 'index.html.gzip',
      encoding: 'identity, gzip',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    // direct request for /index.html
    {
      url: '/index.html',
      asset: 'index.html',
      encoding: 'identity',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/index.html',
      asset: 'index.html.br',
      encoding: 'identity, gzip, br',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/index.html',
      asset: 'index.html.gzip',
      encoding: 'identity, gzip',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    // fallback to index.html
    {
      url: '/fake-path',
      asset: 'index.html',
      encoding: 'identity',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/fake-path',
      asset: 'index.html.br',
      encoding: 'identity, gzip, br',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/fake-path',
      asset: 'index.html.gzip',
      encoding: 'identity, gzip',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    // nested fallback to index.html
    {
      url: '/nested/fake-path',
      asset: 'index.html',
      encoding: 'identity',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/nested/fake-path',
      asset: 'index.html.br',
      encoding: 'identity, gzip, br',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/nested/fake-path',
      asset: 'index.html.gzip',
      encoding: 'identity, gzip',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    // fallback in assets folder to index.html
    {
      url: '/assets/fake-path',
      asset: 'index.html',
      encoding: 'identity',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/assets/fake-path',
      asset: 'index.html.br',
      encoding: 'identity, gzip, br',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    {
      url: '/assets/fake-path',
      asset: 'index.html.gzip',
      encoding: 'identity, gzip',
      contentType: 'text/html',
      cacheControl: 'public, no-cache, no-store',
    },
    // js file
    {
      url: '/assets/index-CuiVGY1H.js',
      asset: 'assets/index-CuiVGY1H.js',
      encoding: 'identity',
      contentType: 'text/javascript',
      cacheControl: 'public, max-age=31536000, immutable',
    },
    {
      url: '/assets/index-CuiVGY1H.js',
      asset: 'assets/index-CuiVGY1H.js.br',
      encoding: 'identity, gzip, br',
      contentType: 'text/javascript',
      cacheControl: 'public, max-age=31536000, immutable',
    },
    {
      url: '/assets/index-CuiVGY1H.js',
      asset: 'assets/index-CuiVGY1H.js.gzip',
      encoding: 'identity, gzip',
      contentType: 'text/javascript',
      cacheControl: 'public, max-age=31536000, immutable',
    },
    // css file
    {
      url: '/assets/index-CsnN7p86.css',
      asset: 'assets/index-CsnN7p86.css',
      encoding: 'identity',
      contentType: 'text/css',
      cacheControl: 'public, max-age=31536000, immutable',
    },
    {
      url: '/assets/index-CsnN7p86.css',
      asset: 'assets/index-CsnN7p86.css.br',
      encoding: 'identity, gzip, br',
      contentType: 'text/css',
      cacheControl: 'public, max-age=31536000, immutable',
    },
    {
      url: '/assets/index-CsnN7p86.css',
      asset: 'assets/index-CsnN7p86.css.gzip',
      encoding: 'identity, gzip',
      contentType: 'text/css',
      cacheControl: 'public, max-age=31536000, immutable',
    },
    // favicon
    {
      url: '/assets/favicon-mtvwWgEY.ico',
      asset: 'assets/favicon-mtvwWgEY.ico',
      encoding: 'identity',
      contentType: 'image/x-icon',
      cacheControl: 'public, max-age=31536000, immutable',
    },
  ].forEach(({ url, asset, encoding, contentType, cacheControl }) => {
    it(`should return "${asset}" for "${url}" with "${encoding}" encoding`, async () => {
      const indexHtml = await loadAsset(asset);
      const request: Request = {
        url,
        method: 'GET',
        headers: [['Accept-Encoding', encoding]],
        body: new Uint8Array(),
        certificate_version: [],
      };

      const response = await actor.http_request(request);

      expect(response.status_code).toBe(200);
      expect(response.body).toEqual(indexHtml);
      expectSecurityHeaders(response.headers);
      expectHeader(response.headers, ['content-type', contentType]);
      expectHeader(response.headers, ['cache-control', cacheControl]);

      let verificationResult = verifyRequestResponsePair(
        request,
        response,
        canisterId.toUint8Array(),
        currentTimeNs,
        maxCertTimeOffsetNs,
        new Uint8Array(rootKey),
        CERTIFICATE_VERSION,
      );

      expect(verificationResult.verificationVersion).toEqual(
        CERTIFICATE_VERSION,
      );

      const verifiedResponse = verificationResult.response;
      expect(verifiedResponse?.statusCode).toBe(200);
      expect(verifiedResponse?.body).toEqual(response.body);
      expectSecurityHeaders(verifiedResponse?.headers);
      expectHeader(verifiedResponse?.headers, ['content-type', contentType]);
      expectHeader(verifiedResponse?.headers, ['cache-control', cacheControl]);
    });
  });

  function expectSecurityHeaders(headers: HeaderField[] = []): void {
    expectHeader(headers, [
      'strict-transport-security',
      'max-age=31536000; includeSubDomains',
    ]);
    expectHeader(headers, ['x-frame-options', 'DENY']);
    expectHeader(headers, ['x-content-type-options', 'nosniff']);
    expectHeader(headers, [
      'content-security-policy',
      "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content",
    ]);
    expectHeader(headers, ['referrer-policy', 'no-referrer']);
    expectHeader(headers, [
      'permissions-policy',
      'accelerometer=(),ambient-light-sensor=(),autoplay=(),battery=(),camera=(),display-capture=(),document-domain=(),encrypted-media=(),fullscreen=(),gamepad=(),geolocation=(),gyroscope=(),layout-animations=(self),legacy-image-formats=(self),magnetometer=(),microphone=(),midi=(),oversized-images=(self),payment=(),picture-in-picture=(),publickey-credentials-get=(),speaker-selection=(),sync-xhr=(self),unoptimized-images=(self),unsized-media=(self),usb=(),screen-wake-lock=(),web-share=(),xr-spatial-tracking=()',
    ]);
    expectHeader(headers, ['cross-origin-embedder-policy', 'require-corp']);
    expectHeader(headers, ['cross-origin-opener-policy', 'same-origin']);
  }

  function expectHeader(
    headers: HeaderField[] = [],
    header: HeaderField,
  ): void {
    expect(headers).toContainEqual(header);
  }

  async function loadAsset(path: string): Promise<Uint8Array> {
    const fullPath = resolve(__dirname, '../../frontend/dist', path);
    const buffer = await readFile(fullPath);
    return Uint8Array.from(buffer);
  }
});
