export interface TestCase {
  url: string;
  responsePath: string;
}

export const TEST_CASES: TestCase[] = [
  // /index.html
  { url: '/', responsePath: 'index.html' },
  { url: '/index.html', responsePath: 'index.html' },
  { url: '/index', responsePath: 'index.html' },

  // /world.html
  { url: '/world', responsePath: 'world.html' },
  { url: '/world.html', responsePath: 'world.html' },

  // /hello/index.html
  { url: '/hello', responsePath: 'hello/index.html' },
  { url: '/hello/', responsePath: 'hello/index.html' },
  { url: '/hello/index.html', responsePath: 'hello/index.html' },
  { url: '/hello/index', responsePath: 'hello/index.html' },

  // /sample-asset.txt
  { url: '/sample-asset.txt', responsePath: 'sample-asset.txt' },
  { url: '/%73ample-asset.txt', responsePath: 'sample-asset.txt' },

  // /another%20sample%20asset.txt
  {
    url: '/another%20sample%20asset.txt',
    responsePath: 'another sample asset.txt',
  },

  // /capture-d’écran-2023-10-26-à.txt
  {
    url: '/capture-d%E2%80%99e%CC%81cran-2023-10-26-a%CC%80.txt',
    responsePath: 'capture-d’écran-2023-10-26-à.txt',
  },

  // /index.html fallback
  { url: '/not-found', responsePath: 'index.html' },
  { url: '/not-found/', responsePath: 'index.html' },
  { url: '/not/found', responsePath: 'index.html' },
  { url: '/not/found/', responsePath: 'index.html' },
  { url: '/a/b/not-found', responsePath: 'index.html' },
  { url: '/world/', responsePath: 'index.html' },
  { url: '/world/not-found', responsePath: 'index.html' },
  // currently broken: see SDK-1298
  // { url: '/hello/not-found', responsePath: 'index.html' },
];
