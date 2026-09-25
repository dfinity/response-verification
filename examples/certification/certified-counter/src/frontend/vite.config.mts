import { execSync } from 'node:child_process';
import { defineConfig, type ServerOptions } from 'vite';
import checker from 'vite-plugin-checker';
import { viteStaticCopy } from 'vite-plugin-static-copy';

const environment = process.env.ICP_ENVIRONMENT || 'local';
const BACKEND_CANISTER = 'certification_certified_counter_backend';

function icp(args: string): string {
  return execSync(`icp ${args}`, { encoding: 'utf-8', stdio: 'pipe' }).trim();
}

// The frontend canister sets the `ic_env` cookie in production. The dev server
// simulates it from the running network, so the backend must already be deployed.
function getDevServerConfig(): ServerOptions {
  const networkStatus = JSON.parse(
    icp(`network status -e ${environment} --json`),
  );
  const canisterId = icp(
    `canister status ${BACKEND_CANISTER} -e ${environment} --id-only`,
  );
  const icEnv = `PUBLIC_CANISTER_ID:${BACKEND_CANISTER}=${canisterId}&ic_root_key=${networkStatus.root_key}`;

  return {
    headers: {
      'Set-Cookie': `ic_env=${encodeURIComponent(icEnv)}; SameSite=Lax;`,
    },
    proxy: {
      '/api': { target: networkStatus.api_url, changeOrigin: true },
    },
  };
}

export default defineConfig(({ command }) => {
  return {
    plugins: [
      checker({ typescript: true }),
      viteStaticCopy({
        targets: [
          {
            src: '.ic-assets.json',
            dest: '.',
          },
        ],
      }),
    ],
    optimizeDeps: {
      esbuildOptions: {
        define: {
          global: 'globalThis',
        },
      },
    },
    ...(command === 'serve' ? { server: getDevServerConfig() } : {}),
  };
});
