import { defineConfig, loadEnv } from 'vite';
import checker from 'vite-plugin-checker';
import { viteStaticCopy } from 'vite-plugin-static-copy';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '../../../../../', '');

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
    define: {
      'process.env': {
        CANISTER_ID_CERTIFICATION_CERTIFIED_COUNTER_BACKEND:
          env.CANISTER_ID_CERTIFICATION_CERTIFIED_COUNTER_BACKEND,
        DFX_NETWORK: env.DFX_NETWORK,
      },
    },
    server: {
      proxy: {
        '/api': 'http://127.0.0.1:8000',
      },
    },
  };
});
