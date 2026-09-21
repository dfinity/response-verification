import { resolve } from 'path';
import { defineConfig } from 'vitest/config';
import checker from 'vite-plugin-checker';

export default defineConfig({
  plugins: [checker({ typescript: true })],
  build: {
    lib: {
      entry: resolve(__dirname, 'src', 'index.ts'),
      name: '@dfinity/certificate-verification',
      fileName: 'certificate-verification',
    },
    sourcemap: true,
    rollupOptions: {
      external: [
        '@icp-sdk/core/agent',
        '@icp-sdk/core/principal',
        '@icp-sdk/core/candid',
      ],
      output: {
        globals: {
          '@icp-sdk/core/agent': 'icp-core-agent',
          '@icp-sdk/core/principal': 'icp-core-principal',
          '@icp-sdk/core/candid': 'icp-core-candid',
        },
      },
    },
  },
});
