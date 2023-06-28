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
      external: ['@dfinity/agent', '@dfinity/principal', '@dfinity/candid'],
      output: {
        globals: {
          '@dfinity/agent': 'dfinity-agent',
          '@dfinity/principal': 'dfinity-principal',
          '@dfinity/candid': 'dfinity-candid',
        },
      },
    },
  },
});
