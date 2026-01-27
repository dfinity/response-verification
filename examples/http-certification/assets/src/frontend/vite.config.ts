import { defineConfig } from 'vite';
import solidPlugin from 'vite-plugin-solid';

// import the compression plugin
import { compression } from 'vite-plugin-compression2';

export default defineConfig({
  plugins: [
    solidPlugin(),

    // setup Gzip compression
    compression({
      algorithm: 'gzip',
      // this extension will be referenced later in the canister code
      ext: '.gz',
      // ensure to not delete the original files
      deleteOriginalAssets: false,
      threshold: 0,
    }),

    // setup Brotli compression
    compression({
      algorithm: 'brotliCompress',
      // this extension will be referenced later in the canister code
      ext: '.br',
      // ensure to not delete the original files
      deleteOriginalAssets: false,
      threshold: 0,
    }),
  ],
  server: {
    port: 3000,
  },
  build: {
    target: 'esnext',
  },
});
