import { defineConfig } from 'vite';
import solidPlugin from 'vite-plugin-solid';

// import the compression plugin
import { compression } from 'vite-plugin-compression2';

export default defineConfig({
  plugins: [
    solidPlugin(),

    // setup Gzip compression
    compression({
      algorithms: ['gzip'],
      // this extension will be referenced later in the canister code
      filename: '[path][base].gz',
      // ensure to not delete the original files
      deleteOriginalAssets: false,
      threshold: 0,
    }),

    // setup Brotli compression
    compression({
      algorithms: ['brotliCompress'],
      // this extension will be referenced later in the canister code
      filename: '[path][base].br',
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
