import { defineConfig } from 'vite';
import checker from 'vite-plugin-checker';
import { viteStaticCopy } from 'vite-plugin-static-copy';

export default defineConfig({
  plugins: [
    checker({ typescript: true }),
    viteStaticCopy({
      targets: [
        {
          src: '.ic-assets.json',
          dest: '.',
        },
        {
          src: 'src/assets',
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
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
});
