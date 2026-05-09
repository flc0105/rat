import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],

  resolve: {
    alias: {
      vue: 'vue/dist/vue.esm-bundler.js',
    },
  },

  server: {
    port: 5173,
    host: '0.0.0.0',
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8085',
        changeOrigin: true,
        ws: true,
      },

      '/ws': {
        target: 'ws://127.0.0.1:8085',
        changeOrigin: true,
        ws: true,
      },
    },
  },
})