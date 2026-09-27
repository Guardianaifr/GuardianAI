import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = fileURLToPath(new URL('.', import.meta.url))

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  define: {
    'global': 'globalThis',
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
      // Local workspace package — no npm install needed; Vite resolves it directly
      "@guardianai/middleware": path.resolve(__dirname, "../packages/guardian-middleware/src/index.ts"),
      buffer: "buffer/",
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8001',
        changeOrigin: true,
        secure: false,
      },
      '/ws/threats': {
        target: 'ws://127.0.0.1:8001',
        ws: true,
        changeOrigin: true,
      }
    }
  }
})

