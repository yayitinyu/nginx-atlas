import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: fileURLToPath(new URL('../internal/ui/dist', import.meta.url)),
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:9090',
      '/healthz': 'http://127.0.0.1:9090',
      '/install.sh': 'http://127.0.0.1:9090',
    },
  },
})
