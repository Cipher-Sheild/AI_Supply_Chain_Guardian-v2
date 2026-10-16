import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({ plugins: [react()], server: { host: "127.0.0.1", port: 3000, proxy: { '/api': { target: (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env.TRUST_ENGINE_URL || 'http://127.0.0.1:8000', changeOrigin: true, rewrite: path => path.replace(/^\/api/, '') } } } });
