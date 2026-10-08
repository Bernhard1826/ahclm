import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

function configuredPort(name: string, fallback: number): number {
	const raw = process.env[name];
	if (!raw) return fallback;
	const value = Number.parseInt(raw, 10);
	if (!Number.isInteger(value) || value < 1 || value > 65535) {
		throw new Error(`${name} must be set to a port in 1..65535`);
	}
	return value;
}

const frontendPort = configuredPort('AHCLM_FRONTEND_PORT', 25173);
const apiProxy = (process.env.AHCLM_API_PROXY_TARGET || process.env.AHCLM_API_PROXY || 'http://127.0.0.1:28000').trim();
const frontendHost = (process.env.AHCLM_FRONTEND_HOST || '127.0.0.1').trim();

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
	server: {
		host: frontendHost,
		port: frontendPort,
    strictPort: true,
    proxy: {
      '/api': {
			target: apiProxy,
        changeOrigin: true,
      },
    },
  },
});
