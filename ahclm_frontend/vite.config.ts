import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

function requiredPort(name: string): number {
	const value = Number.parseInt(process.env[name] || '', 10);
	if (!Number.isInteger(value) || value < 1 || value > 65535) {
		throw new Error(`${name} must be set to a port in 1..65535`);
	}
	return value;
}

const frontendPort = requiredPort('AHCLM_FRONTEND_PORT');
const apiProxy = (process.env.AHCLM_API_PROXY || '').trim();
if (!apiProxy) {
	throw new Error('AHCLM_API_PROXY must be set; the frontend has no implicit backend address');
}
const frontendHost = (process.env.AHCLM_FRONTEND_HOST || '').trim();
if (!frontendHost) {
	throw new Error('AHCLM_FRONTEND_HOST must be set');
}

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
