import {defineConfig} from 'vite'
import react from '@vitejs/plugin-react'

// In dev, /api is proxied to the backend. Use 127.0.0.1 (not "localhost"):
// on Node 17+ "localhost" can resolve to IPv6 (::1) while the backend listens on IPv4,
// which caused "cannot connect to backend" errors.
const target = process.env.VITE_API_TARGET || 'http://127.0.0.1:8000'
export default defineConfig({
  plugins: [react()],
  server: {host: true, port: 5173, proxy: {'/api': {target, changeOrigin: true}}},
})
