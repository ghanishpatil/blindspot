import { fileURLToPath, URL } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
// defineConfig from vitest/config re-exports Vite's own and adds the `test` key types.
import { defineConfig } from 'vitest/config';
export default defineConfig({
    plugins: [react(), tailwindcss()],
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./src', import.meta.url)),
        },
    },
    server: {
        host: '127.0.0.1',
        port: 5173,
        strictPort: true,
    },
    preview: {
        host: '127.0.0.1',
        port: 4173,
    },
    build: {
        outDir: 'dist',
        sourcemap: true,
    },
    test: {
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./src/test/setup.ts'],
        css: true,
        include: ['src/**/*.{test,spec}.{ts,tsx}'],
    },
});
