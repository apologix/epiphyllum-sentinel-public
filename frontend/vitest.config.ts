import {defineConfig} from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {alias: {'@': path.resolve(__dirname, './src')}},
  // testTimeout: la VM comparte 1,5 CPU y las pruebas con componentes
  // animados (motion) superaban los 5 s por defecto solo por contención
  // en la corrida paralela completa (pasan aisladas); 15 s no cambia
  // ninguna aserción, solo el presupuesto de espera (UI-ARC-05).
  test: {include: ['src/**/*.test.{ts,tsx}'], setupFiles: ['./src/test-setup.ts'], testTimeout: 15000},
});
