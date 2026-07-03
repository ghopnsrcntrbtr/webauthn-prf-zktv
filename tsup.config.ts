import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'webauthn/index': 'src/webauthn/index.ts',
    'indexeddb/index': 'src/indexeddb/index.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  target: 'es2022',
  sourcemap: true,
});
