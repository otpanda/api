import js from '@eslint/js';
import globals from 'globals';

// Lint config for the Worker, tests and tooling. CI installs eslint without
// touching package.json or the lockfile (see .github/workflows/test.yml).
export default [
  {ignores: ['dist/**', 'node_modules/**', '.wrangler/**']},
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {...globals.serviceworker, ...globals.node},
    },
    rules: {
      // Unused names are reported but do not fail CI; real bugs below do.
      'no-unused-vars': ['warn', {argsIgnorePattern: '^_', caughtErrors: 'none'}],
      // Input validation intentionally rejects control characters.
      'no-control-regex': 'off',
      'no-empty': ['error', {allowEmptyCatch: true}],
    },
  },
  {files: ['**/*.cjs'], languageOptions: {sourceType: 'commonjs'}},
  {
    // Browser-side check scripts evaluate code inside a page that defines this.
    files: ['tool/auth-only-browser/**'],
    languageOptions: {globals: {OTPandaSession: 'readonly'}},
  },
];
