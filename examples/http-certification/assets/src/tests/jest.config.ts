import type { Config } from 'jest';

const config: Config = {
  watch: false,
  preset: 'ts-jest/presets/js-with-ts',
  testEnvironment: 'node',
  verbose: true,
  testTimeout: 30_000,
};

export default config;
