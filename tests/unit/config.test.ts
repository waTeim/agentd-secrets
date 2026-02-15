import path from 'path';

describe('Config', () => {
  const originalEnv = process.env;
  const fixtureConfig = path.join(__dirname, '..', 'fixtures', 'config.yaml');

  beforeEach(() => {
    jest.resetModules();
    process.env = {
      ...originalEnv,
      OIDC_ISSUER_URL: 'https://idp.example.com/realms/myrealm',
      OIDC_REALM: 'myrealm',
      OIDC_CLIENT_ID: 'agentd-secrets',
      OIDC_CLIENT_SECRET: 'test-secret',
      OIDC_AUDIENCE: 'agentd-secrets',
      VAULT_ADDR: 'https://vault.example.com',
      VAULT_OIDC_MOUNT: 'oidc',
      VAULT_OIDC_ROLE: 'agentd-secrets',
      VAULT_KV_MOUNT: 'secret',
      VAULT_WRAP_TTL: '300s',
      WRAPTOKEN_ENC_KEY: 'a'.repeat(64),
      BROKER_LISTEN_ADDR: ':8080',
      BROKER_CONFIG_PATH: fixtureConfig,
      OIDC_USERNAME: 'approver',
      OIDC_PASSWORD: 'password123',
      OIDC_LOCAL_LISTEN_HOST: '127.0.0.1',
      OIDC_LOCAL_LISTEN_PORT: '8250',
      OIDC_LOCAL_REDIRECT_URI: 'http://localhost:8250/oidc/callback',
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  test('loadConfig succeeds with valid env', () => {
    const { loadConfig } = require('../../src/config');
    const config = loadConfig();
    expect(config.oidc.issuerURL).toBe('https://idp.example.com/realms/myrealm');
    expect(config.oidc.clientID).toBe('agentd-secrets');
    expect(config.vault.addr).toBe('https://vault.example.com');
    expect(config.vault.oidcMount).toBe('oidc');
    expect(config.vault.oidcRole).toBe('agentd-secrets');
    expect(config.vault.kvMount).toBe('secret');
    expect(config.vault.wrapTTL).toBe('300s');
    expect(config.oidcCallback.listenHost).toBe('127.0.0.1');
    expect(config.oidcCallback.listenPort).toBe(8250);
    expect(config.oidcCallback.redirectURI).toBe('http://localhost:8250/oidc/callback');
    expect(config.listenPort).toBe(8080);
    expect(config.login.username).toBe('approver');
    expect(config.serviceRegistry.services['payroll-db']).toBeDefined();
    expect(config.serviceRegistry.services['test-service']).toBeDefined();
  });

  test('loadConfig throws on missing required env', () => {
    delete process.env.VAULT_ADDR;
    const { loadConfig } = require('../../src/config');
    expect(() => loadConfig()).toThrow('VAULT_ADDR');
  });

  test('loadConfig throws on invalid WRAPTOKEN_ENC_KEY', () => {
    process.env.WRAPTOKEN_ENC_KEY = 'tooshort';
    const { loadConfig } = require('../../src/config');
    expect(() => loadConfig()).toThrow('64 hex characters');
  });

  test('loadConfig throws on missing config file', () => {
    process.env.BROKER_CONFIG_PATH = '/nonexistent/path.yaml';
    const { loadConfig } = require('../../src/config');
    expect(() => loadConfig()).toThrow();
  });
});

describe('TTL helpers', () => {
  const { parseTTL, capTTL, ttlToVaultString } = require('../../src/config');

  test('parseTTL handles various formats', () => {
    expect(parseTTL('5m')).toBe(300_000);
    expect(parseTTL('10s')).toBe(10_000);
    expect(parseTTL('1h')).toBe(3600_000);
    expect(parseTTL('500ms')).toBe(500);
    expect(parseTTL('30')).toBe(30_000); // default to seconds
    expect(parseTTL('')).toBe(0);
    expect(parseTTL('invalid')).toBe(0);
  });

  test('capTTL returns default when no request TTL', () => {
    const service = { wrap: { max_ttl: '10m', default_ttl: '5m' } };
    expect(capTTL(undefined, service)).toBe(300_000);
    expect(capTTL('', service)).toBe(300_000);
  });

  test('capTTL caps to max_ttl', () => {
    const service = { wrap: { max_ttl: '10m', default_ttl: '5m' } };
    expect(capTTL('15m', service)).toBe(600_000); // capped to 10m
    expect(capTTL('3m', service)).toBe(180_000);  // under max
  });

  test('ttlToVaultString formats correctly', () => {
    expect(ttlToVaultString(3600_000)).toBe('1h');
    expect(ttlToVaultString(300_000)).toBe('5m');
    expect(ttlToVaultString(45_000)).toBe('45s');
  });
});

describe('validateServiceExists', () => {
  const originalEnv = process.env;
  const fixtureConfig = path.join(__dirname, '..', 'fixtures', 'config.yaml');

  beforeEach(() => {
    jest.resetModules();
    process.env = {
      ...originalEnv,
      OIDC_ISSUER_URL: 'https://idp.example.com/realms/myrealm',
      OIDC_CLIENT_ID: 'agentd-secrets',
      OIDC_CLIENT_SECRET: 'secret',
      VAULT_ADDR: 'https://vault.example.com',
      WRAPTOKEN_ENC_KEY: 'a'.repeat(64),
      BROKER_CONFIG_PATH: fixtureConfig,
      OIDC_USERNAME: 'approver',
      OIDC_PASSWORD: 'pw',
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  test('returns service entry if exists', () => {
    const { loadConfig, validateServiceExists } = require('../../src/config');
    const config = loadConfig();
    const entry = validateServiceExists(config, 'payroll-db');
    expect(entry).not.toBeNull();
    expect(entry!.vault.kv2_mount).toBe('secret');
  });

  test('returns null for unknown service', () => {
    const { loadConfig, validateServiceExists } = require('../../src/config');
    const config = loadConfig();
    expect(validateServiceExists(config, 'nonexistent')).toBeNull();
  });
});
