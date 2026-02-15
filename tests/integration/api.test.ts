import express from 'express';
import http from 'http';
import crypto from 'crypto';
import * as jose from 'jose';
import path from 'path';
import { RequestStore } from '../../src/requestStore';
import { Worker } from '../../src/worker';
import { VaultClient } from '../../src/vaultClient';
import { VaultOidcManager } from '../../src/auth/vaultOidcCliFlow';
import { createApiRouter, createHealthRouter } from '../../src/routes';
import { Config, loadConfig } from '../../src/config';

// Stub VaultOidcManager that skips the real OIDC flow
class MockVaultOidcManager {
  async ensureToken(): Promise<void> {
    // Token is pre-set on the VaultClient; nothing to do
  }
}

describe('API Integration Tests', () => {
  const encKeyHex = crypto.randomBytes(32).toString('hex');
  const encKey = Buffer.from(encKeyHex, 'hex');
  const fixtureConfig = path.join(__dirname, '..', 'fixtures', 'config.yaml');
  const issuer = 'https://idp.example.com/realms/test';
  const audience = 'agentd-secrets';

  let jwksServer: http.Server;
  let jwksPort: number;
  let privateKey: jose.KeyLike;

  let oidcDiscoveryServer: http.Server;
  let oidcPort: number;

  let vaultServer: http.Server;
  let vaultPort: number;

  let appServer: http.Server;
  let appPort: number;

  let store: RequestStore;

  beforeAll(async () => {
    // Generate RSA key pair
    const keyPair = await jose.generateKeyPair('RS256');
    privateKey = keyPair.privateKey;
    const jwk = await jose.exportJWK(keyPair.publicKey);
    jwk.kid = 'test-key-1';
    jwk.alg = 'RS256';
    jwk.use = 'sig';

    // Mock OIDC provider (OIDC discovery + JWKS + token endpoint)
    const kcApp = express();
    kcApp.get('/realms/test/.well-known/openid-configuration', (_req, res) => {
      res.json({
        issuer: `http://127.0.0.1:${oidcPort}/realms/test`,
        authorization_endpoint: `http://127.0.0.1:${oidcPort}/realms/test/protocol/openid-connect/auth`,
        token_endpoint: `http://127.0.0.1:${oidcPort}/realms/test/protocol/openid-connect/token`,
        jwks_uri: `http://127.0.0.1:${oidcPort}/realms/test/protocol/openid-connect/certs`,
      });
    });
    kcApp.get('/realms/test/protocol/openid-connect/certs', (_req, res) => {
      res.json({ keys: [jwk] });
    });
    kcApp.use(express.urlencoded({ extended: true }));
    kcApp.post('/realms/test/protocol/openid-connect/token', async (_req, res) => {
      // Return a mock access token
      const token = await new jose.SignJWT({ sub: 'approver' })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
        .setIssuer(`http://127.0.0.1:${oidcPort}/realms/test`)
        .setAudience(audience)
        .setExpirationTime('5m')
        .setIssuedAt()
        .sign(privateKey);
      res.json({
        access_token: token,
        token_type: 'Bearer',
        expires_in: 300,
      });
    });

    oidcDiscoveryServer = await new Promise<http.Server>((resolve) => {
      const s = kcApp.listen(0, '127.0.0.1', () => resolve(s));
    });
    oidcPort = (oidcDiscoveryServer.address() as { port: number }).port;

    // Mock Vault
    const vaultApp = express();
    vaultApp.use(express.json());
    vaultApp.get('/v1/sys/health', (_req, res) => {
      res.json({ initialized: true, sealed: false });
    });
    vaultApp.get('/v1/secret/data/*', (req, res) => {
      res.json({
        wrap_info: {
          token: 'hvs.mock-wrap-token-' + crypto.randomBytes(8).toString('hex'),
          ttl: 300,
          creation_time: new Date().toISOString(),
        },
      });
    });

    vaultServer = await new Promise<http.Server>((resolve) => {
      const s = vaultApp.listen(0, '127.0.0.1', () => resolve(s));
    });
    vaultPort = (vaultServer.address() as { port: number }).port;

    // Set up env and load config
    process.env.OIDC_ISSUER_URL = `http://127.0.0.1:${oidcPort}/realms/test`;
    process.env.OIDC_REALM = 'test';
    process.env.OIDC_CLIENT_ID = 'agentd-secrets';
    process.env.OIDC_CLIENT_SECRET = 'test-secret';
    process.env.OIDC_AUDIENCE = audience;
    process.env.VAULT_ADDR = `http://127.0.0.1:${vaultPort}`;
    process.env.VAULT_OIDC_MOUNT = 'oidc';
    process.env.VAULT_OIDC_ROLE = 'agentd-secrets';
    process.env.VAULT_KV_MOUNT = 'secret';
    process.env.VAULT_WRAP_TTL = '300s';
    process.env.WRAPTOKEN_ENC_KEY = encKeyHex;
    process.env.BROKER_CONFIG_PATH = fixtureConfig;
    process.env.OIDC_USERNAME = 'approver';
    process.env.OIDC_PASSWORD = 'password';
    process.env.OIDC_LOCAL_REDIRECT_URI = 'http://localhost:8250/oidc/callback';

    // Initialize JWT middleware
    const { initJwtMiddleware } = require('../../src/jwtMiddleware');
    initJwtMiddleware(`http://127.0.0.1:${oidcPort}/realms/test`, audience);

    // Load config
    const config: Config = loadConfig();
    store = new RequestStore(config.wrapTokenEncKey);
    const vaultClient = new VaultClient(config.vault.addr);
    // Pre-set a mock token so readWrapped works
    vaultClient.setToken('mock-vault-token', 3600, true);
    const mockOidcManager = new MockVaultOidcManager() as unknown as VaultOidcManager;
    const worker = new Worker(config, store, mockOidcManager, vaultClient);

    // Create app
    const app = express();
    app.use(express.json());
    app.use(createHealthRouter(config, vaultClient));
    app.use(createApiRouter(config, store, worker));

    appServer = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    appPort = (appServer.address() as { port: number }).port;
  });

  afterAll((done) => {
    store.shutdown();
    appServer.close(() => {
      vaultServer.close(() => {
        oidcDiscoveryServer.close(done);
      });
    });
  });

  async function makeToken(): Promise<string> {
    return new jose.SignJWT({ sub: 'bot-user' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuer(`http://127.0.0.1:${oidcPort}/realms/test`)
      .setAudience(audience)
      .setExpirationTime('5m')
      .setIssuedAt()
      .sign(privateKey);
  }

  test('GET /healthz returns ok', async () => {
    const resp = await fetch(`http://127.0.0.1:${appPort}/healthz`);
    expect(resp.status).toBe(200);
    const body = await resp.json() as Record<string, string>;
    expect(body.status).toBe('ok');
  });

  test('GET /readyz checks OIDC provider and Vault', async () => {
    const resp = await fetch(`http://127.0.0.1:${appPort}/readyz`);
    expect(resp.status).toBe(200);
    const body = await resp.json() as Record<string, string>;
    expect(body.status).toBe('ready');
    expect(body.oidc).toBe('ok');
    expect(body.vault).toBe('ok');
  });

  test('POST /v1/requests requires auth', async () => {
    const resp = await fetch(`http://127.0.0.1:${appPort}/v1/requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'payroll-db', reason: 'test', requester: 'bot' }),
    });
    expect(resp.status).toBe(401);
  });

  test('POST /v1/requests creates request and returns 202', async () => {
    const token = await makeToken();
    const resp = await fetch(`http://127.0.0.1:${appPort}/v1/requests`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        service: 'payroll-db',
        reason: 'deployment',
        requester: 'ci-bot',
      }),
    });
    expect(resp.status).toBe(202);
    const body = await resp.json() as Record<string, string>;
    expect(body.request_id).toBeDefined();
    expect(body.status).toBe('PENDING_APPROVAL');
  });

  test('POST /v1/requests rejects unknown service', async () => {
    const token = await makeToken();
    const resp = await fetch(`http://127.0.0.1:${appPort}/v1/requests`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        service: 'nonexistent',
        reason: 'test',
        requester: 'bot',
      }),
    });
    expect(resp.status).toBe(404);
  });

  test('POST /v1/requests rejects missing fields', async () => {
    const token = await makeToken();
    const resp = await fetch(`http://127.0.0.1:${appPort}/v1/requests`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ service: 'payroll-db' }),
    });
    expect(resp.status).toBe(400);
  });

  test('GET /v1/requests/:id returns request status', async () => {
    const token = await makeToken();

    // Create a request first
    const createResp = await fetch(`http://127.0.0.1:${appPort}/v1/requests`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        service: 'payroll-db',
        reason: 'test',
        requester: 'bot',
      }),
    });
    const createBody = await createResp.json() as Record<string, string>;

    const getResp = await fetch(`http://127.0.0.1:${appPort}/v1/requests/${createBody.request_id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(getResp.status).toBe(200);
    const getBody = await getResp.json() as Record<string, string>;
    expect(getBody.request_id).toBe(createBody.request_id);
    expect(['PENDING_APPROVAL', 'APPROVED', 'FAILED']).toContain(getBody.status);
  });

  test('GET /v1/requests/:id returns 404 for unknown id', async () => {
    const token = await makeToken();
    const resp = await fetch(`http://127.0.0.1:${appPort}/v1/requests/nonexistent`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.status).toBe(404);
  });

  test('Full flow: create request, wait for approval, get wrap token', async () => {
    const token = await makeToken();

    const createResp = await fetch(`http://127.0.0.1:${appPort}/v1/requests`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        service: 'test-service',
        reason: 'integration test',
        requester: 'test-bot',
        wrap_ttl: '2m',
      }),
    });
    const { request_id } = await createResp.json() as { request_id: string };

    // Poll until approved or timeout
    let status = 'PENDING_APPROVAL';
    let wrapToken: string | undefined;
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 200));
      const resp = await fetch(`http://127.0.0.1:${appPort}/v1/requests/${request_id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = await resp.json() as Record<string, string>;
      status = body.status;
      if (status === 'APPROVED') {
        wrapToken = body.wrap_token;
        break;
      }
      if (status === 'FAILED' || status === 'DENIED') break;
    }

    expect(status).toBe('APPROVED');
    expect(wrapToken).toBeDefined();
    expect(wrapToken!.startsWith('hvs.')).toBe(true);
  }, 15000);
});
