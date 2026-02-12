import http from 'http';
import crypto from 'crypto';
import { IPlaywrightDriver, PlaywrightLoginResult } from '../../src/playwrightDriver';
import {
  CallbackListener,
  getVaultAuthUrl,
  exchangeVaultCallback,
  VaultOidcManager,
  VaultOidcConfig,
} from '../../src/auth/vaultOidcCliFlow';
import { VaultClient } from '../../src/vaultClient';

// ─── Test helpers ────────────────────────────────────────────────────────────

function findFreePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = http.createServer();
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

// Mock Playwright driver that simulates a browser hitting the callback.
// It derives the callback URL from the redirectURI parameter passed to login().
class MockPlaywrightDriver implements IPlaywrightDriver {
  public loginCalls: { authURL: string; username: string }[] = [];
  public shouldDeny = false;
  public shouldTimeout = false;
  public delay = 0;

  async login(
    authURL: string,
    redirectURI: string,
    username: string,
    _password: string,
    _expectedState: string,
  ): Promise<PlaywrightLoginResult> {
    this.loginCalls.push({ authURL, username });

    if (this.shouldDeny) {
      throw new Error('DUO_DENIED');
    }
    if (this.shouldTimeout) {
      await new Promise((r) => setTimeout(r, 5000));
      throw new Error('Login timed out');
    }

    if (this.delay > 0) {
      await new Promise((r) => setTimeout(r, this.delay));
    }

    // Extract state from the auth URL to simulate a real browser redirect
    const parsedUrl = new URL(authURL);
    const state = parsedUrl.searchParams.get('state') || 'mock-state';

    // Derive callback URL from the redirectURI (the actual listener address)
    const callbackBase = redirectURI.split('?')[0];
    const callbackUrl = `${callbackBase}?code=mock-auth-code&state=${state}`;
    await fetch(callbackUrl);

    return { code: 'mock-auth-code', state };
  }

  async close() {}
}

// ─── CallbackListener tests ─────────────────────────────────────────────────

describe('CallbackListener', () => {
  test('captures code and state from callback request', async () => {
    const port = await findFreePort();
    const listener = new CallbackListener('127.0.0.1', port, 5000);
    const resultPromise = listener.start();

    // Simulate browser callback
    await fetch(`http://127.0.0.1:${port}/oidc/callback?code=test-code&state=test-state`);

    const result = await resultPromise;
    expect(result.code).toBe('test-code');
    expect(result.state).toBe('test-state');

    await listener.stop();
  });

  test('rejects on OIDC error in callback', async () => {
    const port = await findFreePort();
    const listener = new CallbackListener('127.0.0.1', port, 5000);
    const resultPromise = listener.start();
    // Attach catch handler immediately to prevent unhandled rejection warning
    resultPromise.catch(() => {});

    await fetch(`http://127.0.0.1:${port}/oidc/callback?error=access_denied&error_description=user+denied`);

    await expect(resultPromise).rejects.toThrow('OIDC callback error: access_denied');
    await listener.stop();
  });

  test('rejects on missing code parameter', async () => {
    const port = await findFreePort();
    const listener = new CallbackListener('127.0.0.1', port, 5000);
    const resultPromise = listener.start();
    resultPromise.catch(() => {});

    await fetch(`http://127.0.0.1:${port}/oidc/callback?state=only-state`);

    await expect(resultPromise).rejects.toThrow('missing code or state');
    await listener.stop();
  });

  test('returns 404 for non-callback paths', async () => {
    const port = await findFreePort();
    const listener = new CallbackListener('127.0.0.1', port, 5000);
    const resultPromise = listener.start();

    const resp = await fetch(`http://127.0.0.1:${port}/other`);
    expect(resp.status).toBe(404);

    // Now send valid callback to resolve promise
    await fetch(`http://127.0.0.1:${port}/oidc/callback?code=c&state=s`);
    await resultPromise;
    await listener.stop();
  });

  test('times out if no callback received', async () => {
    const port = await findFreePort();
    const listener = new CallbackListener('127.0.0.1', port, 200);
    const resultPromise = listener.start();

    await expect(resultPromise).rejects.toThrow('not received within 200ms');
    await listener.stop();
  });

  test('stop is idempotent', async () => {
    const port = await findFreePort();
    const listener = new CallbackListener('127.0.0.1', port, 5000);
    const resultPromise = listener.start();

    await fetch(`http://127.0.0.1:${port}/oidc/callback?code=c&state=s`);
    await resultPromise;

    await listener.stop();
    await listener.stop(); // should not throw
  });
});

// ─── getVaultAuthUrl tests ──────────────────────────────────────────────────

describe('getVaultAuthUrl', () => {
  let vaultServer: http.Server;
  let vaultPort: number;

  afterEach(async () => {
    if (vaultServer) {
      await new Promise<void>((resolve) => vaultServer.close(() => resolve()));
    }
  });

  test('returns auth_url from Vault response', async () => {
    const expectedUrl = 'https://keycloak.example.com/auth?client_id=vault&state=abc123';
    const app = http.createServer((req, res) => {
      if (req.url === '/v1/auth/oidc/oidc/auth_url' && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: { auth_url: expectedUrl } }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    vaultServer = await new Promise<http.Server>((resolve) => {
      app.listen(0, '127.0.0.1', () => resolve(app));
    });
    vaultPort = (vaultServer.address() as { port: number }).port;

    const result = await getVaultAuthUrl(
      `http://127.0.0.1:${vaultPort}`,
      'oidc',
      'wyrd-x-pass',
      'http://localhost:8250/oidc/callback',
      'test-nonce',
    );

    expect(result.authUrl).toBe(expectedUrl);
  });

  test('throws on non-200 response', async () => {
    const app = http.createServer((_req, res) => {
      res.writeHead(403);
      res.end('permission denied');
    });

    vaultServer = await new Promise<http.Server>((resolve) => {
      app.listen(0, '127.0.0.1', () => resolve(app));
    });
    vaultPort = (vaultServer.address() as { port: number }).port;

    await expect(
      getVaultAuthUrl(
        `http://127.0.0.1:${vaultPort}`,
        'oidc',
        'wyrd-x-pass',
        'http://localhost:8250/oidc/callback',
        'test-nonce',
      ),
    ).rejects.toThrow('403');
  });

  test('throws on missing auth_url in response', async () => {
    const app = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: {} }));
    });

    vaultServer = await new Promise<http.Server>((resolve) => {
      app.listen(0, '127.0.0.1', () => resolve(app));
    });
    vaultPort = (vaultServer.address() as { port: number }).port;

    await expect(
      getVaultAuthUrl(
        `http://127.0.0.1:${vaultPort}`,
        'oidc',
        'wyrd-x-pass',
        'http://localhost:8250/oidc/callback',
        'test-nonce',
      ),
    ).rejects.toThrow('missing data.auth_url');
  });
});

// ─── exchangeVaultCallback tests ────────────────────────────────────────────

describe('exchangeVaultCallback', () => {
  let vaultServer: http.Server;
  let vaultPort: number;

  afterEach(async () => {
    if (vaultServer) {
      await new Promise<void>((resolve) => vaultServer.close(() => resolve()));
    }
  });

  test('returns auth result from Vault callback exchange', async () => {
    const app = http.createServer((req, res) => {
      if (req.url?.startsWith('/v1/auth/oidc/oidc/callback') && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          auth: {
            client_token: 'hvs.test-vault-token',
            lease_duration: 3600,
            renewable: true,
            accessor: 'test-accessor',
            policies: ['default', 'x-pass-read'],
          },
        }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    vaultServer = await new Promise<http.Server>((resolve) => {
      app.listen(0, '127.0.0.1', () => resolve(app));
    });
    vaultPort = (vaultServer.address() as { port: number }).port;

    const result = await exchangeVaultCallback(
      `http://127.0.0.1:${vaultPort}`,
      'oidc',
      'test-state',
      'test-code',
      'test-nonce',
    );

    expect(result.auth.client_token).toBe('hvs.test-vault-token');
    expect(result.auth.lease_duration).toBe(3600);
    expect(result.auth.renewable).toBe(true);
    expect(result.auth.policies).toContain('x-pass-read');
  });

  test('passes state, code, and client_nonce as query parameters', async () => {
    let capturedUrl = '';
    const app = http.createServer((req, res) => {
      capturedUrl = req.url || '';
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        auth: {
          client_token: 'hvs.test',
          lease_duration: 3600,
          renewable: true,
          accessor: 'a',
          policies: [],
        },
      }));
    });

    vaultServer = await new Promise<http.Server>((resolve) => {
      app.listen(0, '127.0.0.1', () => resolve(app));
    });
    vaultPort = (vaultServer.address() as { port: number }).port;

    await exchangeVaultCallback(
      `http://127.0.0.1:${vaultPort}`,
      'oidc',
      'my-state',
      'my-code',
      'my-nonce',
    );

    expect(capturedUrl).toContain('state=my-state');
    expect(capturedUrl).toContain('code=my-code');
    expect(capturedUrl).toContain('client_nonce=my-nonce');
  });

  test('throws on non-200 response', async () => {
    const app = http.createServer((_req, res) => {
      res.writeHead(400);
      res.end('invalid request');
    });

    vaultServer = await new Promise<http.Server>((resolve) => {
      app.listen(0, '127.0.0.1', () => resolve(app));
    });
    vaultPort = (vaultServer.address() as { port: number }).port;

    await expect(
      exchangeVaultCallback(
        `http://127.0.0.1:${vaultPort}`,
        'oidc',
        's',
        'c',
        'n',
      ),
    ).rejects.toThrow('400');
  });
});

// ─── VaultOidcManager tests ─────────────────────────────────────────────────

describe('VaultOidcManager', () => {
  let vaultServer: http.Server;
  let vaultPort: number;
  let callbackPort: number;

  beforeEach(async () => {
    callbackPort = await findFreePort();
  });

  afterEach(async () => {
    if (vaultServer) {
      await new Promise<void>((resolve) => vaultServer.close(() => resolve()));
    }
  });

  function createMockVaultServer(): Promise<{ server: http.Server; port: number }> {
    return new Promise((resolve) => {
      const authUrlPath = '/v1/auth/oidc/oidc/auth_url';
      const callbackPath = '/v1/auth/oidc/oidc/callback';

      const app = http.createServer((req, res) => {
        if (req.url === authUrlPath && req.method === 'POST') {
          // Return a fake auth URL with a state parameter
          const state = crypto.randomBytes(8).toString('hex');
          const authUrl = `http://keycloak.test/auth?client_id=vault&state=${state}&redirect_uri=http://127.0.0.1:${callbackPort}/oidc/callback`;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ data: { auth_url: authUrl } }));
        } else if (req.url?.startsWith(callbackPath) && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            auth: {
              client_token: 'hvs.manager-test-token',
              lease_duration: 3600,
              renewable: true,
              accessor: 'test-accessor',
              policies: ['default', 'x-pass-read'],
            },
          }));
        } else {
          res.writeHead(404);
          res.end();
        }
      });

      app.listen(0, '127.0.0.1', () => {
        const port = (app.address() as { port: number }).port;
        vaultServer = app;
        vaultPort = port;
        resolve({ server: app, port });
      });
    });
  }

  function makeConfig(overrides?: Partial<VaultOidcConfig>): VaultOidcConfig {
    return {
      vaultAddr: `http://127.0.0.1:${vaultPort}`,
      oidcMount: 'oidc',
      oidcRole: 'wyrd-x-pass',
      callbackListenHost: '127.0.0.1',
      callbackListenPort: callbackPort,
      redirectURI: `http://127.0.0.1:${callbackPort}/oidc/callback`,
      loginUsername: 'test-approver',
      loginPassword: 'test-password',
      callbackTimeoutMs: 10_000,
      ...overrides,
    };
  }

  test('ensureToken performs full OIDC login flow', async () => {
    await createMockVaultServer();
    const mockDriver = new MockPlaywrightDriver();
    const vaultClient = new VaultClient(`http://127.0.0.1:${vaultPort}`);
    const config = makeConfig();
    const manager = new VaultOidcManager(config, mockDriver, vaultClient);

    await manager.ensureToken();

    expect(vaultClient.isTokenValid()).toBe(true);
    expect(mockDriver.loginCalls).toHaveLength(1);
    expect(mockDriver.loginCalls[0].username).toBe('test-approver');
  });

  test('ensureToken reuses cached token on second call', async () => {
    await createMockVaultServer();
    const mockDriver = new MockPlaywrightDriver();
    const vaultClient = new VaultClient(`http://127.0.0.1:${vaultPort}`);
    const config = makeConfig();
    const manager = new VaultOidcManager(config, mockDriver, vaultClient);

    await manager.ensureToken();
    expect(mockDriver.loginCalls).toHaveLength(1);

    // Second call — callback port is no longer listening, so if it tries to login
    // it would fail. The fact that this succeeds proves caching works.
    await manager.ensureToken();
    expect(mockDriver.loginCalls).toHaveLength(1); // still 1
  });

  test('concurrent ensureToken calls trigger only one login', async () => {
    await createMockVaultServer();
    const mockDriver = new MockPlaywrightDriver();
    mockDriver.delay = 100; // slow down login to force overlap
    const vaultClient = new VaultClient(`http://127.0.0.1:${vaultPort}`);
    const config = makeConfig();
    const manager = new VaultOidcManager(config, mockDriver, vaultClient);

    // Fire two concurrent ensureToken calls
    const [r1, r2] = await Promise.all([
      manager.ensureToken(),
      manager.ensureToken(),
    ]);

    // Only one login should have happened
    expect(mockDriver.loginCalls).toHaveLength(1);
    expect(vaultClient.isTokenValid()).toBe(true);
  });

  test('ensureToken propagates DUO_DENIED error', async () => {
    await createMockVaultServer();
    const mockDriver = new MockPlaywrightDriver();
    mockDriver.shouldDeny = true;
    const vaultClient = new VaultClient(`http://127.0.0.1:${vaultPort}`);
    const config = makeConfig();
    const manager = new VaultOidcManager(config, mockDriver, vaultClient);

    await expect(manager.ensureToken()).rejects.toThrow('DUO_DENIED');
    expect(vaultClient.isTokenValid()).toBe(false);
  });

  test('failed login does not poison cache for next attempt', async () => {
    await createMockVaultServer();
    const mockDriver = new MockPlaywrightDriver();
    mockDriver.shouldDeny = true;
    const vaultClient = new VaultClient(`http://127.0.0.1:${vaultPort}`);
    const config = makeConfig();
    const manager = new VaultOidcManager(config, mockDriver, vaultClient);

    // First attempt fails (DUO_DENIED happens before callback listener is used)
    await expect(manager.ensureToken()).rejects.toThrow('DUO_DENIED');
    expect(vaultClient.isTokenValid()).toBe(false);

    // Second attempt succeeds after fixing driver
    mockDriver.shouldDeny = false;
    // The manager reuses the same config/port — the old listener was cleaned up,
    // so a new one can start on the same port.
    await manager.ensureToken();
    expect(vaultClient.isTokenValid()).toBe(true);
  });
});
