import express, { Request, Response } from 'express';
import http from 'http';
import crypto from 'crypto';
import * as jose from 'jose';

// We'll test the JWT middleware by creating a small Express app
describe('JWT Middleware', () => {
  let server: http.Server;
  let port: number;
  let privateKey: jose.KeyLike;
  let publicKey: jose.KeyLike;
  let issuer: string;
  const audience = 'agentd-secrets';

  beforeAll(async () => {
    // Generate RSA key pair for signing test JWTs
    const keyPair = await jose.generateKeyPair('RS256');
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;

    const jwk = await jose.exportJWK(publicKey);
    jwk.kid = 'test-key-1';
    jwk.alg = 'RS256';
    jwk.use = 'sig';

    // Create a mock JWKS endpoint server
    const app = express();

    // JWKS endpoint
    app.get('/realms/test/protocol/openid-connect/certs', (_req: Request, res: Response) => {
      res.json({ keys: [jwk] });
    });

    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        port = (server.address() as { port: number }).port;
        issuer = `http://127.0.0.1:${port}/realms/test`;
        resolve();
      });
    });
  });

  afterAll((done) => {
    server.close(done);
  });

  async function createTestApp() {
    const { initJwtMiddleware, jwtMiddleware } = require('../../src/jwtMiddleware');
    initJwtMiddleware(`http://127.0.0.1:${port}/realms/test`, audience);

    const app = express();
    app.get('/protected', jwtMiddleware, (req: Request, res: Response) => {
      res.json({ ok: true });
    });

    return app;
  }

  async function makeToken(overrides: Record<string, unknown> = {}): Promise<string> {
    const jwt = new jose.SignJWT({ sub: 'bot-user', ...overrides })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setExpirationTime('5m')
      .setIssuedAt();
    return jwt.sign(privateKey);
  }

  test('accepts valid JWT', async () => {
    jest.resetModules();
    const app = await createTestApp();
    const token = await makeToken();

    const testServer = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const testPort = (testServer.address() as { port: number }).port;

    try {
      const resp = await fetch(`http://127.0.0.1:${testPort}/protected`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(resp.status).toBe(200);
      const body = await resp.json();
      expect(body).toEqual({ ok: true });
    } finally {
      testServer.close();
    }
  });

  test('rejects missing Authorization header', async () => {
    jest.resetModules();
    const app = await createTestApp();

    const testServer = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const testPort = (testServer.address() as { port: number }).port;

    try {
      const resp = await fetch(`http://127.0.0.1:${testPort}/protected`);
      expect(resp.status).toBe(401);
    } finally {
      testServer.close();
    }
  });

  test('rejects invalid JWT', async () => {
    jest.resetModules();
    const app = await createTestApp();

    const testServer = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const testPort = (testServer.address() as { port: number }).port;

    try {
      const resp = await fetch(`http://127.0.0.1:${testPort}/protected`, {
        headers: { Authorization: 'Bearer invalid-token' },
      });
      expect(resp.status).toBe(401);
    } finally {
      testServer.close();
    }
  });

  test('rejects expired JWT', async () => {
    jest.resetModules();
    const app = await createTestApp();

    // Create expired token
    const jwt = new jose.SignJWT({ sub: 'bot-user' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setExpirationTime('-1m')
      .setIssuedAt(Math.floor(Date.now() / 1000) - 120);
    const token = await jwt.sign(privateKey);

    const testServer = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const testPort = (testServer.address() as { port: number }).port;

    try {
      const resp = await fetch(`http://127.0.0.1:${testPort}/protected`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(resp.status).toBe(401);
    } finally {
      testServer.close();
    }
  });
});
