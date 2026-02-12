import http from 'http';
import crypto from 'crypto';
import { IPlaywrightDriver } from '../playwrightDriver';
import { VaultClient } from '../vaultClient';
import logger from '../logger';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface VaultOidcConfig {
  vaultAddr: string;
  oidcMount: string;
  oidcRole: string;
  callbackListenHost: string;
  callbackListenPort: number;
  redirectURI: string;
  loginUsername: string;
  loginPassword: string;
  callbackTimeoutMs: number;
}

interface AuthUrlResponse {
  auth_url: string;
}

interface CallbackParams {
  state: string;
  code: string;
}

interface VaultAuthResponse {
  auth: {
    client_token: string;
    lease_duration: number;
    renewable: boolean;
    accessor: string;
    policies: string[];
    metadata?: Record<string, string>;
  };
}

// ─── Callback Listener ──────────────────────────────────────────────────────

/**
 * Ephemeral HTTP server that captures the OIDC callback redirect,
 * mirroring Vault CLI's localhost listener behavior.
 */
export class CallbackListener {
  private server: http.Server | null = null;
  private host: string;
  private port: number;
  private timeoutMs: number;

  constructor(host: string, port: number, timeoutMs: number) {
    this.host = host;
    this.port = port;
    this.timeoutMs = timeoutMs;
  }

  /**
   * Start listening and return a promise that resolves when the callback
   * is received, or rejects on timeout / error.
   */
  start(): Promise<CallbackParams> {
    return new Promise<CallbackParams>((resolve, reject) => {
      let settled = false;

      const timeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          this.stop().catch(() => {});
          reject(new Error(`OIDC callback not received within ${this.timeoutMs}ms`));
        }
      }, this.timeoutMs);

      this.server = http.createServer((req, res) => {
        if (!req.url?.startsWith('/oidc/callback')) {
          res.writeHead(404);
          res.end('Not Found');
          return;
        }

        const url = new URL(req.url, `http://${this.host}:${this.port}`);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');
        const errorDesc = url.searchParams.get('error_description');

        // Respond to the browser so Playwright doesn't hang
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body>Authentication complete. You may close this window.</body></html>');

        if (settled) return;
        settled = true;
        clearTimeout(timeout);

        if (error) {
          reject(new Error(`OIDC callback error: ${error} - ${errorDesc || ''}`));
          return;
        }

        if (!code || !state) {
          reject(new Error('OIDC callback missing code or state parameter'));
          return;
        }

        resolve({ code, state });
      });

      this.server.on('error', (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timeout);
          reject(new Error(`Callback listener error: ${err.message}`));
        }
      });

      this.server.listen(this.port, this.host, () => {
        logger.info('OIDC callback listener started', {
          host: this.host,
          port: this.port,
        });
      });
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => {
          this.server = null;
          resolve();
        });
        // Force connections closed after 1s
        setTimeout(() => {
          this.server?.closeAllConnections?.();
        }, 1000);
      });
    }
  }
}

// ─── Vault OIDC API helpers ─────────────────────────────────────────────────

/**
 * Request an OIDC auth URL from Vault.
 * POST /v1/auth/{mount}/oidc/auth_url
 */
export async function getVaultAuthUrl(
  vaultAddr: string,
  mount: string,
  role: string,
  redirectURI: string,
  clientNonce: string,
): Promise<{ authUrl: string }> {
  const url = `${vaultAddr}/v1/auth/${mount}/oidc/auth_url`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      role,
      redirect_uri: redirectURI,
      client_nonce: clientNonce,
    }),
    signal: AbortSignal.timeout(10_000),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Vault OIDC auth_url request failed: ${resp.status} ${text}`);
  }

  const data = await resp.json() as { data: AuthUrlResponse };
  if (!data.data?.auth_url) {
    throw new Error('Vault OIDC auth_url response missing data.auth_url');
  }

  return { authUrl: data.data.auth_url };
}

/**
 * Complete the OIDC callback exchange with Vault.
 * POST /v1/auth/{mount}/oidc/callback
 */
export async function exchangeVaultCallback(
  vaultAddr: string,
  mount: string,
  state: string,
  code: string,
  clientNonce: string,
): Promise<VaultAuthResponse> {
  const url = `${vaultAddr}/v1/auth/${mount}/oidc/callback`;

  // Vault expects these as query parameters for the callback endpoint
  const params = new URLSearchParams({ state, code, client_nonce: clientNonce });
  const fullUrl = `${url}?${params.toString()}`;

  const resp = await fetch(fullUrl, {
    method: 'GET',
    signal: AbortSignal.timeout(10_000),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Vault OIDC callback exchange failed: ${resp.status} ${text}`);
  }

  const data = await resp.json() as VaultAuthResponse;
  if (!data.auth?.client_token) {
    throw new Error('Vault OIDC callback response missing auth.client_token');
  }

  return data;
}

// ─── VaultOidcManager ────────────────────────────────────────────────────────

/**
 * Manages the full Vault OIDC CLI-style login flow with token caching
 * and concurrency control (Option A: serialize with mutex).
 */
export class VaultOidcManager {
  private config: VaultOidcConfig;
  private driver: IPlaywrightDriver;
  private vaultClient: VaultClient;
  private loginMutex: Promise<void> = Promise.resolve();

  constructor(
    config: VaultOidcConfig,
    driver: IPlaywrightDriver,
    vaultClient: VaultClient,
  ) {
    this.config = config;
    this.driver = driver;
    this.vaultClient = vaultClient;
  }

  /**
   * Ensure a valid Vault token is available.
   * If cached token is valid, reuse it.
   * Otherwise, acquire a new one via OIDC flow (serialized).
   */
  async ensureToken(): Promise<void> {
    if (this.vaultClient.isTokenValid()) {
      logger.info('Reusing cached Vault token');
      return;
    }

    // Serialize concurrent login attempts via mutex chain
    const previousMutex = this.loginMutex;
    let releaseMutex: () => void;
    this.loginMutex = new Promise<void>((resolve) => {
      releaseMutex = resolve;
    });

    try {
      await previousMutex;

      // Double-check after acquiring mutex — another request may have already logged in
      if (this.vaultClient.isTokenValid()) {
        logger.info('Vault token acquired by concurrent request, reusing');
        return;
      }

      await this.performOidcLogin();
    } finally {
      releaseMutex!();
    }
  }

  /**
   * Execute the full Vault OIDC CLI-style login flow:
   * 1. Get auth URL from Vault
   * 2. Start local callback listener
   * 3. Drive Playwright to complete Keycloak login
   * 4. Exchange callback with Vault to obtain token
   */
  private async performOidcLogin(): Promise<void> {
    const startTime = Date.now();
    const clientNonce = crypto.randomBytes(16).toString('hex');

    logger.info('Starting Vault OIDC login flow', {
      oidc_mount: this.config.oidcMount,
      oidc_role: this.config.oidcRole,
      redirect_uri: this.config.redirectURI,
    });

    // Step 1: Get auth URL from Vault
    const { authUrl } = await getVaultAuthUrl(
      this.config.vaultAddr,
      this.config.oidcMount,
      this.config.oidcRole,
      this.config.redirectURI,
      clientNonce,
    );
    logger.info('Vault OIDC auth URL obtained');

    // Extract state from the auth URL for Playwright to verify
    const authUrlParsed = new URL(authUrl);
    const expectedState = authUrlParsed.searchParams.get('state') || '';

    // Step 2: Start local callback listener
    const listener = new CallbackListener(
      this.config.callbackListenHost,
      this.config.callbackListenPort,
      this.config.callbackTimeoutMs,
    );
    const callbackPromise = listener.start();

    try {
      // Step 3: Drive Playwright through Keycloak login
      logger.info('Driving headless browser for Keycloak login');
      await this.driver.login(
        authUrl,
        this.config.redirectURI,
        this.config.loginUsername,
        this.config.loginPassword,
        expectedState,
      );

      // Step 3b: Wait for callback to be captured by listener
      const callbackParams = await callbackPromise;
      logger.info('OIDC callback captured', { state: callbackParams.state });

      // Step 4: Exchange callback with Vault
      const authResult = await exchangeVaultCallback(
        this.config.vaultAddr,
        this.config.oidcMount,
        callbackParams.state,
        callbackParams.code,
        clientNonce,
      );

      // Store the token in VaultClient
      this.vaultClient.setToken(
        authResult.auth.client_token,
        authResult.auth.lease_duration,
        authResult.auth.renewable,
      );

      const elapsed = Date.now() - startTime;
      logger.info('Vault OIDC login complete', {
        elapsed_ms: elapsed,
        lease_duration: authResult.auth.lease_duration,
        renewable: authResult.auth.renewable,
        policies: authResult.auth.policies,
      });
    } catch (err) {
      await listener.stop().catch(() => {});
      throw err;
    } finally {
      await listener.stop().catch(() => {});
    }
  }
}
