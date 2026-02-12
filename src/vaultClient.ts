import logger from './logger';

interface VaultToken {
  clientToken: string;
  leaseDuration: number;
  renewable: boolean;
  obtainedAt: number;
}

interface VaultWrapInfo {
  token: string;
  ttl: number;
  creation_time: string;
}

export class VaultClient {
  private addr: string;
  private cachedToken: VaultToken | null = null;

  constructor(addr: string) {
    this.addr = addr.replace(/\/$/, '');
  }

  /**
   * Supply a Vault token obtained externally (e.g. via the OIDC CLI flow).
   * The token is cached with its lease metadata for automatic expiry checks.
   */
  setToken(clientToken: string, leaseDuration: number, renewable: boolean): void {
    this.cachedToken = {
      clientToken,
      leaseDuration,
      renewable,
      obtainedAt: Date.now(),
    };
    logger.info('Vault token set via external auth');
  }

  private async getToken(): Promise<string> {
    if (this.cachedToken) {
      const elapsed = (Date.now() - this.cachedToken.obtainedAt) / 1000;
      // Reuse if within 80% of lease duration
      if (elapsed < this.cachedToken.leaseDuration * 0.8) {
        return this.cachedToken.clientToken;
      }
      // Try to renew
      if (this.cachedToken.renewable) {
        try {
          return await this.renewToken(this.cachedToken.clientToken);
        } catch {
          logger.warn('Vault token renewal failed, token expired');
        }
      }
    }
    throw new Error(
      'No valid Vault token available. ' +
      'The OIDC login flow must provide a token via setToken() before Vault operations.',
    );
  }

  isTokenValid(): boolean {
    if (!this.cachedToken) return false;
    const elapsed = (Date.now() - this.cachedToken.obtainedAt) / 1000;
    return elapsed < this.cachedToken.leaseDuration * 0.8;
  }

  private async renewToken(token: string): Promise<string> {
    const url = `${this.addr}/v1/auth/token/renew-self`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'X-Vault-Token': token,
        'Content-Type': 'application/json',
      },
    });

    if (!resp.ok) {
      throw new Error(`Vault token renewal failed: ${resp.status}`);
    }

    const data = await resp.json() as {
      auth: { client_token: string; lease_duration: number; renewable: boolean };
    };

    this.cachedToken = {
      clientToken: data.auth.client_token,
      leaseDuration: data.auth.lease_duration,
      renewable: data.auth.renewable,
      obtainedAt: Date.now(),
    };

    return this.cachedToken.clientToken;
  }

  async readWrapped(kv2Mount: string, kv2Path: string, wrapTTL: string): Promise<VaultWrapInfo> {
    const token = await this.getToken();
    const url = `${this.addr}/v1/${kv2Mount}/data/${kv2Path}`;

    const resp = await fetch(url, {
      method: 'GET',
      headers: {
        'X-Vault-Token': token,
        'X-Vault-Wrap-TTL': wrapTTL,
      },
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Vault KV read failed: ${resp.status} ${text}`);
    }

    const data = await resp.json() as {
      wrap_info: { token: string; ttl: number; creation_time: string };
    };

    if (!data.wrap_info || !data.wrap_info.token) {
      throw new Error('Vault response missing wrap_info');
    }

    return {
      token: data.wrap_info.token,
      ttl: data.wrap_info.ttl,
      creation_time: data.wrap_info.creation_time,
    };
  }

  async checkHealth(): Promise<boolean> {
    const url = `${this.addr}/v1/sys/health`;
    try {
      const resp = await fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });
      // Vault returns 200 for initialized+unsealed, 429 for standby, 472/473 for other states
      if (resp.status === 200 || resp.status === 429) {
        return true;
      }
      logger.warn('Vault health check returned unexpected status', {
        url,
        status: resp.status,
      });
      return false;
    } catch (err) {
      logger.warn('Vault readiness check failed', {
        url,
        error: (err as Error).message,
      });
      return false;
    }
  }
}
