import crypto from 'crypto';
import logger from './logger';

export interface OIDCDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  issuer: string;
}

export interface OIDCTokens {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type: string;
}

export interface PKCEParams {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
  nonce: string;
}

export function generatePKCE(): PKCEParams {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  return { codeVerifier, codeChallenge, state, nonce };
}

export async function fetchOIDCDiscovery(issuerURL: string): Promise<OIDCDiscovery> {
  const url = `${issuerURL.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const resp = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!resp.ok) {
    throw new Error(`OIDC discovery failed: ${resp.status}`);
  }
  return (await resp.json()) as OIDCDiscovery;
}

export function buildAuthURL(
  discovery: OIDCDiscovery,
  clientID: string,
  redirectURI: string,
  pkce: PKCEParams,
): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientID,
    redirect_uri: redirectURI,
    scope: 'openid',
    state: pkce.state,
    nonce: pkce.nonce,
    code_challenge: pkce.codeChallenge,
    code_challenge_method: 'S256',
  });
  return `${discovery.authorization_endpoint}?${params.toString()}`;
}

export async function exchangeCode(
  discovery: OIDCDiscovery,
  code: string,
  clientID: string,
  clientSecret: string,
  redirectURI: string,
  codeVerifier: string,
): Promise<OIDCTokens> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: clientID,
    client_secret: clientSecret,
    redirect_uri: redirectURI,
    code_verifier: codeVerifier,
  });

  const resp = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Token exchange failed: ${resp.status} ${text}`);
  }

  return (await resp.json()) as OIDCTokens;
}

export async function checkOidcReachable(issuerURL: string): Promise<boolean> {
  const discoveryURL = `${issuerURL.replace(/\/$/, '')}/.well-known/openid-configuration`;
  try {
    await fetchOIDCDiscovery(issuerURL);
    return true;
  } catch (err) {
    logger.warn('OIDC provider readiness check failed', {
      url: discoveryURL,
      error: (err as Error).message,
    });
    return false;
  }
}
