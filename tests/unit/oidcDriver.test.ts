import { generatePKCE, buildAuthURL, OIDCDiscovery } from '../../src/oidcDriver';
import crypto from 'crypto';

describe('OIDC Driver', () => {
  describe('generatePKCE', () => {
    test('generates valid PKCE parameters', () => {
      const pkce = generatePKCE();
      expect(pkce.codeVerifier).toBeDefined();
      expect(pkce.codeChallenge).toBeDefined();
      expect(pkce.state).toBeDefined();
      expect(pkce.nonce).toBeDefined();

      // Verify S256 challenge
      const expectedChallenge = crypto
        .createHash('sha256')
        .update(pkce.codeVerifier)
        .digest('base64url');
      expect(pkce.codeChallenge).toBe(expectedChallenge);
    });

    test('generates unique values each time', () => {
      const p1 = generatePKCE();
      const p2 = generatePKCE();
      expect(p1.codeVerifier).not.toBe(p2.codeVerifier);
      expect(p1.state).not.toBe(p2.state);
    });
  });

  describe('buildAuthURL', () => {
    const discovery: OIDCDiscovery = {
      authorization_endpoint: 'https://idp.example.com/realms/test/protocol/openid-connect/auth',
      token_endpoint: 'https://idp.example.com/realms/test/protocol/openid-connect/token',
      jwks_uri: 'https://idp.example.com/realms/test/protocol/openid-connect/certs',
      issuer: 'https://idp.example.com/realms/test',
    };

    test('builds correct authorization URL', () => {
      const pkce = generatePKCE();
      const url = buildAuthURL(discovery, 'agentd-secrets', 'http://localhost:8080/oidc/callback', pkce);

      const parsed = new URL(url);
      expect(parsed.origin + parsed.pathname).toBe(discovery.authorization_endpoint);
      expect(parsed.searchParams.get('response_type')).toBe('code');
      expect(parsed.searchParams.get('client_id')).toBe('agentd-secrets');
      expect(parsed.searchParams.get('redirect_uri')).toBe('http://localhost:8080/oidc/callback');
      expect(parsed.searchParams.get('scope')).toBe('openid');
      expect(parsed.searchParams.get('state')).toBe(pkce.state);
      expect(parsed.searchParams.get('nonce')).toBe(pkce.nonce);
      expect(parsed.searchParams.get('code_challenge')).toBe(pkce.codeChallenge);
      expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
    });
  });
});
