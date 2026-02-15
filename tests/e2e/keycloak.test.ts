/**
 * End-to-end tests for the Playwright-based OIDC login flow.
 *
 * These tests are OPTIONAL and only run when E2E_OIDC_BASE_URL is set.
 * They require a real OIDC provider instance with Duo MFA configured.
 *
 * Environment variables:
 *   E2E_OIDC_BASE_URL - Base URL of the OIDC provider (e.g., https://idp.example.com)
 *   E2E_OIDC_REALM - Realm name
 *   E2E_OIDC_CLIENT_ID - Client ID
 *   E2E_OIDC_CLIENT_SECRET - Client secret
 *   E2E_APPROVER_USERNAME - Username for the approver user
 *   E2E_APPROVER_PASSWORD - Password for the approver user
 *   E2E_REDIRECT_URI - Redirect URI (must be registered in the OIDC provider)
 */

import { PlaywrightDriver } from '../../src/playwrightDriver';
import {
  fetchOIDCDiscovery,
  generatePKCE,
  buildAuthURL,
  exchangeCode,
} from '../../src/oidcDriver';

const SKIP_REASON = 'E2E tests skipped: set E2E_OIDC_BASE_URL to run';

const isE2E = !!process.env.E2E_OIDC_BASE_URL;

(isE2E ? describe : describe.skip)('E2E: OIDC + Duo headless login', () => {
  const baseURL = process.env.E2E_OIDC_BASE_URL!;
  const realm = process.env.E2E_OIDC_REALM!;
  const clientID = process.env.E2E_OIDC_CLIENT_ID!;
  const clientSecret = process.env.E2E_OIDC_CLIENT_SECRET!;
  const username = process.env.E2E_APPROVER_USERNAME!;
  const password = process.env.E2E_APPROVER_PASSWORD!;
  const redirectURI = process.env.E2E_REDIRECT_URI || 'http://localhost:8080/oidc/callback';

  let driver: PlaywrightDriver;

  beforeAll(() => {
    driver = new PlaywrightDriver({
      headless: true,
      loginTimeout: 30_000,
      duoTimeout: 120_000,
    });
  });

  afterAll(async () => {
    await driver.close();
  });

  test('full OIDC login with Duo approval', async () => {
    const issuerURL = `${baseURL}/realms/${realm}`;
    const discovery = await fetchOIDCDiscovery(issuerURL);
    const pkce = generatePKCE();
    const authURL = buildAuthURL(discovery, clientID, redirectURI, pkce);

    console.log('Waiting for Duo push approval...');
    const result = await driver.login(authURL, redirectURI, username, password, pkce.state);

    expect(result.code).toBeDefined();
    expect(result.state).toBe(pkce.state);

    // Exchange code for tokens
    const tokens = await exchangeCode(
      discovery,
      result.code,
      clientID,
      clientSecret,
      redirectURI,
      pkce.codeVerifier,
    );

    expect(tokens.access_token).toBeDefined();
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
  }, 180_000); // 3 minute timeout for Duo approval
});

if (!isE2E) {
  test(SKIP_REASON, () => {
    expect(true).toBe(true);
  });
}
