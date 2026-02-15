import { IPlaywrightDriver, PlaywrightLoginResult } from '../../src/playwrightDriver';

// Mock implementation of IPlaywrightDriver for testing
class MockPlaywrightDriver implements IPlaywrightDriver {
  private shouldSucceed: boolean;
  private shouldDeny: boolean;
  private delay: number;

  constructor(opts: { shouldSucceed?: boolean; shouldDeny?: boolean; delay?: number } = {}) {
    this.shouldSucceed = opts.shouldSucceed ?? true;
    this.shouldDeny = opts.shouldDeny ?? false;
    this.delay = opts.delay ?? 0;
  }

  async login(
    authURL: string,
    redirectURI: string,
    username: string,
    password: string,
    expectedState: string,
  ): Promise<PlaywrightLoginResult> {
    if (this.delay > 0) {
      await new Promise((r) => setTimeout(r, this.delay));
    }

    if (this.shouldDeny) {
      throw new Error('DUO_DENIED');
    }

    if (!this.shouldSucceed) {
      throw new Error('Login timed out after 300000ms');
    }

    return {
      code: 'mock-auth-code-' + Math.random().toString(36).slice(2),
      state: expectedState,
    };
  }

  async close(): Promise<void> {
    // no-op
  }
}

describe('PlaywrightDriver interface (mock)', () => {
  test('successful login returns code and state', async () => {
    const driver = new MockPlaywrightDriver({ shouldSucceed: true });
    const result = await driver.login(
      'https://idp.example.com/auth',
      'http://localhost:8080/oidc/callback',
      'user',
      'pass',
      'test-state-123',
    );
    expect(result.code).toBeDefined();
    expect(result.state).toBe('test-state-123');
  });

  test('denied login throws DUO_DENIED', async () => {
    const driver = new MockPlaywrightDriver({ shouldDeny: true });
    await expect(
      driver.login(
        'https://idp.example.com/auth',
        'http://localhost:8080/oidc/callback',
        'user',
        'pass',
        'state',
      ),
    ).rejects.toThrow('DUO_DENIED');
  });

  test('failed login throws timeout error', async () => {
    const driver = new MockPlaywrightDriver({ shouldSucceed: false });
    await expect(
      driver.login(
        'https://idp.example.com/auth',
        'http://localhost:8080/oidc/callback',
        'user',
        'pass',
        'state',
      ),
    ).rejects.toThrow('timed out');
  });

  test('close succeeds', async () => {
    const driver = new MockPlaywrightDriver();
    await expect(driver.close()).resolves.toBeUndefined();
  });
});
