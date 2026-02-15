import express from 'express';
import rateLimit from 'express-rate-limit';
import { loadConfig } from './config';
import { RequestStore } from './requestStore';
import { initJwtMiddleware } from './jwtMiddleware';
import { PlaywrightDriver } from './playwrightDriver';
import { VaultClient } from './vaultClient';
import { VaultOidcManager } from './auth/vaultOidcCliFlow';
import { Worker } from './worker';
import { createApiRouter, createHealthRouter } from './routes';
import logger from './logger';

async function main() {
  logger.info('Starting agentd-secrets broker');

  const config = loadConfig();

  // Initialize JWT middleware
  initJwtMiddleware(config.oidc.issuerURL, config.oidc.audience);

  // Initialize stores and clients
  const store = new RequestStore(config.wrapTokenEncKey);

  const playwrightDriver = new PlaywrightDriver({
    headless: config.playwright.headless,
    loginTimeout: config.login.loginTimeout,
    duoTimeout: config.login.duoTimeout,
  });

  const vaultClient = new VaultClient(config.vault.addr);

  const oidcManager = new VaultOidcManager(
    {
      vaultAddr: config.vault.addr,
      oidcMount: config.vault.oidcMount,
      oidcRole: config.vault.oidcRole,
      callbackListenHost: config.oidcCallback.listenHost,
      callbackListenPort: config.oidcCallback.listenPort,
      redirectURI: config.oidcCallback.redirectURI,
      loginUsername: config.login.username,
      loginPassword: config.login.password,
      callbackTimeoutMs: config.login.duoTimeout,
    },
    playwrightDriver,
    vaultClient,
  );

  const worker = new Worker(config, store, oidcManager, vaultClient);

  // Create Express app
  const app = express();
  app.use(express.json());

  // Rate limiting on POST /v1/requests
  const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later' },
    keyGenerator: (req) => req.ip || 'unknown',
  });
  app.use('/v1/requests', (req, _res, next) => {
    if (req.method === 'POST') {
      limiter(req, _res, next);
    } else {
      next();
    }
  });

  // Mount routes
  app.use(createHealthRouter(config, vaultClient));
  app.use(createApiRouter(config, store, worker));

  // Start server
  const server = app.listen(config.listenPort, () => {
    logger.info(`agentd-secrets broker listening on ${config.listenAddr}`);
  });

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, shutting down`);
    store.shutdown();
    await playwrightDriver.close();
    server.close(() => {
      logger.info('Server closed');
      process.exit(0);
    });
    // Force exit after 10s
    setTimeout(() => process.exit(1), 10_000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  logger.error('Fatal startup error', { error: err.message, stack: err.stack });
  process.exit(1);
});
