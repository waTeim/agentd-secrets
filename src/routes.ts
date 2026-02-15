import { Router, Request, Response } from 'express';
import { Config, validateServiceExists, capTTL, ttlToVaultString } from './config';
import { RequestStore } from './requestStore';
import { Worker } from './worker';
import { jwtMiddleware } from './jwtMiddleware';
import { checkOidcReachable } from './oidcDriver';
import { VaultClient } from './vaultClient';
import { VaultOidcManager } from './auth/vaultOidcCliFlow';
import logger from './logger';

export function createApiRouter(
  config: Config,
  store: RequestStore,
  worker: Worker,
): Router {
  const router = Router();

  // POST /v1/requests — create a new secret request
  router.post('/v1/requests', jwtMiddleware, async (req: Request, res: Response) => {
    try {
      const { service, reason, requester, wrap_ttl } = req.body;

      if (!service || !reason || !requester) {
        res.status(400).json({ error: 'Missing required fields: service, reason, requester' });
        return;
      }

      const serviceEntry = validateServiceExists(config, service);
      if (!serviceEntry) {
        res.status(404).json({ error: `Service '${service}' not found in service registry` });
        return;
      }

      // Cap and validate wrap_ttl
      const effectiveTTLMs = capTTL(wrap_ttl, serviceEntry);
      const effectiveTTL = ttlToVaultString(effectiveTTLMs);

      const request = store.create(service, reason, requester, effectiveTTL);

      // Enqueue async worker job (fire and forget)
      worker.processRequest(request).catch((err) => {
        logger.error('Unhandled worker error', {
          request_id: request.id,
          error: (err as Error).message,
        });
      });

      res.status(202).json({
        request_id: request.id,
        status: request.status,
      });
    } catch (err) {
      logger.error('Error creating request', { error: (err as Error).message });
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // GET /v1/requests/:id — check request status
  router.get('/v1/requests/:id', jwtMiddleware, async (req: Request, res: Response) => {
    try {
      const request = store.get(req.params.id);
      if (!request) {
        res.status(404).json({ error: 'Request not found' });
        return;
      }

      const view = store.toPublicView(request);
      res.json(view);
    } catch (err) {
      logger.error('Error getting request', { error: (err as Error).message });
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}

export function createHealthRouter(config: Config, vaultClient: VaultClient): Router {
  const router = Router();

  // GET /healthz — liveness
  router.get('/healthz', (_req: Request, res: Response) => {
    res.json({ status: 'ok' });
  });

  // GET /readyz — readiness (checks OIDC provider + Vault)
  router.get('/readyz', async (_req: Request, res: Response) => {
    try {
      const [kcOk, vaultOk] = await Promise.all([
        checkOidcReachable(config.oidc.issuerURL),
        vaultClient.checkHealth(),
      ]);

      if (kcOk && vaultOk) {
        res.json({ status: 'ready', oidc: 'ok', vault: 'ok' });
      } else {
        logger.warn('Readiness check failed', {
          oidc: kcOk ? 'ok' : 'unreachable',
          vault: vaultOk ? 'ok' : 'unreachable',
        });
        res.status(503).json({
          status: 'not ready',
          oidc: kcOk ? 'ok' : 'unreachable',
          vault: vaultOk ? 'ok' : 'unreachable',
        });
      }
    } catch (err) {
      logger.error('Readiness check error', { error: (err as Error).message });
      res.status(503).json({ status: 'not ready', error: (err as Error).message });
    }
  });

  return router;
}

export function createDiagRouter(
  config: Config,
  vaultClient: VaultClient,
  oidcManager: VaultOidcManager,
): Router {
  const router = Router();

  // POST /diag/test-login — trigger OIDC login flow to obtain a Vault token
  router.post('/diag/test-login', async (_req: Request, res: Response) => {
    try {
      logger.info('Diag: triggering OIDC login flow');
      await oidcManager.ensureToken();
      res.json({
        status: 'ok',
        tokenValid: vaultClient.isTokenValid(),
      });
    } catch (err) {
      logger.error('Diag: login failed', { error: (err as Error).message });
      res.status(500).json({ error: (err as Error).message });
    }
  });

  // GET /diag/token-status — check cached Vault token validity
  router.get('/diag/token-status', (_req: Request, res: Response) => {
    res.json({ tokenValid: vaultClient.isTokenValid() });
  });

  // GET /diag/config — show non-sensitive config values
  router.get('/diag/config', (_req: Request, res: Response) => {
    res.json({
      oidc: {
        issuerURL: config.oidc.issuerURL,
        clientID: config.oidc.clientID,
        audience: config.oidc.audience,
      },
      vault: {
        addr: config.vault.addr,
        oidcMount: config.vault.oidcMount,
        oidcRole: config.vault.oidcRole,
        kvMount: config.vault.kvMount,
        wrapTTL: config.vault.wrapTTL,
      },
      services: Object.keys(config.serviceRegistry.services),
      listenAddr: config.listenAddr,
    });
  });

  // POST /diag/test-read — attempt a Vault KV read for a registered service
  router.post('/diag/test-read', async (req: Request, res: Response) => {
    try {
      const { service } = req.body;
      const serviceNames = Object.keys(config.serviceRegistry.services);

      if (!service && serviceNames.length === 0) {
        res.status(400).json({ error: 'No services registered and no service specified' });
        return;
      }

      const targetService = service || serviceNames[0];
      const entry = validateServiceExists(config, targetService);
      if (!entry) {
        res.status(404).json({ error: `Service '${targetService}' not found` });
        return;
      }

      logger.info('Diag: test-read', { service: targetService, path: entry.vault.kv2_path });
      await oidcManager.ensureToken();
      const wrapInfo = await vaultClient.readWrapped(
        entry.vault.kv2_mount,
        entry.vault.kv2_path,
        config.vault.wrapTTL,
      );
      res.json({
        status: 'ok',
        service: targetService,
        wrapInfo: {
          token: wrapInfo.token.substring(0, 8) + '...',
          ttl: wrapInfo.ttl,
          creationTime: wrapInfo.creation_time,
        },
      });
    } catch (err) {
      logger.error('Diag: test-read failed', { error: (err as Error).message });
      res.status(500).json({ error: (err as Error).message });
    }
  });

  return router;
}
