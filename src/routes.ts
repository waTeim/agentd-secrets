import { Router, Request, Response } from 'express';
import { Config, validateServiceExists, resolveService, capTTL, ttlToVaultString } from './config';
import { RequestStore } from './requestStore';
import { Worker } from './worker';
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
  router.post('/v1/requests', async (req: Request, res: Response) => {
    try {
      const { service, reason, requester, wrap_ttl } = req.body;

      if (!service || !reason || !requester) {
        res.status(400).json({ error: 'Missing required fields: service, reason, requester' });
        return;
      }

      const resolved = resolveService(config, service);
      if (!resolved) {
        res.status(404).json({ error: `Service '${service}' not found in service registry` });
        return;
      }

      // Cap and validate wrap_ttl
      const effectiveTTLMs = capTTL(wrap_ttl, resolved.entry);
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
  router.get('/v1/requests/:id', async (req: Request, res: Response) => {
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

  // GET / — service discovery
  router.get('/', (_req: Request, res: Response) => {
    res.json({
      service: 'agentd-secrets',
      description: 'Secret broker that mediates access to Vault secrets with human-in-the-loop MFA approval. No authentication required -- access control is enforced via Duo MFA push to the approver.',
      version: '0.1.0',
      endpoints: {
        'POST /v1/requests': {
          description: 'Request access to a secret. Returns a request_id to poll. Triggers a Duo MFA push to the human approver.',
          body: {
            service: 'string (required) — secret name, supports prefix/subkey e.g. "logins/google"',
            reason: 'string (required) — justification for access',
            requester: 'string (required) — caller identity',
            wrap_ttl: 'string (optional) — requested wrap TTL e.g. "5m", "300s"',
          },
          response: '202 { request_id, status }',
        },
        'GET /v1/requests/:id': {
          description: 'Poll request status. When APPROVED, response includes a Vault wrap_token.',
          response: '200 { request_id, service, requester, status, created_at, wrap_token?, wrap_expires_at?, failure_reason? }',
          statuses: ['PENDING_APPROVAL', 'APPROVED', 'DENIED', 'EXPIRED', 'FAILED'],
          usage: 'Use wrap_token with Vault unwrap API: POST <vault_addr>/v1/sys/wrapping/unwrap with X-Vault-Token header. The wrap_token is single-use.',
        },
        'GET /healthz': { description: 'Liveness check' },
        'GET /readyz': { description: 'Readiness check (OIDC + Vault connectivity)' },
      },
      services: Object.keys(config.serviceRegistry.services),
      vault_addr: config.vault.addr,
    });
  });

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
      const resolved = resolveService(config, targetService);
      if (!resolved) {
        res.status(404).json({ error: `Service '${targetService}' not found` });
        return;
      }

      logger.info('Diag: test-read', { service: targetService, path: resolved.resolvedPath });
      await oidcManager.ensureToken();
      const wrapInfo = await vaultClient.readWrapped(
        resolved.kvMount,
        resolved.resolvedPath,
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
