import { Config, capTTL, ttlToVaultString, validateServiceExists } from './config';
import { encrypt } from './encryption';
import { RequestStore, BrokerRequest } from './requestStore';
import { VaultOidcManager } from './auth/vaultOidcCliFlow';
import { VaultClient } from './vaultClient';
import logger from './logger';

export class Worker {
  private config: Config;
  private store: RequestStore;
  private oidcManager: VaultOidcManager;
  private vaultClient: VaultClient;

  constructor(
    config: Config,
    store: RequestStore,
    oidcManager: VaultOidcManager,
    vaultClient: VaultClient,
  ) {
    this.config = config;
    this.store = store;
    this.oidcManager = oidcManager;
    this.vaultClient = vaultClient;
  }

  async processRequest(request: BrokerRequest): Promise<void> {
    const { id, service, wrap_ttl } = request;
    const startTime = Date.now();

    try {
      const serviceEntry = validateServiceExists(this.config, service);
      if (!serviceEntry) {
        this.store.fail(id, `Service '${service}' not found in registry`);
        return;
      }

      // Step 1: Ensure we have a valid Vault token (via OIDC CLI-style flow)
      logger.info('Ensuring Vault token via OIDC login', { request_id: id, service });

      try {
        await this.oidcManager.ensureToken();
      } catch (err) {
        const msg = (err as Error).message;
        if (msg === 'DUO_DENIED' || msg.toLowerCase().includes('denied')) {
          this.store.deny(id, 'Duo push was denied by the approver');
          logger.info('Duo push denied', {
            request_id: id,
            elapsed_ms: Date.now() - startTime,
          });
          return;
        }
        throw err;
      }

      logger.info('Vault token available, proceeding to read secret', { request_id: id });

      // Step 2: Read from Vault with response wrapping
      const effectiveTTLMs = capTTL(wrap_ttl, serviceEntry);
      const vaultTTL = ttlToVaultString(effectiveTTLMs);

      logger.info('Reading wrapped secret from Vault', {
        request_id: id,
        kv2_mount: serviceEntry.vault.kv2_mount,
        kv2_path: serviceEntry.vault.kv2_path,
        wrap_ttl: vaultTTL,
      });

      const wrapInfo = await this.vaultClient.readWrapped(
        serviceEntry.vault.kv2_mount,
        serviceEntry.vault.kv2_path,
        vaultTTL,
      );

      // Step 3: Encrypt wrap token and store as approved
      const encryptedToken = encrypt(wrapInfo.token, this.config.wrapTokenEncKey);
      const wrapExpiresAt = new Date(Date.now() + effectiveTTLMs).toISOString();

      this.store.approve(id, encryptedToken, wrapExpiresAt);

      const elapsed = Date.now() - startTime;
      logger.info('Request processing complete', {
        request_id: id,
        service,
        requester: request.requester,
        outcome: 'APPROVED',
        elapsed_ms: elapsed,
      });
    } catch (err) {
      const elapsed = Date.now() - startTime;
      const message = (err as Error).message;
      logger.error('Request processing failed', {
        request_id: id,
        service,
        requester: request.requester,
        outcome: 'FAILED',
        error: message,
        elapsed_ms: elapsed,
      });
      this.store.fail(id, message);
    }
  }
}
