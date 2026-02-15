import fs from 'fs';
import yaml from 'js-yaml';
import logger from './logger';

export interface ServiceEntry {
  vault: {
    kv2_mount: string;
    kv2_path: string;
  };
  authz?: {
    oidc?: {
      resource_id?: string;
      scope?: string;
    };
  };
  wrap: {
    max_ttl: string;
    default_ttl: string;
  };
}

export interface ServiceRegistry {
  services: Record<string, ServiceEntry>;
}

export interface Config {
  oidc: {
    issuerURL: string;
    realm: string;
    clientID: string;
    audience: string;
  };
  vault: {
    addr: string;
    oidcMount: string;
    oidcRole: string;
    kvMount: string;
    wrapTTL: string;
  };
  oidcCallback: {
    listenHost: string;
    listenPort: number;
    redirectURI: string;
  };
  wrapTokenEncKey: Buffer;
  listenAddr: string;
  listenPort: number;
  login: {
    username: string;
    password: string;
    loginTimeout: number;
    duoTimeout: number;
  };
  playwright: {
    headless: boolean;
    browser: string;
  };
  serviceRegistry: ServiceRegistry;
  configPath: string;
}

function parseDuration(s: string, defaultMs: number): number {
  if (!s) return defaultMs;
  const match = s.match(/^(\d+)(ms|s|m|h)?$/);
  if (!match) return defaultMs;
  const val = parseInt(match[1], 10);
  switch (match[2]) {
    case 'h':
      return val * 3600_000;
    case 'm':
      return val * 60_000;
    case 's':
      return val * 1000;
    case 'ms':
      return val;
    default:
      return val * 1000;
  }
}

export function parseTTL(s: string): number {
  return parseDuration(s, 0);
}

export function capTTL(requestedTTL: string | undefined, service: ServiceEntry): number {
  const maxMs = parseTTL(service.wrap.max_ttl);
  const defaultMs = parseTTL(service.wrap.default_ttl);
  if (!requestedTTL) return defaultMs;
  const requestedMs = parseTTL(requestedTTL);
  if (requestedMs <= 0) return defaultMs;
  return Math.min(requestedMs, maxMs);
}

export function ttlToVaultString(ms: number): string {
  if (ms >= 3600_000 && ms % 3600_000 === 0) return `${ms / 3600_000}h`;
  if (ms >= 60_000 && ms % 60_000 === 0) return `${ms / 60_000}m`;
  return `${Math.ceil(ms / 1000)}s`;
}

function loadServiceRegistry(configPath: string): ServiceRegistry {
  if (!fs.existsSync(configPath)) {
    logger.warn(`Service registry not found at ${configPath}, starting with empty registry`);
    return { services: {} };
  }
  const raw = fs.readFileSync(configPath, 'utf-8');
  const parsed = yaml.load(raw) as Record<string, unknown> | null;
  if (!parsed || typeof parsed !== 'object') {
    logger.warn(`Service registry at ${configPath} is empty, starting with empty registry`);
    return { services: {} };
  }
  return { services: (parsed.services as Record<string, ServiceEntry>) || {} };
}

function requireEnv(name: string): string {
  const val = process.env[name];
  if (!val) throw new Error(`Required environment variable ${name} is not set`);
  return val;
}

export function loadConfig(): Config {
  const encKeyHex = requireEnv('WRAPTOKEN_ENC_KEY');
  if (!/^[0-9a-fA-F]{64}$/.test(encKeyHex)) {
    throw new Error('WRAPTOKEN_ENC_KEY must be exactly 64 hex characters (32 bytes)');
  }

  const configPath = process.env.BROKER_CONFIG_PATH || '/etc/agentd-secrets/config.yaml';

  const listenAddr = process.env.BROKER_LISTEN_ADDR || ':8080';
  const portMatch = listenAddr.match(/:(\d+)$/);
  const listenPort = portMatch ? parseInt(portMatch[1], 10) : 8080;

  const registry = loadServiceRegistry(configPath);

  return {
    oidc: {
      issuerURL: requireEnv('OIDC_ISSUER_URL'),
      realm: process.env.OIDC_REALM || '',
      clientID: requireEnv('OIDC_CLIENT_ID'),
      audience: process.env.OIDC_AUDIENCE || '',
    },
    vault: {
      addr: requireEnv('VAULT_ADDR'),
      oidcMount: process.env.VAULT_OIDC_MOUNT || 'oidc',
      oidcRole: process.env.VAULT_OIDC_ROLE || 'agentd-secrets',
      kvMount: process.env.VAULT_KV_MOUNT || 'secret',
      wrapTTL: process.env.VAULT_WRAP_TTL || '300s',
    },
    oidcCallback: {
      listenHost: process.env.OIDC_LOCAL_LISTEN_HOST || '127.0.0.1',
      listenPort: parseInt(process.env.OIDC_LOCAL_LISTEN_PORT || '8250', 10),
      redirectURI: process.env.OIDC_LOCAL_REDIRECT_URI || 'http://localhost:8250/oidc/callback',
    },
    wrapTokenEncKey: Buffer.from(encKeyHex, 'hex'),
    listenAddr,
    listenPort,
    login: {
      username: requireEnv('OIDC_USERNAME'),
      password: requireEnv('OIDC_PASSWORD'),
      loginTimeout: parseDuration(process.env.OIDC_LOGIN_TIMEOUT || '2m', 120_000),
      duoTimeout: parseDuration(process.env.OIDC_DUO_TIMEOUT || '5m', 300_000),
    },
    playwright: {
      headless: process.env.PLAYWRIGHT_HEADLESS !== 'false',
      browser: process.env.PLAYWRIGHT_BROWSER || 'chromium',
    },
    serviceRegistry: registry,
    configPath,
  };
}

export function validateServiceExists(config: Config, serviceName: string): ServiceEntry | null {
  return config.serviceRegistry.services[serviceName] || null;
}

logger.debug('Config module loaded');
