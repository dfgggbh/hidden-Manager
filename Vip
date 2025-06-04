// ========================================
// CORE SYSTEM IMPLEMENTATION (Enhanced)
// ========================================

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { jwt } from 'hono/jwt';
import { serveStatic } from 'hono/cloudflare-workers';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import * as yaml from 'yaml';
import * as OTPAuth from 'otpauth';
import { createHash } from 'crypto';

// Extended Types with XHTTP Support
interface EnhancedUser {
  id: string;
  email: string;
  role: 'admin' | 'user' | 'reseller';
  is_active: boolean;
  created_at: Date;
  expires_at: Date;
  traffic_used: number;
  traffic_limit: number;
  upload_used: number;
  download_used: number;
  notification_preferences: {
    email: boolean;
    telegram: boolean;
    webhook: boolean;
    whatsapp: boolean;
  };
  telegram_chat_id?: string;
  webhook_url?: string;
  warp_license_key?: string;
  warp_plus_enabled: boolean;
  warp_usage: number;
  warp_limit: number;
  devices: Device[];
  configs: Config[];
  otp_enabled: boolean;
  otp_secret?: string;
  subscription_plan?: string;
  referral_code?: string;
  referrer_id?: string;
  payment_status: 'active' | 'pending' | 'expired';
  last_payment_date?: Date;
  next_payment_date?: Date;
  xhttp_settings?: XHTTPSettings;
}

interface XHTTPSettings {
  enabled: boolean;
  host_spoofing: string[];
  path_strategy: 'random' | 'static' | 'date_based';
  static_path?: string;
  fragment_packets: boolean;
  packet_delay: number;
  padding_size: number;
  fake_headers: {
    'User-Agent': string[];
    'Accept': string[];
    'Accept-Language': string[];
  };
  tls_fingerprint: string;
}

interface Device {
  id: string;
  name: string;
  type: string;
  user_agent: string;
  ip: string;
  location: string;
  last_active: Date;
  is_trusted: boolean;
  client_type?: 'clash' | 'singbox' | 'v2ray' | 'wireguard';
}

interface Config {
  id: string;
  name: string;
  protocol: 'vmess' | 'vless' | 'trojan' | 'shadowsocks2022' | 'hysteria2' | 'wireguard' | 'cloudflared' | 'xhttp';
  server: string;
  port: number;
  settings: {
    [key: string]: any;
  };
  shared_users: string[];
  traffic_limit?: number;
  speed_limit?: number;
  is_active: boolean;
  created_at: Date;
  warp_integrated: boolean;
  warp_settings?: {
    endpoint: string;
    public_key: string;
    private_key: string;
    reserved: number[];
  };
  reality_settings?: {
    public_key: string;
    private_key: string;
    short_id: string;
  };
  tls_fingerprint?: string;
  mux_settings?: {
    enabled: boolean;
    protocol: string;
    max_connections: number;
  };
  xhttp_settings?: XHTTPSettings;
  latency?: number;
  health_status: 'healthy' | 'degraded' | 'offline';
  last_health_check?: Date;
}

interface Env {
  DB: D1Database;
  KV: KVNamespace;
  R2: R2Bucket;
  VPN_JWT_SECRET: string;
  WARP_API_KEY?: string;
  TELEGRAM_BOT_TOKEN?: string;
  SMTP_HOST?: string;
  SMTP_PORT?: string;
  SMTP_USER?: string;
  SMTP_PASSWORD?: string;
  RATE_LIMIT_ENABLED?: string;
  CF_API_TOKEN?: string;
  CF_ACCOUNT_ID?: string;
  PAYMENT_API_KEY?: string;
}

// ========================================
// XHTTP CONFIG GENERATOR
// ========================================

class XHTTPConfigGenerator {
  generateXHTTPConfig(baseConfig: Config, user?: EnhancedUser): string {
    if (!baseConfig.xhttp_settings) {
      throw new Error('XHTTP settings not configured');
    }

    const settings = baseConfig.xhttp_settings;
    const xhttpConfig = {
      ...baseConfig,
      protocol: 'xhttp',
      settings: {
        ...baseConfig.settings,
        host: this.getSpoofedHost(settings.host_spoofing),
        path: this.generatePath(settings.path_strategy, settings.static_path),
        headers: this.generateFakeHeaders(settings.fake_headers),
        fragment_packets: settings.fragment_packets,
        packet_delay: settings.packet_delay,
        padding_size: settings.padding_size,
        tls_fingerprint: settings.tls_fingerprint
      }
    };

    return this.generateConfig(xhttpConfig, user);
  }

  private getSpoofedHost(hosts: string[]): string {
    return hosts[Math.floor(Math.random() * hosts.length)];
  }

  private generatePath(strategy: 'random' | 'static' | 'date_based', staticPath?: string): string {
    switch(strategy) {
      case 'random':
        return `/cdn/${Math.random().toString(36).substring(2, 8)}/update`;
      case 'static':
        return staticPath || '/cdn/update';
      case 'date_based':
        const now = new Date();
        return `/cdn/${now.getFullYear()}/${now.getMonth() + 1}/${now.getDate()}/update`;
    }
  }

  private generateFakeHeaders(headers: XHTTPSettings['fake_headers']): Record<string, string> {
    return {
      'User-Agent': headers['User-Agent'][Math.floor(Math.random() * headers['User-Agent'].length)],
      'Accept': headers['Accept'][Math.floor(Math.random() * headers['Accept'].length)],
      'Accept-Language': headers['Accept-Language'][Math.floor(Math.random() * headers['Accept-Language'].length)],
      'Cache-Control': 'no-cache',
      'Pragma': 'no-cache'
    };
  }

  generateClashXHTTPConfig(configs: Config[], user?: EnhancedUser): string {
    const proxies = configs.map(config => {
      if (config.protocol === 'xhttp' && config.xhttp_settings) {
        return {
          name: config.name,
          type: 'xhttp',
          server: config.server,
          port: config.port,
          uuid: config.settings.uuid || user?.id,
          network: 'tcp',
          tls: true,
          'tls-fingerprint': config.xhttp_settings.tls_fingerprint,
          'fake-host': this.getSpoofedHost(config.xhttp_settings.host_spoofing),
          'fake-path': this.generatePath(config.xhttp_settings.path_strategy, config.xhttp_settings.static_path),
          'fragment-packet': config.xhttp_settings.fragment_packets,
          'packet-delay': config.xhttp_settings.packet_delay,
          'padding-size': config.xhttp_settings.padding_size,
          headers: this.generateFakeHeaders(config.xhttp_settings.fake_headers)
        };
      }
      return null;
    }).filter(Boolean);

    return yaml.dump({
      proxies,
      'proxy-groups': [{
        name: 'XHTTP-Auto',
        type: 'url-test',
        proxies: proxies.map(p => p.name),
        url: 'http://www.gstatic.com/generate_204',
        interval: 300
      }],
      rules: [
        'DOMAIN-SUFFIX,cloudflare.com,DIRECT',
        'GEOIP,IR,DIRECT',
        'MATCH,XHTTP-Auto'
      ]
    });
  }

  generateSingboxXHTTPConfig(configs: Config[], user?: EnhancedUser): string {
    const outbounds = configs.map(config => {
      if (config.protocol === 'xhttp' && config.xhttp_settings) {
        return {
          type: 'xhttp',
          tag: config.name,
          server: config.server,
          server_port: config.port,
          uuid: config.settings.uuid || user?.id,
          transport: {
            type: 'tcp',
            host: this.getSpoofedHost(config.xhttp_settings.host_spoofing),
            path: this.generatePath(config.xhttp_settings.path_strategy, config.xhttp_settings.static_path),
            headers: this.generateFakeHeaders(config.xhttp_settings.fake_headers)
          },
          tls: {
            enabled: true,
            fingerprint: config.xhttp_settings.tls_fingerprint
          },
          packet_encoding: {
            fragment: config.xhttp_settings.fragment_packets,
            delay: config.xhttp_settings.packet_delay,
            padding: config.xhttp_settings.padding_size
          }
        };
      }
      return null;
    }).filter(Boolean);

    return JSON.stringify({
      outbounds: [
        ...outbounds,
        {
          type: 'direct',
          tag: 'direct'
        },
        {
          type: 'block',
          tag: 'block'
        }
      ]
    }, null, 2);
  }
}

// ========================================
// MAIN APPLICATION (Enhanced)
// ========================================

const app = new Hono<{ Bindings: Env }>();

// Middleware
app.use('*', cors());
app.use('*', async (c, next) => {
  // Enhanced rate limiting with device fingerprinting
  if (c.env.RATE_LIMIT_ENABLED === 'true') {
    const limiter = new RateLimiter(c.env.KV);
    const ip = c.req.header('CF-Connecting-IP') || '';
    const deviceId = c.req.header('X-Device-ID') || createHash('sha256')
      .update(ip + (c.req.header('User-Agent') || ''))
      .digest('hex');
    
    const isAllowed = await Promise.all([
      limiter.isAllowed(`ip:${ip}`, 100, 60),
      limiter.isAllowed(`device:${deviceId}`, 50, 60)
    ]);
    
    if (!isAllowed.every(Boolean)) {
      throw new HTTPException(429, { message: 'Too many requests' });
    }
  }
  
  await next();
});

// XHTTP Routes
app.post('/api/xhttp/config', async (c) => {
  const payload = c.get('jwtPayload');
  const configData = await c.req.json();
  
  const db = new EnhancedDatabaseManager(c.env.DB);
  const config = await db.createConfig({
    ...configData,
    protocol: 'xhttp'
  });
  
  return c.json(config);
});

app.get('/api/xhttp/configs', async (c) => {
  const payload = c.get('jwtPayload');
  const db = new EnhancedDatabaseManager(c.env.DB);
  
  const configs = (await db.getUserConfigs(payload.userId))
    .filter(c => c.protocol === 'xhttp');
  
  return c.json(configs);
});

// Export routes for configs
app.get('/api/configs/export/:format', async (c) => {
  const payload = c.get('jwtPayload');
  const format = c.req.param('format');
  const db = new EnhancedDatabaseManager(c.env.DB);
  const configs = await db.getUserConfigs(payload.userId);
  
  const generator = new EnhancedConfigGenerator();
  let content: string;
  let contentType: string;
  
  switch(format) {
    case 'clash':
      content = generator.generateClashConfig(configs);
      contentType = 'application/yaml';
      break;
    case 'singbox':
      content = generator.generateSingboxConfig(configs);
      contentType = 'application/json';
      break;
    case 'wireguard':
      content = generator.generateWireguardConfig(configs[0]); // Assuming one WG config
      contentType = 'text/plain';
      break;
    default:
      throw new HTTPException(400, { message: 'Invalid format' });
  }
  
  // Store in R2 for download
  const key = `configs/${payload.userId}/${format}-${Date.now()}.${format === 'clash' ? 'yaml' : format === 'singbox' ? 'json' : 'conf'}`;
  await c.env.R2.put(key, content);
  
  return c.json({ download_url: `/download/${key}` });
});

// Serve static files (including config exports)
app.get('/download/*', async (c) => {
  const key = c.req.path.replace('/download/', '');
  const object = await c.env.R2.get(key);
  
  if (!object) {
    throw new HTTPException(404);
  }
  
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  
  return new Response(object.body, { headers });
});

// ========================================
// CRON HANDLERS
// ========================================

async function handleExpiredUsers(env: Env) {
  const db = new EnhancedDatabaseManager(env.DB);
  await db.disableExpiredUsers();
  
  // Notify users who will expire in 3 days
  const expiringUsers = await db.getExpiringUsers(3);
  const notificationManager = new NotificationManager(env, db);
  
  await Promise.all(expiringUsers.map(user => 
    notificationManager.sendNotification(
      user.id, 
      'expiration', 
      `Your subscription will expire in 3 days. Renew now to avoid interruption.`
    )
  ));
}

async function handleTrafficAlerts(env: Env) {
  const db = new EnhancedDatabaseManager(env.DB);
  const highUsageUsers = await db.getHighUsageUsers(0.9); // 90% usage
  
  const notificationManager = new NotificationManager(env, db);
  await Promise.all(highUsageUsers.map(user => 
    db.checkAndNotifyTraffic(user.id)
  ));
}

async function handleWarpRotation(env: Env) {
  const db = new EnhancedDatabaseManager(env.DB);
  const users = await db.getAllUsers();
  
  const authManager = new EnhancedAuthManager(env, db);
  await Promise.all(users
    .filter(u => u.warp_plus_enabled)
    .map(user => authManager.generateWarpConfig(user.id))
  );
}

// ========================================
// WORKER EXPORTS
// ========================================

export default {
  fetch: app.fetch,
  scheduled: async (event: ScheduledEvent, env: Env, ctx: ExecutionContext) => {
    switch(event.cron) {
      case '0 0 * * *': // Daily
        await handleExpiredUsers(env);
        await handleTrafficAlerts(env);
        break;
      case '0 */6 * * *': // Every 6 hours
        await handleWarpRotation(env);
        break;
    }
  }
};

-- Users table
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  role TEXT CHECK(role IN ('admin', 'user', 'reseller')) NOT NULL DEFAULT 'user',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP,
  traffic_used INTEGER NOT NULL DEFAULT 0,
  traffic_limit INTEGER NOT NULL DEFAULT 1073741824, -- 1GB
  upload_used INTEGER NOT NULL DEFAULT 0,
  download_used INTEGER NOT NULL DEFAULT 0,
  notification_preferences TEXT NOT NULL DEFAULT '{"email":true,"telegram":false,"webhook":false,"whatsapp":false}',
  telegram_chat_id TEXT,
  webhook_url TEXT,
  warp_license_key TEXT,
  warp_plus_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  warp_usage INTEGER NOT NULL DEFAULT 0,
  warp_limit INTEGER NOT NULL DEFAULT 536870912, -- 512MB
  otp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  otp_secret TEXT,
  subscription_plan TEXT,
  referral_code TEXT UNIQUE,
  referrer_id TEXT,
  payment_status TEXT CHECK(payment_status IN ('active', 'pending', 'expired')) NOT NULL DEFAULT 'pending',
  last_payment_date TIMESTAMP,
  next_payment_date TIMESTAMP,
  xhttp_settings TEXT
);

-- Devices table
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  type TEXT,
  user_agent TEXT,
  ip TEXT,
  location TEXT,
  last_active TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
  client_type TEXT CHECK(client_type IN ('clash', 'singbox', 'v2ray', 'wireguard'))
);

-- Configs table
CREATE TABLE configs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  protocol TEXT CHECK(protocol IN ('vmess', 'vless', 'trojan', 'shadowsocks2022', 'hysteria2', 'wireguard', 'cloudflared', 'xhttp')) NOT NULL,
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  settings TEXT NOT NULL DEFAULT '{}',
  shared_users TEXT NOT NULL DEFAULT '[]',
  traffic_limit INTEGER,
  speed_limit INTEGER,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  warp_integrated BOOLEAN NOT NULL DEFAULT FALSE,
  warp_settings TEXT,
  reality_settings TEXT,
  tls_fingerprint TEXT,
  mux_settings TEXT,
  xhttp_settings TEXT,
  latency INTEGER,
  health_status TEXT CHECK(health_status IN ('healthy', 'degraded', 'offline')) NOT NULL DEFAULT 'healthy',
  last_health_check TIMESTAMP
);

-- Sessions table
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  user_agent TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  refresh_token TEXT NOT NULL
);

-- Traffic logs
CREATE TABLE traffic_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  config_id TEXT REFERENCES configs(id) ON DELETE SET NULL,
  device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
  upload_bytes INTEGER NOT NULL,
  download_bytes INTEGER NOT NULL,
  timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Notifications
CREATE TABLE notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  is_read BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Payment history
CREATE TABLE payments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL,
  plan_id TEXT,
  payment_method TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_configs_user_id ON configs(user_id);
CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_traffic_logs_user_id ON traffic_logs(user_id);
CREATE INDEX idx_traffic_logs_timestamp ON traffic_logs(timestamp);
CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_payments_user_id ON payments(user_id);

<!-- src/routes/+page.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import Dashboard from '../components/Dashboard.svelte';
  import Configs from '../components/Configs.svelte';
  import Devices from '../components/Devices.svelte';
  import Settings from '../components/Settings.svelte';
  import XHTTPConfig from '../components/XHTTPConfig.svelte';

  let activeTab = 'dashboard';
  let user: any = null;
  let stats: any = null;

  onMount(async () => {
    const res = await fetch('/api/user/me');
    if (res.ok) {
      user = await res.json();
    }
    
    const statsRes = await fetch('/api/stats');
    if (statsRes.ok) {
      stats = await statsRes.json();
    }
  });

  $: currentTab = $page.url.searchParams.get('tab') || 'dashboard';
</script>

<main class="container mx-auto px-4 py-8">
  {#if user}
    <div class="tabs mb-8">
      <a 
        class="tab {activeTab === 'dashboard' ? 'tab-active' : ''}" 
        href="?tab=dashboard"
        on:click={() => activeTab = 'dashboard'}
      >
        Dashboard
      </a>
      <a 
        class="tab {activeTab === 'configs' ? 'tab-active' : ''}" 
        href="?tab=configs"
        on:click={() => activeTab = 'configs'}
      >
        Configurations
      </a>
      <a 
        class="tab {activeTab === 'xhttp' ? 'tab-active' : ''}" 
        href="?tab=xhttp"
        on:click={() => activeTab = 'xhttp'}
      >
        XHTTP
      </a>
      <a 
        class="tab {activeTab === 'devices' ? 'tab-active' : ''}" 
        href="?tab=devices"
        on:click={() => activeTab = 'devices'}
      >
        Devices
      </a>
      <a 
        class="tab {activeTab === 'settings' ? 'tab-active' : ''}" 
        href="?tab=settings"
        on:click={() => activeTab = 'settings'}
      >
        Settings
      </a>
    </div>

    {#if activeTab === 'dashboard' && stats}
      <Dashboard {user} {stats} />
    {:else if activeTab === 'configs'}
      <Configs {user} />
    {:else if activeTab === 'xhttp'}
      <XHTTPConfig {user} />
    {:else if activeTab === 'devices'}
      <Devices {user} />
    {:else if activeTab === 'settings'}
      <Settings {user} />
    {/if}
  {:else}
    <div class="text-center py-20">
      <h1 class="text-3xl font-bold mb-4">Loading...</h1>
    </div>
  {/if}
</main>

#!/usr/bin/env node
import { Command } from 'commander';
import axios from 'axios';
import chalk from 'chalk';
import inquirer from 'inquirer';
import fs from 'fs';
import path from 'path';
import os from 'os';

const program = new Command();
const CONFIG_PATH = path.join(os.homedir(), '.vpn-cli-config.json');

// Load saved config
let config = {};
try {
  config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
} catch (err) {
  // Config doesn't exist yet
}

const api = axios.create({
  baseURL: config.baseUrl || 'https://your-vpn-api.com',
  headers: {
    'Authorization': config.token ? `Bearer ${config.token}` : undefined
  }
});

program
  .name('vpn-cli')
  .description('CLI tool for managing VPN subscriptions')
  .version('1.0.0');

program.command('login')
  .description('Login to your VPN account')
  .action(async () => {
    const { email, password } = await inquirer.prompt([
      {
        type: 'input',
        name: 'email',
        message: 'Email:'
      },
      {
        type: 'password',
        name: 'password',
        message: 'Password:'
      }
    ]);

    try {
      const res = await api.post('/api/auth/login', { email, password });
      config.token = res.data.token;
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
      console.log(chalk.green('Successfully logged in!'));
    } catch (err) {
      console.error(chalk.red('Login failed:'), err.response?.data?.message || err.message);
    }
  });

program.command('configs')
  .description('List your VPN configurations')
  .option('--format <format>', 'Output format (json, yaml, table)', 'table')
  .action(async (options) => {
    try {
      const res = await api.get('/api/configs');
      
      if (options.format === 'json') {
        console.log(JSON.stringify(res.data, null, 2));
      } else if (options.format === 'yaml') {
        console.log(yaml.dump(res.data));
      } else {
        // Table format
        console.log(chalk.bold('\nYour VPN Configurations:\n'));
        console.table(res.data.map(c => ({
          Name: c.name,
          Protocol: c.protocol,
          Server: c.server,
          Port: c.port,
          Status: c.is_active ? chalk.green('Active') : chalk.red('Inactive')
        })));
      }
    } catch (err) {
      console.error(chalk.red('Failed to fetch configs:'), err.response?.data?.message || err.message);
    }
  });

program.command('export')
  .description('Export a configuration')
  .argument('<configId>', 'Configuration ID')
  .option('--format <format>', 'Export format (clash, singbox, wireguard)', 'clash')
  .action(async (configId, options) => {
    try {
      const res = await api.get(`/api/configs/export/${options.format}?configId=${configId}`);
      const fileName = `vpn-config-${configId}.${options.format === 'clash' ? 'yaml' : options.format === 'singbox' ? 'json' : 'conf'}`;
      fs.writeFileSync(fileName, res.data);
      console.log(chalk.green(`Configuration exported to ${fileName}`));
    } catch (err) {
      console.error(chalk.red('Export failed:'), err.response?.data?.message || err.message);
    }
  });

program.command('warp')
  .description('Manage WARP configuration')
  .command('rotate')
  .description('Rotate WARP license key')
  .action(async () => {
    try {
      const res = await api.post('/api/warp/rotate');
      console.log(chalk.green('WARP key rotated:'), res.data.license_key);
    } catch (err) {
      console.error(chalk.red('Rotation failed:'), err.response?.data?.message || err.message);
    }
  });

program.parse(process.argv);

# wrangler.toml
name = "vpn-management-system"
compatibility_date = "2023-08-01"
main = "src/index.ts"
workers_dev = true

[[d1_databases]]
binding = "DB"
database_name = "vpn-db"
database_id = "YOUR_D1_DATABASE_ID"

[[kv_namespaces]]
binding = "KV"
id = "YOUR_KV_NAMESPACE_ID"

[[r2_buckets]]
binding = "R2"
bucket_name = "vpn-configs"
preview_bucket_name = "vpn-configs-preview"

[triggers]
crons = [
  "0 0 * * *",    # Daily at midnight
  "0 */6 * * *"   # Every 6 hours
]

[vars]
VPN_JWT_SECRET = "@vpn_jwt_secret"
RATE_LIMIT_ENABLED = "true"

[env.production]
vars = { 
  CF_API_TOKEN = "@cf_api_token",
  CF_ACCOUNT_ID = "@cf_account_id",
  WARP_API_KEY = "@warp_api_key"
}
