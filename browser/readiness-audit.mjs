import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const NAVIGATION_HOSTS = Object.freeze({
  aws: ['console.aws.amazon.com', '.console.aws.amazon.com', '.signin.aws.amazon.com'],
  gcp: ['console.cloud.google.com', 'accounts.google.com'],
  azure: ['portal.azure.com', 'login.microsoftonline.com'],
  cloudflare: ['dash.cloudflare.com'],
  github: ['github.com'],
  upstash: ['console.upstash.com'],
  vercel: ['vercel.com', '.vercel.com'],
  'digital-ocean': ['cloud.digitalocean.com'],
  netlify: ['app.netlify.com'],
  render: ['dashboard.render.com'],
  'fly-io': ['fly.io', '.fly.io'],
  heroku: ['dashboard.heroku.com', '.heroku.com'],
});

const DEFAULT_URLS = Object.freeze({
  aws: 'https://console.aws.amazon.com/',
  gcp: 'https://console.cloud.google.com/',
  azure: 'https://portal.azure.com/',
  cloudflare: 'https://dash.cloudflare.com/',
  github: 'https://github.com/',
  upstash: 'https://console.upstash.com/',
  vercel: 'https://vercel.com/dashboard',
  'digital-ocean': 'https://cloud.digitalocean.com/',
  netlify: 'https://app.netlify.com/',
  render: 'https://dashboard.render.com/',
  'fly-io': 'https://fly.io/dashboard',
  heroku: 'https://dashboard.heroku.com/',
});

export function isSafeMethod(method) {
  return SAFE_METHODS.has(String(method).toUpperCase());
}

export function isNavigationHostAllowed(provider, hostname) {
  const rules = NAVIGATION_HOSTS[provider] ?? [];
  return rules.some((rule) => rule.startsWith('.') ? hostname.endsWith(rule) : hostname === rule);
}

export function validateTarget(provider, input) {
  if (!Object.hasOwn(NAVIGATION_HOSTS, provider)) {
    throw new Error(`unsupported provider: ${provider}`);
  }
  const target = new URL(input ?? DEFAULT_URLS[provider]);
  if (target.protocol !== 'https:') {
    throw new Error('readiness browser target must use https');
  }
  if (!isNavigationHostAllowed(provider, target.hostname)) {
    throw new Error(`navigation host ${target.hostname} is not allowlisted for ${provider}`);
  }
  return target;
}

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) {
      throw new Error(`invalid argument sequence near ${key ?? '<end>'}`);
    }
    args[key.slice(2)] = value;
  }
  return args;
}

function safeNavigation(provider, requestUrl) {
  try {
    const url = new URL(requestUrl);
    return url.protocol === 'https:' && isNavigationHostAllowed(provider, url.hostname);
  } catch {
    return false;
  }
}

async function extractPage(page, engine, blockedRequests) {
  const title = await page.title();
  const url = page.url();
  const data = await page.evaluate(() => {
    const headings = [...document.querySelectorAll('h1,h2,h3')]
      .map((element) => element.textContent?.trim())
      .filter(Boolean)
      .slice(0, 40);
    const links = [...document.querySelectorAll('a[href]')]
      .map((element) => ({
        text: element.textContent?.trim().slice(0, 180) ?? '',
        href: element.href,
      }))
      .filter((entry) => entry.text || entry.href)
      .slice(0, 80);
    const bodyText = document.body?.innerText?.replace(/\s+/g, ' ').trim().slice(0, 16000) ?? '';
    return { headings, links, bodyText };
  });

  const authRequired = /sign[ -]?in|log[ -]?in|authenticate|continue with/i.test(
    `${title} ${data.headings.join(' ')} ${data.bodyText.slice(0, 1500)}`,
  );

  return {
    engine,
    finalUrl: url,
    title,
    authRequired,
    blockedRequests: blockedRequests.slice(0, 100),
    ...data,
  };
}

async function runPlaywright(provider, target) {
  let playwright;
  try {
    playwright = await import('playwright');
  } catch (error) {
    throw new Error(`playwright is not installed: ${error.message}`);
  }
  const browser = await playwright.chromium.launch({ headless: true });
  const storageState = process.env.CANONICAL_PLAYWRIGHT_STORAGE_STATE || undefined;
  const context = await browser.newContext(storageState ? { storageState } : {});
  const blockedRequests = [];

  await context.route('**/*', async (route) => {
    const request = route.request();
    const method = request.method().toUpperCase();
    if (!isSafeMethod(method)) {
      blockedRequests.push({ method, url: request.url(), reason: 'non-read-http-method' });
      await route.abort('blockedbyclient');
      return;
    }
    if (request.isNavigationRequest() && !safeNavigation(provider, request.url())) {
      blockedRequests.push({ method, url: request.url(), reason: 'navigation-host-not-allowlisted' });
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });

  try {
    const page = await context.newPage();
    await page.goto(target.href, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForTimeout(1000);
    return await extractPage(page, 'playwright', blockedRequests);
  } finally {
    await browser.close();
  }
}

async function runPuppeteer(provider, target) {
  let puppeteer;
  try {
    puppeteer = await import('puppeteer');
  } catch (error) {
    throw new Error(`puppeteer is not installed: ${error.message}`);
  }
  const userDataDir = process.env.CANONICAL_PUPPETEER_USER_DATA_DIR || undefined;
  const browser = await puppeteer.default.launch({ headless: true, ...(userDataDir ? { userDataDir } : {}) });
  const blockedRequests = [];

  try {
    const page = await browser.newPage();
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      const method = request.method().toUpperCase();
      if (!isSafeMethod(method)) {
        blockedRequests.push({ method, url: request.url(), reason: 'non-read-http-method' });
        void request.abort('blockedbyclient');
        return;
      }
      if (request.isNavigationRequest() && !safeNavigation(provider, request.url())) {
        blockedRequests.push({ method, url: request.url(), reason: 'navigation-host-not-allowlisted' });
        void request.abort('blockedbyclient');
        return;
      }
      void request.continue();
    });
    await page.goto(target.href, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await new Promise((resolve) => setTimeout(resolve, 1000));
    return await extractPage(page, 'puppeteer', blockedRequests);
  } finally {
    await browser.close();
  }
}

export async function runBrowserAudit({ provider, engine, url }) {
  const target = validateTarget(provider, url);
  const page = engine === 'playwright'
    ? await runPlaywright(provider, target)
    : engine === 'puppeteer'
      ? await runPuppeteer(provider, target)
      : (() => { throw new Error(`unsupported browser engine: ${engine}`); })();

  return {
    provider,
    mode: 'strict-read-only-browser',
    requestPolicy: {
      allowedMethods: [...SAFE_METHODS],
      blockedMethods: ['POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'TRACE'],
      topLevelNavigationAllowlist: NAVIGATION_HOSTS[provider],
      clicksPerformed: 0,
      formsSubmitted: 0,
    },
    page,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await runBrowserAudit({
    provider: args.provider,
    engine: args.engine,
    url: args.url,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

const thisFile = fileURLToPath(import.meta.url);
const invokedFile = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (thisFile === invokedFile) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
