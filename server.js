const express = require('express');
const dnsSync = require('dns');
const dns     = require('dns').promises;
const axios   = require('axios');
const path    = require('path');
const crypto  = require('crypto');
const fs      = require('fs');
const bcrypt  = require('bcryptjs');
const Database = require('better-sqlite3');

dnsSync.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1']);

/* ============================================================
   DATABASE — PIN storage
   ============================================================ */
if (!fs.existsSync('./data')) fs.mkdirSync('./data');
const db = new Database('./data/app.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )
`);

// Seed PIN on first run (from env var, never hardcoded)
const pinRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('pin_hash');
if (!pinRow) {
  const initialPin = process.env.PIN_CODE;
  if (!initialPin) {
    console.error('ERROR: PIN_CODE environment variable is not set. Please set it before starting.');
    process.exit(1);
  }
  const hash = bcrypt.hashSync(initialPin, 10);
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('pin_hash', hash);
  console.log('PIN initialized from environment variable.');
}

/* ============================================================
   TOKEN — simple HMAC-based stateless auth
   ============================================================ */
const TOKEN_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function makeToken() {
  // Token is derived from the current pin_hash + secret so it
  // becomes invalid if the PIN is changed.
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('pin_hash');
  return crypto.createHmac('sha256', TOKEN_SECRET).update(row ? row.value : '').digest('hex');
}

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (token && token === makeToken()) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

/* ============================================================
   EXPRESS SETUP
   ============================================================ */
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* ============================================================
   AUTH ENDPOINT
   ============================================================ */
app.post('/api/auth', (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: 'PIN required' });

  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('pin_hash');
  if (!row) return res.status(500).json({ error: 'PIN not configured' });

  if (bcrypt.compareSync(String(pin), row.value)) {
    res.json({ token: makeToken() });
  } else {
    res.status(401).json({ error: "Noto'g'ri PIN. Qayta urinib ko'ring." });
  }
});

/* ============================================================
   IP LOOKUP — protected
   ============================================================ */
const CLOUDFLARE_RANGES = [
  '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '104.16.0.0/13', '104.24.0.0/14', '108.162.192.0/18',
  '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15',
  '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
  '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17'
];

let awsRanges = null;
async function getAwsRanges() {
  if (awsRanges) return awsRanges;
  try {
    const res = await axios.get('https://ip-ranges.amazonaws.com/ip-ranges.json', { timeout: 5000 });
    awsRanges = res.data.prefixes.map(p => p.ip_prefix);
    return awsRanges;
  } catch { return []; }
}

function ipToLong(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
}
function ipInCidr(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = ~(Math.pow(2, 32 - parseInt(bits)) - 1) >>> 0;
  return (ipToLong(ip) & mask) === (ipToLong(range) & mask);
}
function isCloudflareIP(ip) {
  return CLOUDFLARE_RANGES.some(cidr => { try { return ipInCidr(ip, cidr); } catch { return false; } });
}
function isAwsIP(ip, ranges) {
  return ranges.some(cidr => { try { return ipInCidr(ip, cidr); } catch { return false; } });
}
function extractDomain(url) {
  try {
    let u = url.trim();
    if (!u.startsWith('http')) u = 'https://' + u;
    return new URL(u).hostname.replace(/^www\./, '');
  } catch {
    return url.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  }
}

async function lookupIPs(hostname) {
  try {
    const addrs = await dns.resolve4(hostname);
    if (addrs && addrs.length > 0) return addrs;
  } catch {}
  try {
    const result = await new Promise((resolve, reject) => {
      dnsSync.lookup(hostname, { all: true, family: 4 }, (err, addrs) => {
        if (err) reject(err);
        else resolve(addrs.map(a => a.address));
      });
    });
    if (result && result.length > 0) return result;
  } catch {}
  try {
    const addrs = await dns.resolve6(hostname);
    return addrs;
  } catch {}
  return [];
}

async function checkHeaders(url) {
  try {
    let u = url.trim();
    if (!u.startsWith('http')) u = 'https://' + u;
    const res = await axios.get(u, {
      timeout: 8000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; IPFinder/1.0)' }
    });
    return res.headers;
  } catch { return {}; }
}

async function getGeoInfo(ips) {
  if (!ips || ips.length === 0) return {};
  const ipv4s = [...new Set(ips.filter(ip => /^\d+\.\d+\.\d+\.\d+$/.test(ip)))];
  if (ipv4s.length === 0) return {};
  try {
    const res = await axios.post(
      'http://ip-api.com/batch?fields=status,country,countryCode,city,org,as,isp,query',
      ipv4s.map(ip => ({ query: ip })),
      { timeout: 8000 }
    );
    const result = {};
    for (const item of res.data) {
      if (item.status === 'success') {
        result[item.query] = {
          country: item.country, countryCode: item.countryCode,
          city: item.city, org: item.org, as: item.as, isp: item.isp
        };
      }
    }
    return result;
  } catch { return {}; }
}

async function checkShodanInternetDB(ip) {
  try {
    const res = await axios.get(`https://internetdb.shodan.io/${ip}`, { timeout: 6000 });
    return {
      ports: res.data.ports || [],
      hostnames: res.data.hostnames || [],
      tags: res.data.tags || [],
      vulns: (res.data.vulns || []).slice(0, 5)
    };
  } catch { return null; }
}

async function findRealIP(domain) {
  const found = [];

  try {
    const mx = await dns.resolveMx(domain);
    for (const m of mx) {
      const ips = await lookupIPs(m.exchange);
      for (const ip of ips) found.push({ source: `MX: ${m.exchange}`, ip, method: 'MX' });
    }
  } catch {}

  try {
    const txt = await dns.resolveTxt(domain);
    for (const record of txt) {
      const joined = record.join('');
      const ipMatches = joined.match(/ip4:([\d.\/]+)/g);
      if (ipMatches) {
        for (const match of ipMatches) {
          const ip = match.replace('ip4:', '').split('/')[0];
          if (/^\d+\.\d+\.\d+\.\d+$/.test(ip))
            found.push({ source: 'SPF/TXT yozuvi', ip, method: 'SPF' });
        }
      }
    }
  } catch {}

  try {
    const ns = await dns.resolveNs(domain);
    for (const nameserver of ns) {
      const ips = await lookupIPs(nameserver);
      for (const ip of ips) found.push({ source: `NS: ${nameserver}`, ip, method: 'NS' });
    }
  } catch {}

  try {
    const soa = await dns.resolveSoa(domain);
    if (soa && soa.nsname) {
      const ips = await lookupIPs(soa.nsname);
      for (const ip of ips) found.push({ source: `SOA NS: ${soa.nsname}`, ip, method: 'SOA' });
    }
  } catch {}

  const srvList = [
    '_sip._tcp', '_sip._udp', '_sipfederationtls._tcp',
    '_xmpp-server._tcp', '_xmpp-client._tcp',
    '_smtp._tcp', '_submission._tcp', '_smtps._tcp',
    '_imap._tcp', '_imaps._tcp', '_pop3._tcp', '_pop3s._tcp',
    '_caldavs._tcp', '_carddavs._tcp', '_autodiscover._tcp'
  ];
  const srvResults = await Promise.allSettled(
    srvList.map(async (srv) => {
      const recs = await dns.resolveSrv(`${srv}.${domain}`).catch(() => []);
      const res = [];
      for (const r of recs) {
        const ips = await lookupIPs(r.name);
        for (const ip of ips) res.push({ source: `SRV ${srv}: ${r.name}`, ip, method: 'SRV' });
      }
      return res;
    })
  );
  for (const r of srvResults) if (r.status === 'fulfilled') found.push(...r.value);

  try {
    const dmarcTxt = await dns.resolveTxt(`_dmarc.${domain}`);
    for (const rec of dmarcTxt) {
      const joined = rec.join('');
      const match = joined.match(/rua=mailto:[^@]+@([^;,\s>]+)/i);
      if (match) {
        const reportDomain = match[1].replace(/[>]/g, '').trim();
        if (reportDomain !== domain) {
          const ips = await lookupIPs(reportDomain);
          for (const ip of ips) found.push({ source: `DMARC raporlash: ${reportDomain}`, ip, method: 'DMARC' });
        }
      }
    }
  } catch {}

  try {
    const res = await axios.get(
      `https://crt.sh/?q=%25.${domain}&output=json`,
      { timeout: 12000, headers: { 'Accept': 'application/json' } }
    );
    if (Array.isArray(res.data)) {
      const subdomainsFromCert = new Set();
      for (const cert of res.data) {
        const names = (cert.name_value || '').split('\n');
        for (const name of names) {
          const cleaned = name.trim().replace(/^\*\./, '');
          if (cleaned && cleaned.endsWith(domain) && cleaned !== domain)
            subdomainsFromCert.add(cleaned);
        }
      }
      const certResults = await Promise.allSettled(
        Array.from(subdomainsFromCert).slice(0, 60).map(async (sub) => {
          const ips = await lookupIPs(sub);
          return ips.map(ip => ({ source: `crt.sh: ${sub}`, ip, method: 'CRT.SH' }));
        })
      );
      for (const r of certResults) if (r.status === 'fulfilled') found.push(...r.value);
    }
  } catch {}

  try {
    const res = await axios.get(
      `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`,
      { timeout: 8000, headers: { 'Accept': 'application/json' } }
    );
    if (res.data && res.data.passive_dns) {
      for (const rec of res.data.passive_dns) {
        if (rec.record_type === 'A' && /^\d+\.\d+\.\d+\.\d+$/.test(rec.address))
          found.push({ source: `AlienVault OTX (${rec.first || 'tarix'})`, ip: rec.address, method: 'OTX' });
      }
    }
  } catch {}

  try {
    const res = await axios.get(
      `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=100`,
      { timeout: 8000, headers: { 'Accept': 'application/json' } }
    );
    if (res.data && res.data.results) {
      for (const r of res.data.results) {
        const ip = r.page && r.page.ip;
        if (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip))
          found.push({ source: `URLScan.io: ${r.page.domain || domain}`, ip, method: 'URLScan' });
      }
    }
  } catch {}

  try {
    const res = await axios.get(
      `https://api.hackertarget.com/hostsearch/?q=${domain}`,
      { timeout: 7000 }
    );
    if (res.data && !res.data.includes('error') && !res.data.includes('API count')) {
      const lines = res.data.trim().split('\n');
      for (const line of lines) {
        const parts = line.split(',');
        const host = parts[0]; const ip = parts[1];
        if (host && ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip.trim()))
          found.push({ source: `HackerTarget: ${host.trim()}`, ip: ip.trim(), method: 'HackerTarget' });
      }
    }
  } catch {}

  try {
    const res = await axios.get(
      `https://rapiddns.io/subdomain/${domain}?full=1`,
      { timeout: 8000, headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html' } }
    );
    if (res.data) {
      const ipMatches = res.data.match(/\b(\d{1,3}\.){3}\d{1,3}\b/g) || [];
      for (const ip of [...new Set(ipMatches)]) {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ip))
          found.push({ source: `RapidDNS`, ip, method: 'RapidDNS' });
      }
    }
  } catch {}

  try {
    const res = await axios.get(
      `https://viewdns.info/iphistory/?domain=${domain}`,
      { timeout: 8000, headers: { 'User-Agent': 'Mozilla/5.0' } }
    );
    if (res.data) {
      const ipMatches = res.data.match(/\b(\d{1,3}\.){3}\d{1,3}\b/g) || [];
      for (const ip of [...new Set(ipMatches)]) {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ip))
          found.push({ source: `ViewDNS IP tarixi`, ip, method: 'ViewDNS' });
      }
    }
  } catch {}

  const subdomains = [
    'mail', 'ftp', 'cpanel', 'whm', 'webmail', 'smtp', 'pop', 'imap',
    'direct', 'server', 'host', 'ns1', 'ns2', 'ns3', 'ns4', 'vpn', 'remote', 'api',
    'dev', 'staging', 'beta', 'admin', 'portal', 'shop', 'blog', 'forum',
    'old', 'origin', 'back', 'backup', 'unproxied', 'secure', 'www2', 'www1',
    'new', 'test', 'demo', 'static', 'media', 'cdn', 'assets', 'img', 'images',
    'upload', 'download', 'files', 'data', 'app', 'apps', 'mobile', 'api2',
    'v1', 'v2', 'v3', 'support', 'help', 'docs', 'wiki', 'status', 'monitor',
    'panel', 'dashboard', 'control', 'manage', 'db', 'mysql', 'redis',
    'git', 'jenkins', 'ci', 'jira', 'office', 'owa', 'autodiscover', 'm',
    'cms', 'wp', 'store', 'pay', 'billing', 'crm', 'erp',
    'intranet', 'internal', 'auth', 'sso', 'login', 'account',
    'chat', 'meet', 'video', 'stream', 'health', 'ping',
    'stg', 'prod', 'preprod', 'qa', 'uat', 'ssl', 'sftp',
    'mx1', 'mx2', 'pop3', 'ns', 'dns', 'mail2', 'smtp2', 'relay',
    'bounce', 'en', 'ru', 'uz', 'tr', 'de', 'fr',
    'proxy', 'gateway', 'edge', 'lb', 'load', 'web', 'web1', 'web2',
    'api3', 'rest', 'graphql', 'ws', 'socket', 'push', 'notify',
    'img2', 'assets2', 'cdn2', 'media2', 'upload2',
    'dev2', 'test2', 'staging2', 'preview', 'alpha',
    'mail3', 'smtp3', 'imap2', 'webmail2'
  ];
  const subResults = await Promise.allSettled(
    subdomains.map(async (sub) => {
      const hostname = `${sub}.${domain}`;
      const ips = await lookupIPs(hostname);
      return ips.map(ip => ({ source: `Subdomain: ${hostname}`, ip, method: 'Brute' }));
    })
  );
  for (const r of subResults) if (r.status === 'fulfilled') found.push(...r.value);

  return found;
}

app.post('/api/lookup', requireAuth, async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });

  const domain = extractDomain(url);
  const result = {
    domain,
    mainIPs: [],
    protection: { cloudflare: false, aws: false, name: null },
    headers: {},
    realIPCandidates: [],
    geoData: {},
    shodanData: {},
    error: null
  };

  try {
    result.mainIPs = await lookupIPs(domain);

    const awsR = await getAwsRanges();
    for (const ip of result.mainIPs) {
      if (isCloudflareIP(ip)) { result.protection.cloudflare = true; result.protection.name = 'Cloudflare'; }
      if (isAwsIP(ip, awsR)) {
        result.protection.aws = true;
        result.protection.name = result.protection.name ? result.protection.name + ' + AWS' : 'AWS/Amazon';
      }
    }

    const headers = await checkHeaders(url);
    const relevantHeaders = {};
    for (const h of ['server','x-powered-by','x-forwarded-for','x-real-ip','cf-ray',
      'cf-cache-status','x-amz-cf-id','x-amz-request-id','via','x-cache',
      'x-varnish','x-backend','x-origin-server','x-host']) {
      if (headers[h]) relevantHeaders[h] = headers[h];
    }
    result.headers = relevantHeaders;

    if (headers['cf-ray']) { result.protection.cloudflare = true; result.protection.name = 'Cloudflare'; }
    if (headers['x-amz-cf-id'] || headers['x-amz-request-id']) {
      result.protection.aws = true;
      result.protection.name = result.protection.name ? result.protection.name + ' + AWS' : 'AWS/Amazon';
    }

    if (result.protection.cloudflare || result.protection.aws) {
      const candidates = await findRealIP(domain);
      const unique = new Map();
      for (const c of candidates) {
        if (!unique.has(c.ip)) {
          const isCF = isCloudflareIP(c.ip);
          const isAWS = isAwsIP(c.ip, awsR);
          unique.set(c.ip, { ...c, isCF, isAWS, likely: !isCF && !isAWS });
        } else {
          const existing = unique.get(c.ip);
          if (!existing.sources) existing.sources = [existing.source];
          if (!existing.sources.includes(c.source)) existing.sources.push(c.source);
        }
      }
      result.realIPCandidates = Array.from(unique.values());

      const realCandidates = result.realIPCandidates.filter(c => c.likely).slice(0, 12);
      const shodanResults = await Promise.allSettled(
        realCandidates.map(async (c) => ({ ip: c.ip, data: await checkShodanInternetDB(c.ip) }))
      );
      for (const r of shodanResults) {
        if (r.status === 'fulfilled' && r.value.data)
          result.shodanData[r.value.ip] = r.value.data;
      }
    }

    const allIPs = [...result.mainIPs, ...result.realIPCandidates.map(c => c.ip)];
    result.geoData = await getGeoInfo(allIPs);

  } catch (err) {
    result.error = err.message;
  }

  res.json(result);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
