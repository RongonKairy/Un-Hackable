/**
 * Zerathon Guard for Node.js / Express. Zero dependencies.
 *   const { Zerathon } = require('./zerathon-guard');
 *   const guard = new Zerathon({ trustProxy: true });
 *   app.use(guard.middleware());
 *   // on failed login: guard.recordFailedLogin(req.ip)
 */
const fs = require('fs');
const https = require('https');

const SIGNATURES = {
  sqli: [70, /(\bunion\b\s+(all\s+)?select\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|;\s*drop\s+table|\bsleep\s*\(\s*\d+|information_schema|\bxp_cmdshell\b)/i],
  xss: [70, /(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|<\s*iframe|<\s*svg[^>]*\bon\w+\s*=)/i],
  path_traversal: [80, /(\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|\/proc\/self|c:\\windows)/i],
  cmd_injection: [80, /((;|\|\||&&|\|)\s*(cat|ls|curl|wget|bash|sh|nc|powershell)\b|\$\()/i],
  prompt_injection: [50, /(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)|reveal\s+(your\s+)?(system\s+)?prompt|developer\s+mode|disregard\s+.{0,20}(rules|instructions)|\bjailbreak\b|\bDAN\s+mode\b)/i],
};
const SCANNER_UA = /(sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|hydra|zgrab|nuclei)/i;
const HONEYPOTS = ['/admin.php', '/wp-login.php', '/.env', '/.git/config', '/phpmyadmin', '/backup.sql', '/config.json', '/server-status', '/xmlrpc.php', '/.aws/credentials'];
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'self'",
};

const norm = (s) => { for (let i = 0; i < 2; i++) { try { s = decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch { break; } } return s; };

class Zerathon {
  constructor(cfg = {}) {
    this.cfg = Object.assign({
      rateLimit: 120, rateWindow: 60, maxBodyBytes: 1_000_000,
      tempBanSeconds: 900, permBanAfterStrikes: 3,
      loginMaxFailures: 5, loginWindow: 600,
      allowIps: [], denyIps: [], denyCountries: [],
      honeypots: HONEYPOTS, auditLog: 'zerathon_audit.jsonl',
      telegramToken: process.env.ZERATHON_TG_TOKEN || '', telegramChat: process.env.ZERATHON_TG_CHAT || '',
      alertCooldown: 60, trustProxy: false,
    }, cfg);
    this.allow = new Set(this.cfg.allowIps);
    this.deny = new Set(this.cfg.denyIps);
    this.lockdown = false;
    this.hits = new Map(); this.fails = new Map(); this.strikes = new Map(); this.bans = new Map();
    this.lastAlert = 0;
  }

  ban(ip, reason, seconds = null) { this.bans.set(ip, { until: seconds ? Date.now() + seconds * 1000 : null, reason }); }
  unban(ip) { this.bans.delete(ip); this.strikes.delete(ip); }
  enableLockdown() { this.lockdown = true; this.log({ event: 'lockdown_on' }); this.alert('LOCKDOWN ENABLED', true); }
  disableLockdown() { this.lockdown = false; this.log({ event: 'lockdown_off' }); }

  activeBan(ip) {
    const b = this.bans.get(ip);
    if (!b) return null;
    if (b.until && b.until < Date.now()) { this.bans.delete(ip); return null; }
    return b;
  }

  window(map, ip, seconds) {
    const now = Date.now();
    const arr = (map.get(ip) || []).filter((t) => t > now - seconds * 1000);
    arr.push(now); map.set(ip, arr); return arr.length;
  }

  recordFailedLogin(ip, user = null) {
    const n = this.window(this.fails, ip, this.cfg.loginWindow);
    this.log({ event: 'failed_login', ip, user, count: n });
    if (n >= this.cfg.loginMaxFailures) this.punish(ip, 75, ['brute force: repeated failed logins']);
    return n;
  }
  recordSuccessfulLogin(ip) { this.fails.delete(ip); }

  inspect({ ip, path = '/', headers = {}, query = '', body = '', country = null }) {
    const ref = 'ZR-' + String(Date.now() % 100000).padStart(5, '0');
    if (this.allow.has(ip)) return { score: 0, decision: 'allow', action: 'none', reasons: ['allowlisted'], ref };
    if (this.deny.has(ip)) return { score: 100, decision: 'block', action: 'perm_ban', reasons: ['denylisted'], ref };
    const b = this.activeBan(ip);
    if (b) return { score: 100, decision: 'block', action: 'banned', reasons: ['active ban: ' + b.reason], ref };
    if (this.lockdown) return { score: 100, decision: 'block', action: 'lockdown', reasons: ['kill switch active'], ref };
    if (country && this.cfg.denyCountries.map((c) => c.toUpperCase()).includes(String(country).toUpperCase()))
      return { score: 100, decision: 'block', action: 'perm_ban', reasons: ['geo-blocked: ' + country], ref };

    const p = norm(path).toLowerCase().split('?')[0];
    if (this.cfg.honeypots.some((hp) => p === hp || p.startsWith(hp + '/'))) {
      this.log({ event: 'honeypot', ip, path }); this.ban(ip, 'honeypot ' + path);
      this.alert(`Honeypot hit by ${ip} on ${path}. Permanently banned.`);
      return { score: 100, decision: 'block', action: 'perm_ban', reasons: ['honeypot: ' + path], ref };
    }

    let score = 0; const reasons = [];
    const ua = headers['user-agent'] || '';
    if (!ua) { score += 15; reasons.push('missing user-agent'); }
    if (SCANNER_UA.test(ua)) { score += 70; reasons.push('known scanner user-agent'); }

    const n = this.window(this.hits, ip, this.cfg.rateWindow);
    if (n > 2 * this.cfg.rateLimit) { score += 70; reasons.push(`flood: ${n} req/${this.cfg.rateWindow}s`); }
    else if (n > this.cfg.rateLimit) { score += 40; reasons.push(`rate limit exceeded: ${n} req/${this.cfg.rateWindow}s`); }

    if ((body || '').length > this.cfg.maxBodyBytes) { score += 30; reasons.push('oversized body'); }

    const blob = norm([path, query, String(body).slice(0, 20000), headers.referer || '', headers.cookie || ''].join(' '));
    for (const [name, [pts, rx]] of Object.entries(SIGNATURES)) if (rx.test(blob)) { score += pts; reasons.push(name); }

    score = Math.min(score, 100);
    let d;
    if (score >= 86) d = { decision: 'block', action: 'perm_ban' };
    else if (score >= 61) d = { decision: 'block', action: 'temp_ban' };
    else if (score >= 31) d = { decision: 'challenge', action: 'captcha' };
    else d = { decision: 'allow', action: 'none' };
    const out = { score, ...d, reasons, ref };
    if (out.decision === 'block') this.punish(ip, score, reasons, ref);
    else if (out.decision === 'challenge') this.log({ event: 'challenge', ip, path, score, reasons });
    return out;
  }

  punish(ip, score, reasons, ref = '') {
    const strikes = (this.strikes.get(ip) || 0) + 1; this.strikes.set(ip, strikes);
    if (score >= 86 || strikes >= this.cfg.permBanAfterStrikes) {
      this.ban(ip, reasons.join('; '));
      this.alert(`PERMANENT BAN ${ip} | score ${score} | ${reasons.join('; ')}`);
    } else {
      this.ban(ip, reasons.join('; '), Math.min(this.cfg.tempBanSeconds * 2 ** (strikes - 1), 86400));
      if (strikes >= 2) this.alert(`Repeat offender ${ip} (strike ${strikes}) | ${reasons.join('; ')}`);
    }
    this.log({ event: 'block', ip, score, reasons, ref });
  }

  log(entry) {
    entry.ts = new Date().toISOString();
    fs.appendFile(this.cfg.auditLog, JSON.stringify(entry) + '\n', () => {});
  }

  alert(text, force = false) {
    const { telegramToken: t, telegramChat: c } = this.cfg;
    if (!t || !c) return;
    if (!force && Date.now() - this.lastAlert < this.cfg.alertCooldown * 1000) return;
    this.lastAlert = Date.now();
    const data = new URLSearchParams({ chat_id: c, text: '[Zerathon] ' + text }).toString();
    const req = https.request({ hostname: 'api.telegram.org', path: `/bot${t}/sendMessage`, method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) } });
    req.on('error', () => {}); req.write(data); req.end();
  }

  clientIp(req) {
    if (this.cfg.trustProxy) {
      return req.headers['cf-connecting-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;
    }
    return req.socket.remoteAddress;
  }

  middleware() {
    return (req, res, next) => {
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
      const body = typeof req.body === 'string' ? req.body : (req.body ? JSON.stringify(req.body) : '');
      const d = this.inspect({
        ip: this.clientIp(req), path: req.path, headers: req.headers,
        query: req.url.includes('?') ? req.url.split('?')[1] : '', body, country: req.headers['cf-ipcountry'],
      });
      req.zerathon = d;
      if (d.decision === 'block') return res.status(403).json({ error: 'Access denied', ref: d.ref });
      next(); // d.decision === 'challenge': show CAPTCHA / require 2FA in your route via req.zerathon
    };
  }
}

module.exports = { Zerathon, SECURITY_HEADERS };
