// Entry point of the dashboard container: starts the Next.js server with ONE guard in front of it.
//
// The API rate-limits sign-ins, writes the audit log and recognises agents by the caller's address, which it reads from the
// X-Forwarded-For header. Next.js passes that header through untouched, so anyone who can reach this port directly could
// simply invent it: unlimited password guessing, a forged address in the audit log, and "I am that server" during agent
// registration. Here the header is believed only when the TCP connection comes from a trusted reverse proxy (by default:
// this machine itself, i.e. nginx on the Docker host). For everyone else it is replaced with the real peer address.
//
//   TRUSTED_PROXIES=10.0.0.5,10.0.1.0/24   a reverse proxy on ANOTHER machine (replaces the default list; "none" trusts nobody)
const fs = require('fs');
const http = require('http');
const net = require('net');

function defaultGateway() {
  // The Docker host as seen from inside the container (connections from nginx on the host arrive from this address).
  try {
    for (const line of fs.readFileSync('/proc/net/route', 'utf8').split('\n').slice(1)) {
      const f = line.trim().split(/\s+/);
      if (f.length > 2 && f[1] === '00000000' && f[2] !== '00000000') return f[2].match(/../g).reverse().map(h => parseInt(h, 16)).join('.');
    }
  } catch { /* not Linux */ }
  return null;
}

const configured = (process.env.TRUSTED_PROXIES || '').split(',').map(s => s.trim()).filter(Boolean);
const list = new net.BlockList();
const add = entry => {
  try {
    const [address, prefix] = entry.split('/');
    const family = net.isIPv6(address) ? 'ipv6' : 'ipv4';
    if (prefix !== undefined) list.addSubnet(address, Number(prefix), family); else list.addAddress(address, family);
  } catch { console.error(`TRUSTED_PROXIES: ignoring invalid entry "${entry}"`); }
};
if (configured.length) configured.filter(e => e.toLowerCase() !== 'none').forEach(add);
else ['127.0.0.1', '::1', defaultGateway()].filter(Boolean).forEach(add);

const normalise = address => (address || '').replace(/^::ffff:/i, '').split('%')[0];
const trusted = address => { try { return net.isIP(address) !== 0 && list.check(address, net.isIPv6(address) ? 'ipv6' : 'ipv4'); } catch { return false; } };
const FORWARDED = ['x-forwarded-for', 'x-real-ip', 'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-port', 'forwarded'];

const emit = http.Server.prototype.emit;
http.Server.prototype.emit = function (event, request, ...rest) {
  if ((event === 'request' || event === 'upgrade') && request && request.headers && request.socket) {
    const peer = normalise(request.socket.remoteAddress);
    if (!trusted(peer)) {
      for (const name of FORWARDED) delete request.headers[name];
      if (peer) request.headers['x-forwarded-for'] = peer;
      // rawHeaders is what some proxies copy from: keep it consistent
      if (Array.isArray(request.rawHeaders)) {
        const raw = [];
        for (let i = 0; i < request.rawHeaders.length; i += 2) if (!FORWARDED.includes(String(request.rawHeaders[i]).toLowerCase())) raw.push(request.rawHeaders[i], request.rawHeaders[i + 1]);
        if (peer) raw.push('X-Forwarded-For', peer);
        request.rawHeaders = raw;
      }
    }
  }
  return emit.call(this, event, request, ...rest);
};

require('./server.js');
