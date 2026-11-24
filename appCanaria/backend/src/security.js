import crypto from 'node:crypto';
export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`;
}
export function verifyPassword(password, stored) {
  try {
    const [, saltHex, hashHex] = String(stored).split(':');
    const hash = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), 64);
    return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
  } catch { return false; }
}
export const newToken = () => crypto.randomBytes(32).toString('hex');
export const newRequestId = () => 'req-' + crypto.randomBytes(8).toString('hex');
const ip4 = ip => { const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || ''); return m ? m.slice(1).map(Number) : null; };
export function ipInCidr(ip, cidr) {
  if (!cidr) return false;
  const [net, bitsStr] = cidr.split('/'); const bits = Number(bitsStr ?? 32);
  const a = ip4(ip?.replace('::ffff:', '')); const b = ip4(net);
  if (!a || !b || bits < 0 || bits > 32) return false;
  const toInt = o => ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (toInt(a) & mask) === (toInt(b) & mask);
}
export function isPrivateIp(ip) {
  const o = ip4((ip || '').replace('::ffff:', ''));
  if (ip === '::1' || ip === '127.0.0.1') return true;
  if (!o) return false;
  return o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) || o[0] === 127;
}
