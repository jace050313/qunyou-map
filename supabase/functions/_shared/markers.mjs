const DAY = 86_400_000;
const SESSION_SECONDS = 8 * 60 * 60;
const LOGIN_WINDOW = 15 * 60_000;
const PAGE_SIZE = 50;
const MAX_BODY = 48 * 1024;
const AVATAR_PATTERN = /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/;
const OWNER_PATTERN = /^[a-f0-9]{64}$/;
const ID_PATTERN = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const HEX_256 = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const EMOJIS = new Set(['😀', '😄', '😎', '🥳', '🐱', '🐶', '🐼', '🦊', '🐸', '🐳', '🍊', '🍓', '🍰', '🍜', '🍵', '🎧', '🎸', '🚀', '✈️', '🪐', '🌈', '⚽', '🔥', '🌰', '🚦', '🥐', '🍧', '🍬', '🍡', '🐚', '🪁']);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers }
  });
}

function hex(buffer) {
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function digest(value) {
  return hex(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}

async function readBody(request) {
  if (request.headers.get('content-type')?.split(';')[0].trim() !== 'application/json') {
    throw new HttpError(415, '请求必须是 JSON。');
  }
  if (Number(request.headers.get('content-length')) > MAX_BODY) {
    throw new HttpError(413, '上传的头像太大。');
  }
  const reader = request.body?.getReader();
  if (!reader) throw new HttpError(400, '缺少请求内容。');

  const parts = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY) {
      await reader.cancel().catch(() => {});
      throw new HttpError(413, '上传的头像太大。');
    }
    parts.push(value);
  }

  try {
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) {
      bytes.set(part, offset);
      offset += part.byteLength;
    }
    const body = JSON.parse(new TextDecoder().decode(bytes));
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
    return body;
  } catch {
    throw new HttpError(400, '请求内容格式有误。');
  }
}

function markerFields(body, now) {
  const name = typeof body.name === 'string' ? body.name.trim().replace(/\s+/g, ' ') : '';
  if (!name || Array.from(name).length > 16) throw new HttpError(400, '请输入 1 到 16 个字符的名字。');
  if (!Number.isFinite(body.lat) || Math.abs(body.lat) > 90 ||
      !Number.isFinite(body.lng) || Math.abs(body.lng) > 180) {
    throw new HttpError(400, '请选择有效的地图位置。');
  }

  const avatar = body.avatar_url ?? '';
  if (avatar !== '') {
    const match = typeof avatar === 'string' && AVATAR_PATTERN.exec(avatar);
    if (!match || match[1].length > 24_000) throw new HttpError(400, '头像格式不正确或太大。');
    let image;
    try { image = atob(match[1]); } catch { image = ''; }
    if (!image.startsWith('\xff\xd8\xff') || !image.endsWith('\xff\xd9')) {
      throw new HttpError(400, '无法读取头像。');
    }
  }

  const fields = {
    name,
    emoji: EMOJIS.has(body.emoji) ? body.emoji : '',
    avatar_url: avatar,
    lat: Math.round(body.lat * 100) / 100,
    lng: Math.round(body.lng * 100) / 100
  };
  const days = body.duration_days;
  if (days === null) fields.expires_at = null;
  else if (days !== undefined) {
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      throw new HttpError(400, '请输入 1 到 3650 的整数天数。');
    }
    fields.expires_at = new Date(now + days * DAY).toISOString();
  }
  return fields;
}

function publicRecord(record, ownerHash) {
  const { owner_hash, ...marker } = record;
  return { ...marker, is_mine: owner_hash === ownerHash };
}

export function createApp(store, { password, passwordDigest, secret, secure = false, bearer = false } = {}) {
  const cookie = 'qunyou_admin';
  const key = secret ? crypto.subtle.importKey(
    'raw', typeof secret === 'string' ? encoder.encode(secret) : secret,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  ) : null;
  const sign = async (value) => hex(await crypto.subtle.sign('HMAC', await key, encoder.encode(value)));
  const expectedPassword = key && (HEX_256.test(passwordDigest) ? passwordDigest :
    (password ? sign('password:' + password) : null));
  const sessionMessage = (value, owner) => 'session:' + (password || passwordDigest) + ':' +
    (bearer ? owner + ':' : '') + value;

  async function verify(signature, value) {
    if (!HEX_256.test(signature)) return false;
    const bytes = Uint8Array.from(signature.match(/../g), (part) => parseInt(part, 16));
    return crypto.subtle.verify('HMAC', await key, bytes, encoder.encode(value));
  }

  async function isAdmin(request, now, ownerHash) {
    if (!expectedPassword || (bearer && !ownerHash)) return false;
    const token = bearer ? request.headers.get('authorization')?.match(/^Bearer ([^\s]+)$/)?.[1] :
      request.headers.get('cookie')?.split(/;\s*/).find((pair) => pair.startsWith(cookie + '='))?.slice(cookie.length + 1);
    if (!token) return false;
    const [expires, nonce, signature, extra] = token.split('.');
    if (extra !== undefined || !/^\d+$/.test(expires) || Number(expires) <= now || !ID_PATTERN.test(nonce)) return false;
    return verify(signature, sessionMessage(expires + '.' + nonce, ownerHash));
  }

  function adminCookie(value, seconds) {
    return cookie + '=' + value + '; Path=/api; HttpOnly; SameSite=Strict; Max-Age=' +
      seconds + (secure ? '; Secure' : '');
  }

  async function admin(request, context, now) {
    if (request.method !== 'POST') return json({ error: '不支持此方法。' }, 405, { Allow: 'POST' });
    const body = await readBody(request);
    if (body.action === 'logout') return json({ admin: false }, 200, bearer ? {} : { 'Set-Cookie': adminCookie('', 0) });
    if (!expectedPassword) throw new HttpError(503, '管理员密码尚未配置。');
    if (body.action !== 'login' || typeof body.password !== 'string' || body.password.length > 128) {
      throw new HttpError(400, '请输入管理员密码。');
    }

    const ownerKey = request.headers.get('x-owner-key') || '';
    if (bearer && !OWNER_PATTERN.test(ownerKey)) throw new HttpError(400, '浏览器标记凭证不可用。');
    const bucket = Math.floor(now / LOGIN_WINDOW);
    const attemptKey = await sign('login:' + (context.ip || 'unknown'));
    if (!await store.recordAttempt(attemptKey, bucket)) {
      throw new HttpError(429, '尝试次数过多，请稍后再试。');
    }
    if (!await verify(await expectedPassword, 'password:' + body.password)) throw new HttpError(401, '管理员密码不正确。');
    const value = (now + SESSION_SECONDS * 1000) + '.' + crypto.randomUUID();
    const token = value + '.' + await sign(sessionMessage(value, bearer ? await digest(ownerKey) : null));
    if (bearer) return json({ admin: true, token });
    return json({ admin: true }, 200, { 'Set-Cookie': adminCookie(token, SESSION_SECONDS) });
  }

  async function markers(request, now) {
    const ownerKey = request.headers.get('x-owner-key') || '';
    const ownerHash = OWNER_PATTERN.test(ownerKey) ? await digest(ownerKey) : null;
    const administrator = await isAdmin(request, now, ownerHash);
    const timestamp = new Date(now).toISOString();
    const url = new URL(request.url);

    if (request.method === 'GET') {
      const all = url.searchParams.get('admin') === '1';
      const after = url.searchParams.get('after') || '';
      if (all && !administrator) throw new HttpError(401, '请重新登录管理员模式。');
      if (after && !ID_PATTERN.test(after)) throw new HttpError(400, '分页参数错误。');
      const records = await store.list({ all, ownerHash, timestamp, after, limit: PAGE_SIZE + 1 });
      const page = records.slice(0, PAGE_SIZE);
      return json({
        markers: page.map((record) => publicRecord(record, ownerHash)),
        next: records.length > PAGE_SIZE ? page.at(-1).id : null,
        admin: administrator
      });
    }

    if (!['POST', 'PATCH', 'DELETE'].includes(request.method)) {
      return json({ error: '不支持此方法。' }, 405, { Allow: 'GET, POST, PATCH, DELETE' });
    }
    const body = await readBody(request);
    if (request.method === 'POST') {
      if (!ownerHash) throw new HttpError(400, '浏览器标记凭证不可用。');
      const fields = markerFields(body, now);
      const record = await store.insert({
        id: crypto.randomUUID(),
        owner_hash: ownerHash,
        created_at: timestamp,
        expires_at: null,
        ...fields
      });
      return json({ marker: publicRecord(record, ownerHash) }, 201);
    }

    if (typeof body.id !== 'string' || !ID_PATTERN.test(body.id)) {
      throw new HttpError(400, '标记编号有误。');
    }
    if (!administrator && !ownerHash) throw new HttpError(403, '当前浏览器没有管理权限。');
    const ownerFilter = administrator ? null : ownerHash;
    const record = request.method === 'PATCH'
      ? await store.update(body.id, ownerFilter, markerFields(body, now))
      : await store.remove(body.id, ownerFilter);
    if (!record) throw new HttpError(404, '标记已删除，或当前没有管理权限。');
    return request.method === 'PATCH' ? json({ marker: publicRecord(record, ownerHash) }) : json({ id: body.id });
  }

  return async function handleApi(request, context = {}) {
    try {
      const path = new URL(request.url).pathname;
      if (path === '/api/markers') return await markers(request, Date.now());
      if (path === '/api/admin') return await admin(request, context, Date.now());
      return json({ error: '接口不存在。' }, 404);
    } catch (error) {
      if (error instanceof HttpError) return json({ error: error.message }, error.status);
      console.error('[群友地图] 标记服务处理失败', error.message);
      return json({ error: '标记服务暂时不可用，请稍后重试。' }, 503);
    }
  };
}
