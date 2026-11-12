/* 一行多按钮拼版 · 云端方案库 API
 * Cloudflare Pages Functions + Workers KV（绑定名：RECORDS）
 *   GET    /api/records?space=xxx   读取方案记录
 *   PUT    /api/records?space=xxx   保存方案记录  body: {records:[...], secret?}
 *   DELETE /api/records?space=xxx   清空（若设过口令则需口令）
 *   OPTIONS                         CORS 预检（供 GitHub Pages 跨域调用）
 * 说明：space 是方案库 ID，请设成不易猜测的字符串；secret 首次写入时会记下哈希，
 *       之后所有写入必须带相同口令。GET 凭 space 读取，方便换设备载入。
 */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: Object.assign(
      { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
      CORS
    ),
  });
}

function safeSpace(s) {
  s = String(s || 'default').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 64);
  return s || 'default';
}

async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
}

function stamp() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

async function readMeta(env, sp) {
  try {
    const m = await env.RECORDS.get('meta:' + sp);
    return m ? JSON.parse(m) : {};
  } catch (e) { return {}; }
}

export function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function onRequestGet(context) {
  const sp = safeSpace(new URL(context.request.url).searchParams.get('space'));
  const raw = await context.env.RECORDS.get('data:' + sp);
  if (!raw) return json({ ok: true, space: sp, records: [], updatedAt: null });
  try {
    const o = JSON.parse(raw);
    return json({
      ok: true, space: sp,
      records: Array.isArray(o.records) ? o.records : [],
      updatedAt: o.updatedAt || null,
    });
  } catch (e) {
    return json({ ok: true, space: sp, records: [], updatedAt: null });
  }
}

export async function onRequestPut(context) {
  const env = context.env;
  const sp = safeSpace(new URL(context.request.url).searchParams.get('space'));
  let body;
  try { body = await context.request.json(); } catch (e) { return json({ error: '请求体不是合法 JSON' }, 400); }
  const records = body.records;
  if (!Array.isArray(records)) return json({ error: '缺少 records 数组' }, 400);
  if (records.length > 200) return json({ error: '一次最多保存 200 条记录' }, 400);

  const meta = await readMeta(env, sp);
  const secret = String(body.secret || '');
  if (meta.secretHash) {
    if (await sha256(secret) !== meta.secretHash) {
      return json({ error: '访问口令不正确（该方案库已设置口令）' }, 403);
    }
  } else if (secret) {
    meta.secretHash = await sha256(secret);
    await env.RECORDS.put('meta:' + sp, JSON.stringify(meta));
  }

  const updatedAt = stamp();
  const payload = JSON.stringify({ records: records, updatedAt: updatedAt });
  if (payload.length > 20 * 1024 * 1024) {
    return json({ error: '数据超过 20MB，请减少记录或压缩按钮图' }, 413);
  }
  await env.RECORDS.put('data:' + sp, payload);
  return json({ ok: true, space: sp, count: records.length, updatedAt: updatedAt });
}

export async function onRequestDelete(context) {
  const env = context.env;
  const sp = safeSpace(new URL(context.request.url).searchParams.get('space'));
  const meta = await readMeta(env, sp);
  if (meta.secretHash) {
    let body = {};
    try { body = await context.request.json(); } catch (e) {}
    if (await sha256(String(body.secret || '')) !== meta.secretHash) {
      return json({ error: '访问口令不正确' }, 403);
    }
  }
  await env.RECORDS.delete('data:' + sp);
  return json({ ok: true, space: sp, cleared: true });
}
