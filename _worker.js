// _worker.js — Cloudflare Pages Advanced Mode
// Per-person passwords with a 3-login limit, managed from /admin.
// Storage: KV namespace bound as PWDB (create it in the dashboard first).
//   key "pw:<sha256(password)>" -> JSON {label, uses, maxUses, revoked, createdAt}
//   key "meta:migrated" -> "1" once the legacy FRIEND_PASSWORD has been imported.
// Admin password: env var ADMIN_PASSWORD (set in the dashboard, never in chat).
// Legacy: env var FRIEND_PASSWORD is imported once (label "朋友", uses 0) so the
// current friend keeps working; after that, manage passwords from /admin.
// Login cookie "h666" = sha256(password), 1 day. Each successful login consumes
// one use; an existing session keeps working until the cookie expires, but
// revoking a password blocks it immediately (checked on every request).

const MAX_USES = 3;
const COOKIE_DAYS = 1;

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (e) {
      return new Response('服务暂时不可用，请联系管理员。', {
        status: 500,
        headers: { 'content-type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }
  },
};

async function handle(request, env) {
  const url = new URL(request.url);

  if (url.pathname === '/login' && request.method === 'POST') {
    return handleLogin(request, env);
  }
  if (url.pathname === '/logout') {
    return new Response(null, {
      status: 302,
      headers: {
        Location: '/',
        'Set-Cookie': 'h666=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
      },
    });
  }
  if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
    return handleAdmin(request, env, url);
  }

  if (!env.PWDB) {
    return plain503('后台存储未配置，请联系管理员配置后再访问。');
  }
  await migrateLegacy(env);

  const h = cookieVal(request, 'h666');
  if (h) {
    const rec = await getRecord(env, h);
    if (rec && !rec.revoked) {
      return env.ASSETS.fetch(request);
    }
  }
  return new Response(loginPage(''), {
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

async function handleLogin(request, env) {
  if (!env.PWDB) return plain503('后台存储未配置，请联系管理员配置后再访问。');
  await migrateLegacy(env);
  let pw = '';
  try {
    const form = await request.formData();
    const v = form.get('password');
    if (typeof v === 'string') pw = v;
  } catch (_) {}
  if (!pw) return loginFail('密码不对，请重试。');
  const h = await sha256(pw);
  const rec = await getRecord(env, h);
  if (!rec) return loginFail('密码不对，请重试。');
  if (rec.revoked) return loginFail('该密码已被停用。');
  if ((rec.uses || 0) >= (rec.maxUses || MAX_USES)) return loginFail('该密码使用次数已用完（最多3次）。');
  rec.uses = (rec.uses || 0) + 1;
  await putRecord(env, h, rec);
  return new Response(null, {
    status: 302,
    headers: {
      Location: '/',
      'Set-Cookie': `h666=${h}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_DAYS * 24 * 3600}`,
    },
  });
}

function loginFail(msg) {
  return new Response(loginPage(msg), {
    status: 401,
    headers: { 'content-type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function plain503(msg) {
  return new Response(msg, {
    status: 503,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

/* ---------- KV records ---------- */
async function getRecord(env, hash) {
  const raw = await env.PWDB.get('pw:' + hash);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}
async function putRecord(env, hash, rec) {
  await env.PWDB.put('pw:' + hash, JSON.stringify(rec));
}
async function listRecords(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.PWDB.list({ prefix: 'pw:', cursor });
    for (const k of page.keys) {
      const raw = await env.PWDB.get(k.name);
      if (!raw) continue;
      try {
        const rec = JSON.parse(raw);
        out.push({
          id: k.name.slice(3),
          label: rec.label || '',
          password: rec.password || '',
          uses: rec.uses || 0,
          maxUses: rec.maxUses || MAX_USES,
          revoked: !!rec.revoked,
          createdAt: rec.createdAt || '',
        });
      } catch (_) {}
    }
    cursor = page.cursor;
  } while (cursor);
  out.sort(function (a, b) { return a.createdAt < b.createdAt ? -1 : 1; });
  return out;
}

/* Import the old single FRIEND_PASSWORD once, so the current friend keeps working. */
async function migrateLegacy(env) {
  if (!env.PWDB || !env.FRIEND_PASSWORD) return;
  const h = await sha256(env.FRIEND_PASSWORD);
  if (!(await env.PWDB.get('meta:migrated'))) {
    if (!(await env.PWDB.get('pw:' + h))) {
      await env.PWDB.put('pw:' + h, JSON.stringify({
        label: '朋友', password: env.FRIEND_PASSWORD, uses: 0, maxUses: MAX_USES, revoked: false,
        createdAt: new Date().toISOString(),
      }));
    }
    await env.PWDB.put('meta:migrated', '1');
  }
  // Backfill the plaintext password for the migrated record (records created
  // before plaintext storage don't have it); only when the hash still matches.
  const rec = await getRecord(env, h);
  if (rec && !rec.password) {
    rec.password = env.FRIEND_PASSWORD;
    await putRecord(env, h, rec);
  }
}

/* ---------- admin ---------- */
async function handleAdmin(request, env, url) {
  if (!env.ADMIN_PASSWORD) {
    return plain503('未设置管理密码，请联系管理员在后台设置 ADMIN_PASSWORD 后再访问。');
  }
  await migrateLegacy(env);
  if (url.pathname === '/admin/login' && request.method === 'POST') {
    let pw = '';
    try {
      const form = await request.formData();
      const v = form.get('password');
      if (typeof v === 'string') pw = v;
    } catch (_) {}
    if (pw && pw === env.ADMIN_PASSWORD) {
      const h = await sha256(pw);
      return new Response(null, {
        status: 302,
        headers: {
          Location: '/admin',
          'Set-Cookie': `h666admin=${h}; Path=/admin; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_DAYS * 24 * 3600}`,
        },
      });
    }
    return new Response(adminLoginPage('管理密码不对，请重试。'), {
      status: 401,
      headers: { 'content-type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }
  if (url.pathname === '/admin/logout') {
    return new Response(null, {
      status: 302,
      headers: {
        Location: '/admin',
        'Set-Cookie': 'h666admin=; Path=/admin; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
      },
    });
  }
  if (!(await isAdminAuthed(request, env))) {
    return new Response(adminLoginPage(''), {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }
  if ((url.pathname === '/admin' || url.pathname === '/admin/') && request.method === 'GET') {
    return new Response(adminPage(), {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }
  if (url.pathname === '/admin/api/list' && request.method === 'GET') {
    return json(await listRecords(env));
  }
  if (url.pathname === '/admin/api/add' && request.method === 'POST') {
    const body = await request.json().catch(function () { return null; });
    if (!body || typeof body.label !== 'string' || typeof body.password !== 'string' ||
        !body.label.trim() || !body.password) {
      return json({ ok: false, error: '请填写名称和密码。' }, 400);
    }
    if (body.password.length < 4) {
      return json({ ok: false, error: '密码至少 4 位。' }, 400);
    }
    const h = await sha256(body.password);
    // Check duplicates against the same list the admin page shows, not a raw
    // KV get: after a delete, KV list and KV get can disagree briefly (eventual
    // consistency), which used to show an empty list while add still said
    // "already exists". The list is what the user sees, so it decides.
    const existing = await listRecords(env);
    if (existing.some(function (r) { return r.id === h; })) {
      return json({ ok: false, error: '这个密码已经存在。' }, 400);
    }
    await env.PWDB.put('pw:' + h, JSON.stringify({
      label: body.label.trim(), password: body.password, uses: 0, maxUses: MAX_USES, revoked: false,
      createdAt: new Date().toISOString(),
    }));
    return json({ ok: true });
  }
  if ((url.pathname === '/admin/api/revoke' || url.pathname === '/admin/api/unrevoke') && request.method === 'POST') {
    const body = await request.json().catch(function () { return null; });
    const rec = body && typeof body.id === 'string' ? await getRecord(env, body.id) : null;
    if (!rec) return json({ ok: false, error: '找不到该密码。' }, 404);
    rec.revoked = url.pathname === '/admin/api/revoke';
    await putRecord(env, body.id, rec);
    return json({ ok: true });
  }
  if (url.pathname === '/admin/api/delete' && request.method === 'POST') {
    const body = await request.json().catch(function () { return null; });
    if (!body || typeof body.id !== 'string') return json({ ok: false, error: '缺少参数。' }, 400);
    await env.PWDB.delete('pw:' + body.id);
    return json({ ok: true });
  }
  if (url.pathname === '/admin/api/change' && request.method === 'POST') {
    const body = await request.json().catch(function () { return null; });
    if (!body || typeof body.id !== 'string' || typeof body.password !== 'string' || !body.password) {
      return json({ ok: false, error: '请填写新密码。' }, 400);
    }
    if (body.password.length < 4) {
      return json({ ok: false, error: '密码至少 4 位。' }, 400);
    }
    const oldRec = await getRecord(env, body.id);
    if (!oldRec) return json({ ok: false, error: '找不到该密码。' }, 404);
    const newH = await sha256(body.password);
    if (newH === body.id) return json({ ok: false, error: '新密码和旧密码相同。' }, 400);
    if (await env.PWDB.get('pw:' + newH)) {
      return json({ ok: false, error: '这个密码已经存在。' }, 400);
    }
    // Keep label, uses, maxUses, revoked and createdAt; move the record to the new key.
    oldRec.password = body.password;
    await env.PWDB.delete('pw:' + body.id);
    await env.PWDB.put('pw:' + newH, JSON.stringify(oldRec));
    return json({ ok: true });
  }
  if (url.pathname === '/admin/api/bulk' && request.method === 'POST') {
    const body = await request.json().catch(function () { return null; });
    if (!body || !Array.isArray(body.ids) || typeof body.revoked !== 'boolean') {
      return json({ ok: false, error: '参数不对。' }, 400);
    }
    let updated = 0;
    for (const id of body.ids) {
      if (typeof id !== 'string') continue;
      const rec = await getRecord(env, id);
      if (!rec) continue;
      rec.revoked = body.revoked;
      await putRecord(env, id, rec);
      updated++;
    }
    return json({ ok: true, updated });
  }
  if (url.pathname === '/admin/api/bulk-delete' && request.method === 'POST') {
    const body = await request.json().catch(function () { return null; });
    if (!body || !Array.isArray(body.ids)) {
      return json({ ok: false, error: '参数不对。' }, 400);
    }
    const results = [];
    for (const id of body.ids) {
      if (typeof id !== 'string') { results.push({ id: '', ok: false, error: '参数不对。' }); continue; }
      const rec = await getRecord(env, id);
      if (!rec) { results.push({ id, ok: false, error: '找不到该密码。' }); continue; }
      await env.PWDB.delete('pw:' + id);
      results.push({ id, ok: true });
    }
    const deleted = results.filter(function (r) { return r.ok; }).length;
    return json({ ok: true, deleted, results });
  }
  if (url.pathname === '/admin/api/bulk-change' && request.method === 'POST') {
    const body = await request.json().catch(function () { return null; });
    if (!body || !Array.isArray(body.changes)) {
      return json({ ok: false, error: '参数不对。' }, 400);
    }
    const results = [];
    for (const ch of body.changes) {
      if (!ch || typeof ch.id !== 'string' || typeof ch.password !== 'string' || !ch.password) {
        results.push({ id: (ch && ch.id) || '', ok: false, error: '请填写新密码。' });
        continue;
      }
      if (ch.password.length < 4) {
        results.push({ id: ch.id, ok: false, error: '密码至少 4 位。' });
        continue;
      }
      const oldRec = await getRecord(env, ch.id);
      if (!oldRec) { results.push({ id: ch.id, ok: false, error: '找不到该密码。' }); continue; }
      const newH = await sha256(ch.password);
      if (newH === ch.id) { results.push({ id: ch.id, ok: false, error: '新密码和旧密码相同。' }); continue; }
      if (await env.PWDB.get('pw:' + newH)) { results.push({ id: ch.id, ok: false, error: '这个密码已经存在。' }); continue; }
      // Keep label, uses, maxUses, revoked and createdAt; move the record to the new key.
      oldRec.password = ch.password;
      await env.PWDB.delete('pw:' + ch.id);
      await env.PWDB.put('pw:' + newH, JSON.stringify(oldRec));
      results.push({ id: ch.id, ok: true });
    }
    const updated = results.filter(function (r) { return r.ok; }).length;
    return json({ ok: true, updated, results });
  }
  if (url.pathname === '/admin/api/bulk-reset' && request.method === 'POST') {
    const body = await request.json().catch(function () { return null; });
    if (!body || !Array.isArray(body.ids)) {
      return json({ ok: false, error: '参数不对。' }, 400);
    }
    const results = [];
    for (const id of body.ids) {
      if (typeof id !== 'string') { results.push({ id: '', ok: false, error: '参数不对。' }); continue; }
      const rec = await getRecord(env, id);
      if (!rec) { results.push({ id, ok: false, error: '找不到该密码。' }); continue; }
      // Reset activation count to 0; password, label, revoked and createdAt stay as-is.
      rec.uses = 0;
      await putRecord(env, id, rec);
      results.push({ id, ok: true });
    }
    const updated = results.filter(function (r) { return r.ok; }).length;
    return json({ ok: true, updated, results });
  }
  return new Response('Not found', { status: 404 });
}

async function isAdminAuthed(request, env) {
  const v = cookieVal(request, 'h666admin');
  if (!v) return false;
  const expected = await sha256(env.ADMIN_PASSWORD);
  return safeEqual(v, expected);
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'content-type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function cookieVal(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : '';
}

async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function loginPage(msg) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>海南666航线查询 · 登录</title><style>body{font-family:system-ui,-apple-system,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;background:#f6f6f4;margin:0}form{background:#fff;padding:28px 32px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);width:min(92vw,340px)}h1{font-size:18px;margin:0 0 6px}p{color:#666;font-size:14px;margin:0 0 16px}input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:16px;border:1px solid #ccc;border-radius:8px;margin-bottom:12px}button{width:100%;padding:11px;font-size:16px;border:0;border-radius:8px;background:#d7000f;color:#fff;cursor:pointer}.err{color:#d7000f;font-size:14px;min-height:20px;margin-bottom:8px}@media (max-width:480px){form{padding:22px 20px}h1{font-size:17px}}</style></head><body><form method="post" action="/login"><h1>海南666航线查询</h1><p>请输入访问密码</p><div class="err">${msg}</div><input type="password" name="password" placeholder="访问密码" autocomplete="current-password" required autofocus><label style="display:flex;align-items:center;gap:6px;font-size:14px;color:#666;margin:0 0 12px"><input type="checkbox" id="showPw" style="width:auto;margin:0"> 显示密码</label><button type="submit">进入</button></form><script>document.getElementById("showPw").addEventListener("change", function(e){ var i = document.querySelector('input[name="password"]'); i.type = e.target.checked ? "text" : "password"; });</script></body></html>`;
}

function adminLoginPage(msg) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>密码管理 · 登录</title><style>body{font-family:system-ui,-apple-system,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;background:#f6f6f4;margin:0}form{background:#fff;padding:28px 32px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);width:min(92vw,340px)}h1{font-size:18px;margin:0 0 6px}p{color:#666;font-size:14px;margin:0 0 16px}input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:16px;border:1px solid #ccc;border-radius:8px;margin-bottom:12px}button{width:100%;padding:11px;font-size:16px;border:0;border-radius:8px;background:#d7000f;color:#fff;cursor:pointer}.err{color:#d7000f;font-size:14px;min-height:20px;margin-bottom:8px}@media (max-width:480px){form{padding:22px 20px}h1{font-size:17px}}</style></head><body><form method="post" action="/admin/login"><h1>密码管理</h1><p>请输入管理密码</p><div class="err">${msg}</div><input type="password" name="password" placeholder="管理密码" autocomplete="current-password" required autofocus><label style="display:flex;align-items:center;gap:6px;font-size:14px;color:#666;margin:0 0 12px"><input type="checkbox" id="showPw" style="width:auto;margin:0"> 显示密码</label><button type="submit">进入管理</button></form><script>document.getElementById("showPw").addEventListener("change", function(e){ var i = document.querySelector('input[name="password"]'); i.type = e.target.checked ? "text" : "password"; });</script></body></html>`;
}

function adminPage() {
  return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>密码管理</title><style>'
    + 'body{font-family:system-ui,-apple-system,sans-serif;background:#f6f6f4;margin:0;padding:24px;color:#222}'
    + '.wrap{max-width:760px;margin:0 auto;background:#fff;padding:24px 28px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08)}'
    + 'h1{font-size:20px;margin:0 0 6px}p{color:#666;font-size:14px;line-height:1.6}'
    + 'form{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}input{padding:10px 12px;font-size:15px;border:1px solid #ccc;border-radius:8px;flex:1;min-width:140px}'
    + 'button{padding:10px 16px;font-size:15px;border:0;border-radius:8px;background:#d7000f;color:#fff;cursor:pointer}button.ghost{background:#eee;color:#333}'
    + 'table{width:100%;border-collapse:collapse;margin-top:8px;font-size:15px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #eee}th{color:#888;font-weight:600}'
    + '#msg{color:#d7000f;font-size:14px;min-height:20px}a{color:#d7000f}'
    + 'input[type="checkbox"]{flex:none;min-width:0;width:auto;padding:0;border:0}'
    + 'form label{font-size:14px;color:#666;display:flex;align-items:center;gap:6px;white-space:nowrap}'
    + '.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}'
    + '.row label{font-size:14px;color:#666;display:flex;align-items:center;gap:6px;white-space:nowrap}'
    + '#editBox,#bulkEditBox{background:#fff7f7;border:1px solid #f0c0c0;border-radius:8px;padding:12px;margin:12px 0}'
    + '#bulkEditList .row{margin:8px 0}'
    + '#bulkEditList .row span{min-width:80px;font-weight:600}'
    + '.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}'
    + 'table{min-width:720px}'
    + '@media (max-width:640px){body{padding:12px}.wrap{padding:16px}table{font-size:14px;min-width:640px}th,td{padding:8px 6px}button{padding:9px 12px;font-size:14px}form input{min-width:0}h1{font-size:18px}}'
    + '</style></head><body><div class="wrap">'
    + '<h1>密码管理</h1>'
    + '<p>每个密码最多登录 3 次，第 4 次输密码就进不去了。登录后 1 天内不用重复输密码。点“停用”后该密码立刻不能再用（已登录的设备也会被踢出）。密码直接显示在列表里，只有登录了管理页才能看到。改密码会保留已用次数，旧密码立即失效；忘了某个密码就删掉重加一个。点“批量重置”会把选中账号的已用次数清零（恢复到 0 / 3），密码本身不变。</p>'
    + '<form id="addForm"><input name="label" placeholder="名称（例如：朋友A）" required><input id="addPw" name="password" type="password" placeholder="密码（至少 4 位）" required autocomplete="new-password"><label><input type="checkbox" id="showAddPw"> 显示密码</label><button type="submit">添加密码</button></form>'
    + '<div id="editBox" style="display:none"><b>正在修改：<span id="editLabel"></span></b><div class="row"><input id="editPw" type="password" placeholder="新密码（至少 4 位）" autocomplete="new-password"><label><input type="checkbox" id="showEditPw"> 显示密码</label><button id="saveEdit" type="button">保存新密码</button><button id="cancelEdit" type="button" class="ghost">取消</button></div></div>'
    + '<div id="bulkEditBox" style="display:none"><b>批量改密码</b><div id="bulkEditList"></div><div class="row"><label><input type="checkbox" id="showBulkPw"> 全部显示密码</label><button id="saveBulkEdit" type="button">保存全部</button><button id="cancelBulkEdit" type="button" class="ghost">取消</button></div></div>'
    + '<div id="msg"></div>'
    + '<div class="row"><button id="bulkRevoke" type="button">批量停用</button><button id="bulkUnrevoke" type="button" class="ghost">批量启用</button><button id="bulkChange" type="button" class="ghost">批量改密码</button><button id="bulkReset" type="button" class="ghost">批量重置</button><button id="bulkDelete" type="button" class="ghost">批量删除</button><span id="selCount"></span></div>'
    + '<div class="table-wrap"><table><thead><tr><th><input type="checkbox" id="selAll"></th><th>名称</th><th>密码</th><th>已用 / 最多</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead><tbody id="rows"></tbody></table></div>'
    + '<p><a href="/admin/logout">退出管理</a> · <a href="/">回航线页</a></p>'
    + '</div><script>'
    + 'var rows = document.getElementById("rows");'
    + 'var msg = document.getElementById("msg");'
    + 'var editingId = null;'
    + 'var currentList = [];'
    + 'function esc(s){ return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }'
    + 'function load(){'
    + '  fetch("/admin/api/list").then(function(r){ return r.json(); }).then(function(list){'
    + '    currentList = list;'
    + '    if(!list.length){ rows.innerHTML = "<tr><td colspan=\\"7\\">还没有密码，先在上面添加一个。</td></tr>"; return; }'
    + '    rows.innerHTML = list.map(function(it){'
    + '      var status = it.revoked ? "已停用" : (it.uses >= it.maxUses ? "已用完" : "正常");'
    + '      var btn = it.revoked'
    + '        ? "<button data-act=\\"unrevoke\\" data-id=\\"" + it.id + "\\">启用</button>"'
    + '        : "<button data-act=\\"revoke\\" data-id=\\"" + it.id + "\\">停用</button>";'
    + '      return "<tr><td><input type=\\"checkbox\\" class=\\"sel\\" data-id=\\"" + it.id + "\\"></td><td>" + esc(it.label) + "</td><td>" + (it.password ? esc(it.password) : "—") + "</td><td>" + it.uses + " / " + it.maxUses + "</td><td>" + status + "</td><td>" + esc((it.createdAt || "").slice(0, 10)) + "</td><td>" + btn + " <button data-act=\\"change\\" data-id=\\"" + it.id + "\\" data-label=\\"" + esc(it.label) + "\\">改密码</button> <button data-act=\\"delete\\" data-id=\\"" + it.id + "\\">删除</button></td></tr>";'
    + '    }).join("");'
    + '    updateSelCount();'
    + '  }).catch(function(){ msg.textContent = "加载失败，请刷新重试。"; });'
    + '}'
    + 'function selectedIds(){ return Array.prototype.slice.call(document.querySelectorAll(".sel:checked")).map(function(c){ return c.getAttribute("data-id"); }); }'
    + 'function updateSelCount(){ var n = selectedIds().length; document.getElementById("selCount").textContent = n ? "已选 " + n + " 个" : ""; var all = document.getElementById("selAll"); var boxes = document.querySelectorAll(".sel"); all.checked = boxes.length > 0 && n === boxes.length; }'
    + 'document.getElementById("selAll").addEventListener("change", function(e){ var boxes = document.querySelectorAll(".sel"); for (var i = 0; i < boxes.length; i++) boxes[i].checked = e.target.checked; updateSelCount(); });'
    + 'rows.addEventListener("change", function(e){ if (e.target.classList && e.target.classList.contains("sel")) updateSelCount(); });'
    + 'rows.addEventListener("click", function(e){'
    + '  var b = e.target.closest ? e.target.closest("button[data-act]") : null;'
    + '  if(!b) return;'
    + '  var act = b.getAttribute("data-act"), id = b.getAttribute("data-id");'
    + '  if(act === "change"){ startEdit(id, b.getAttribute("data-label")); return; }'
    + '  if(act === "delete" && !confirm("确定删除这个密码吗？删除后用它再也登不进来了。")) return;'
    + '  fetch("/admin/api/" + act, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({id: id})}).then(function(){ load(); });'
    + '});'
    + 'function startEdit(id, label){ editingId = id; document.getElementById("editLabel").textContent = label; document.getElementById("editPw").value = ""; document.getElementById("editBox").style.display = "block"; document.getElementById("editPw").focus(); }'
    + 'document.getElementById("cancelEdit").addEventListener("click", function(){ editingId = null; document.getElementById("editBox").style.display = "none"; });'
    + 'document.getElementById("saveEdit").addEventListener("click", function(){'
    + '  if(!editingId) return;'
    + '  var pw = document.getElementById("editPw").value;'
    + '  fetch("/admin/api/change", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({id: editingId, password: pw})}).then(function(r){ return r.json(); }).then(function(res){'
    + '    if(res.ok){ msg.textContent = "密码已修改，旧密码立即失效。"; editingId = null; document.getElementById("editBox").style.display = "none"; load(); }'
    + '    else { msg.textContent = res.error || "修改失败。"; }'
    + '  });'
    + '});'
    + 'function bulkSet(revoked){'
    + '  var ids = selectedIds();'
    + '  if(!ids.length){ msg.textContent = "请先勾选要操作的密码。"; return; }'
    + '  fetch("/admin/api/bulk", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ids: ids, revoked: revoked})}).then(function(r){ return r.json(); }).then(function(res){'
    + '    if(res.ok){ msg.textContent = "已更新 " + res.updated + " 个密码。"; load(); }'
    + '    else { msg.textContent = res.error || "操作失败。"; }'
    + '  });'
    + '}'
    + 'document.getElementById("bulkRevoke").addEventListener("click", function(){ bulkSet(true); });'
    + 'document.getElementById("bulkUnrevoke").addEventListener("click", function(){ bulkSet(false); });'
    + 'document.getElementById("bulkDelete").addEventListener("click", function(){'
    + '  var ids = selectedIds();'
    + '  if(!ids.length){ msg.textContent = "请先勾选要删除的密码。"; return; }'
    + '  if(!confirm("确定删除选中的 " + ids.length + " 个密码吗？删除后用它们再也登不进来了，这个操作不能撤销。")) return;'
    + '  fetch("/admin/api/bulk-delete", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ids: ids})}).then(function(r){ return r.json(); }).then(function(res){'
    + '    if(res.ok){'
    + '      var failed = (res.results || []).filter(function(x){ return !x.ok; });'
    + '      if(failed.length){ msg.textContent = "已删除 " + res.deleted + " 个，有 " + failed.length + " 个失败：" + failed.map(function(x){ return x.error || "失败"; }).join("；"); }'
    + '      else { msg.textContent = "已删除 " + res.deleted + " 个密码。"; }'
    + '      load();'
    + '    }'
    + '    else { msg.textContent = res.error || "操作失败。"; }'
    + '  });'
    + '});'
    + 'document.getElementById("bulkReset").addEventListener("click", function(){'
    + '  var ids = selectedIds();'
    + '  if(!ids.length){ msg.textContent = "请先勾选要重置的密码。"; return; }'
    + '  if(!confirm("确定把选中的 " + ids.length + " 个密码的已用次数清零吗？清零后它们又可以登录 3 次，密码本身不变。")) return;'
    + '  fetch("/admin/api/bulk-reset", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ids: ids})}).then(function(r){ return r.json(); }).then(function(res){'
    + '    if(res.ok){'
    + '      var failed = (res.results || []).filter(function(x){ return !x.ok; });'
    + '      if(failed.length){ msg.textContent = "已重置 " + res.updated + " 个，有 " + failed.length + " 个失败：" + failed.map(function(x){ return x.error || "失败"; }).join("；"); }'
    + '      else { msg.textContent = "已重置 " + res.updated + " 个密码的已用次数（恢复到 0 / 3）。"; }'
    + '      load();'
    + '    }'
    + '    else { msg.textContent = res.error || "操作失败。"; }'
    + '  });'
    + '});'
    + 'document.getElementById("bulkChange").addEventListener("click", function(){'
    + '  var ids = selectedIds();'
    + '  if(!ids.length){ msg.textContent = "请先勾选要改密码的账号。"; return; }'
    + '  var box = document.getElementById("bulkEditList");'
    + '  box.innerHTML = ids.map(function(id){'
    + '    var label = id;'
    + '    for (var i = 0; i < currentList.length; i++) { if (currentList[i].id === id) { label = currentList[i].label; break; } }'
    + '    return "<div class=\\"row\\"><span>" + esc(label) + "</span><input type=\\"password\\" class=\\"bulkPw\\" data-id=\\"" + id + "\\" placeholder=\\"新密码（至少 4 位）\\" autocomplete=\\"new-password\\"></div>";'
    + '  }).join("");'
    + '  document.getElementById("bulkEditBox").style.display = "block";'
    + '  var first = box.querySelector("input");'
    + '  if (first) first.focus();'
    + '});'
    + 'document.getElementById("cancelBulkEdit").addEventListener("click", function(){ document.getElementById("bulkEditBox").style.display = "none"; });'
    + 'document.getElementById("showBulkPw").addEventListener("change", function(e){'
    + '  var inputs = document.querySelectorAll("#bulkEditList input.bulkPw");'
    + '  for (var i = 0; i < inputs.length; i++) inputs[i].type = e.target.checked ? "text" : "password";'
    + '});'
    + 'document.getElementById("saveBulkEdit").addEventListener("click", function(){'
    + '  var inputs = document.querySelectorAll("#bulkEditList input.bulkPw");'
    + '  var changes = [];'
    + '  var seen = {};'
    + '  for (var i = 0; i < inputs.length; i++) {'
    + '    var pw = inputs[i].value;'
    + '    var id = inputs[i].getAttribute("data-id");'
    + '    if (!pw) { msg.textContent = "请给每个选中的账号都填一个新密码。"; return; }'
    + '    if (seen[pw]) { msg.textContent = "有两个账号填了相同的新密码，请改成不一样的。"; return; }'
    + '    seen[pw] = true;'
    + '    changes.push({ id: id, password: pw });'
    + '  }'
    + '  if (!changes.length) { msg.textContent = "请先勾选要改密码的账号。"; return; }'
    + '  fetch("/admin/api/bulk-change", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({changes: changes})}).then(function(r){ return r.json(); }).then(function(res){'
    + '    if (res.ok) {'
    + '      var failed = res.results.filter(function(x){ return !x.ok; });'
    + '      if (failed.length) { msg.textContent = "已更新 " + res.updated + " 个，有 " + failed.length + " 个失败：" + failed.map(function(x){ return x.error || "失败"; }).join("；"); }'
    + '      else { msg.textContent = "已更新 " + res.updated + " 个密码。"; }'
    + '      document.getElementById("bulkEditBox").style.display = "none";'
    + '      load();'
    + '    } else { msg.textContent = res.error || "操作失败。"; }'
    + '  });'
    + '});'
    + 'document.getElementById("showAddPw").addEventListener("change", function(e){ document.getElementById("addPw").type = e.target.checked ? "text" : "password"; });'
    + 'document.getElementById("showEditPw").addEventListener("change", function(e){ document.getElementById("editPw").type = e.target.checked ? "text" : "password"; });'
    + 'document.getElementById("addForm").addEventListener("submit", function(e){'
    + '  e.preventDefault();'
    + '  var f = e.target;'
    + '  var label = f.elements.label.value.trim();'
    + '  var password = f.elements.password.value;'
    + '  fetch("/admin/api/add", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({label: label, password: password})}).then(function(r){ return r.json(); }).then(function(res){'
    + '    if(res.ok){ msg.textContent = "已添加。"; f.reset(); load(); }'
    + '    else { msg.textContent = res.error || "添加失败。"; load(); }'
    + '  });'
    + '});'
    + 'load();'
    + '</script></body></html>';
}
