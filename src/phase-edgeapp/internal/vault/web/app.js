'use strict';

// 前端状态。注意：**主密钥不在此处也不在浏览器任何地方** ——
// 解密全部由服务端在会话内完成，前端只拿到单条明文结果。
const state = {
  initialized: false,
  username: '',
  unlocked: false,
  csrf: '',
  categoryID: 0,
  trash: false,
  page: 1,
  limit: 20,
  total: 0,
  categories: [],
  editingID: null,
};

const $ = (id) => document.getElementById(id);

// ---------- 通用请求 ----------

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (state.csrf) headers['X-CSRF-Token'] = state.csrf;

  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
  });

  let data = null;
  const text = await res.text();
  if (text) {
    try { data = JSON.parse(text); }
    catch { throw new Error('服务器返回了非 JSON 数据'); }
  }
  if (data && data.csrf) state.csrf = data.csrf;

  if (!res.ok) {
    const err = new Error((data && (data.error || data.message)) || `请求失败（HTTP ${res.status}）`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data || {};
}

function toast(msg, isError) {
  const el = $('toast');
  el.textContent = msg;
  el.className = 'toast' + (isError ? ' err' : '');
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 2600);
}

function showError(el, msg) {
  el.textContent = msg;
  el.hidden = false;
}

// 密码框小眼睛（事件委托，覆盖所有 .eye）
document.addEventListener('click', (e) => {
  const btn = e.target.closest('.eye');
  if (!btn) return;
  const input = $(btn.dataset.target);
  if (!input) return;
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  btn.textContent = show ? '🙈' : '👁';
  btn.setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
});

// ---------- 启动 ----------

async function boot() {
  try {
    const st = await api('GET', '/api/status');
    state.initialized = !!st.initialized;
    if (!state.initialized) {
      $('authTitle').textContent = '创建主账户';
      $('authSub').textContent = '首次使用，请设置登录凭据与主密钥密码';
      $('masterField').hidden = false;
      $('masterPassword').required = true;
      $('authSubmit').textContent = '创建主账户';
    } else {
      $('authTitle').textContent = '登录';
      $('authSub').textContent = '请输入您的凭据以继续';
      $('authSubmit').textContent = '登录';
    }
    $('authView').hidden = false;
    $('username').focus();
  } catch (err) {
    toast('无法连接本地服务：' + err.message, true);
  }
}

// ---------- 认证 ----------

$('authForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = $('authError');
  errEl.hidden = true;
  const btn = $('authSubmit');
  btn.disabled = true;

  const username = $('username').value.trim();
  const password = $('password').value;
  const masterPassword = $('masterPassword').value;

  try {
    if (!state.initialized) {
      if (password !== masterPassword && masterPassword.length < 8) {
        throw new Error('主密钥密码至少 8 位');
      }
      await api('POST', '/api/register', { username, password, master_password: masterPassword });
      state.unlocked = true;
      await enterMain(username);
    } else {
      const r = await api('POST', '/api/login', { username, password });
      state.unlocked = !!r.unlocked;
      await enterMain(r.username || username);
    }
  } catch (err) {
    showError(errEl, err.message);
  } finally {
    btn.disabled = false;
  }
});

async function enterMain(username) {
  state.username = username;
  $('authView').hidden = true;
  $('mainView').hidden = false;
  await refreshUnlockState();
  await loadCategories();
  await loadEntries();
}

async function refreshUnlockState() {
  try {
    const s = await api('GET', '/api/session');
    state.unlocked = !!s.unlocked;
  } catch { state.unlocked = false; }
  $('lockBanner').hidden = state.unlocked;
}

// ---------- 解锁 ----------

function askUnlock() {
  return new Promise((resolve) => {
    const dlg = $('unlockDialog');
    const errEl = $('unlockError');
    errEl.hidden = true;
    $('unlockPassword').value = '';
    dlg.showModal();
    $('unlockPassword').focus();

    const form = $('unlockForm');
    const onSubmit = async (ev) => {
      ev.preventDefault();
      const pw = $('unlockPassword').value;
      if (!pw) return;
      try {
        await api('POST', '/api/unlock', { password: pw });
        cleanup();
        state.unlocked = true;
        $('lockBanner').hidden = true;
        dlg.close();
        resolve(true);
      } catch (err) {
        showError(errEl, err.message);
      }
    };
    const onCancel = () => { cleanup(); dlg.close(); resolve(false); };
    const cleanup = () => {
      form.removeEventListener('submit', onSubmit);
      $('unlockCancel').removeEventListener('click', onCancel);
    };
    form.addEventListener('submit', onSubmit);
    $('unlockCancel').addEventListener('click', onCancel);
  });
}

async function withUnlock(fn) {
  if (!state.unlocked) {
    const ok = await askUnlock();
    if (!ok) return;
  }
  try {
    return await fn();
  } catch (err) {
    // 423 = 需要解锁（服务端判定主密钥失效或闲置超时）
    if (err.status === 423) {
      state.unlocked = false;
      $('lockBanner').hidden = false;
      const ok = await askUnlock();
      if (!ok) return;
      return await fn();
    }
    toast(err.message, true);
  }
}

$('btnUnlock').addEventListener('click', () => askUnlock());

$('btnLock').addEventListener('click', async () => {
  try {
    await api('POST', '/api/lock');
    state.unlocked = false;
    $('lockBanner').hidden = false;
    // 必须立刻抹掉表格里已解密的明文：否则锁定后明文仍留在 DOM 上，
    // 最长要等 revealInto 的 15 秒定时器才遮回去 —— 锁定就形同虚设。
    maskAllDecrypted();
    toast('已锁定');
  } catch (err) { toast(err.message, true); }
});

$('btnLogout').addEventListener('click', async () => {
  try { await api('POST', '/api/logout'); } catch { /* 忽略 */ }
  location.reload();
});

// 退出程序：桌面版专用，直接停掉本地服务
$('btnShutdown').addEventListener('click', async () => {
  if (!confirm('确定退出密码管理器？\n\n本地服务将停止，正在编辑的内容请先保存。')) return;
  try {
    await api('POST', '/api/shutdown');
  } catch { /* 服务可能已停，忽略 */ }
  // 退出提示用类而不是内联 style：CSP style-src 'self' 会拒绝内联样式
  document.body.innerHTML = '<div class="bye">程序已退出。<br>' +
    '可以关闭此页面，再次使用时重新运行本程序。</div>';
});

// ---------- 分类 ----------

async function loadCategories() {
  const r = await api('GET', '/api/categories');
  state.categories = r.categories || [];
  renderCategories();
  renderCategoryOptions();
}

function renderCategories() {
  const ul = $('categoryList');
  ul.innerHTML = '';

  const mk = (label, id, extra) => {
    const li = document.createElement('li');
    if (state.categoryID === id && state.trash === (id === -1)) li.classList.add('active');
    if (state.trash && id === -1) li.classList.add('active');

    const name = document.createElement('span');
    name.className = 'cname';
    name.textContent = label;
    li.appendChild(name);

    if (extra) {
      const del = document.createElement('button');
      del.className = 'cdel';
      del.textContent = '×';
      del.title = '删除分类';
      del.addEventListener('click', async (ev) => {
        ev.stopPropagation();
        await deleteCategory(id, label);
      });
      li.appendChild(del);
    }

    li.addEventListener('click', () => {
      state.trash = (id === -1);
      state.categoryID = id === -1 ? 0 : id;
      state.page = 1;
      renderCategories();
      loadEntries();
    });
    ul.appendChild(li);
  };

  mk('所有密码', 0, false);
  const roots = state.categories.filter((c) => !c.parent_id);
  for (const c of roots) {
    mk(`${c.icon === 'folder' ? '📁' : '🏷'} ${c.name}`, c.id, true);
    if (state.categoryID === c.id && !state.trash) {
      // 展开二级
      const kids = state.categories.filter((k) => k.parent_id === c.id);
      for (const k of kids) {
        const li = document.createElement('li');
        li.className = 'cat-child';
        li.textContent = `– ${k.name}`;
        li.addEventListener('click', (ev) => {
          ev.stopPropagation();
          state.trash = false;
          state.categoryID = k.id;
          state.page = 1;
          renderCategories();
          loadEntries();
        });
        $('categoryList').appendChild(li);
      }
    }
  }
  mk('🗑 回收站', -1, false);
}

function renderCategoryOptions() {
  const sel = $('eCategory');
  sel.innerHTML = '';
  const opt0 = document.createElement('option');
  opt0.value = '0';
  opt0.textContent = '未分类';
  sel.appendChild(opt0);
  for (const c of state.categories) {
    const o = document.createElement('option');
    o.value = String(c.id);
    o.textContent = c.parent_id ? `  – ${c.name}` : c.name;
    sel.appendChild(o);
  }
}

async function deleteCategory(id, name) {
  if (!confirm(`确定删除分类「${name}」？\n\n该分类下不能有未删除的记录。`)) return;
  try {
    await api('DELETE', `/api/categories/${id}`);
    toast('分类已删除');
    if (state.categoryID === id) { state.categoryID = 0; }
    await loadCategories();
    await loadEntries();
  } catch (err) { toast(err.message, true); }
}

$('btnAddCategory').addEventListener('click', () => {
  $('catName').value = '';
  $('catIcon').value = 'folder';
  $('catError').hidden = true;
  $('catDialog').showModal();
  $('catName').focus();
});
$('catCancel').addEventListener('click', () => $('catDialog').close());
$('catForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('POST', '/api/categories', {
      name: $('catName').value.trim(),
      parent_id: 0,
      icon: $('catIcon').value.trim() || 'folder',
    });
    $('catDialog').close();
    toast('分类已创建');
    await loadCategories();
  } catch (err) { showError($('catError'), err.message); }
});

// ---------- 记录列表 ----------

async function loadEntries() {
  const params = new URLSearchParams({
    page: String(state.page),
    limit: String(state.limit),
    category_id: String(state.categoryID),
    trash: state.trash ? '1' : '0',
  });
  const q = $('search').value.trim();
  if (q) params.set('search', q);

  try {
    const r = await api('GET', '/api/entries?' + params.toString());
    state.total = r.total || 0;
    $('listTitle').textContent = state.trash ? '回收站' : (state.categoryID ? '分类内密码' : '所有密码');
    $('listCount').textContent = String(state.total);
    renderRows(r.entries || []);
    renderPager();
  } catch (err) { toast(err.message, true); }
}

function renderRows(entries) {
  const tbody = $('entryRows');
  tbody.innerHTML = '';
  $('emptyState').hidden = entries.length > 0;

  const start = (state.page - 1) * state.limit;
  entries.forEach((e, i) => {
    const tr = document.createElement('tr');

    const tdIdx = document.createElement('td');
    tdIdx.className = 'mono';
    tdIdx.textContent = String(start + i + 1);
    tr.appendChild(tdIdx);

    const tdTitle = document.createElement('td');
    tdTitle.className = 'trunc';
    tdTitle.textContent = e.title;
    tdTitle.title = e.title;
    tr.appendChild(tdTitle);

    const tdUrl = document.createElement('td');
    tdUrl.className = 'trunc';
    if (e.url) {
      if (/^https?:\/\//i.test(e.url)) {
        const a = document.createElement('a');
        a.href = e.url;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.className = 'ext-link';
        a.textContent = e.url;
        tdUrl.appendChild(a);
      } else {
        tdUrl.textContent = e.url;
      }
      tdUrl.title = e.url;
    } else { tdUrl.textContent = '—'; }
    tr.appendChild(tdUrl);

    const tdUser = document.createElement('td');
    tdUser.className = 'trunc';
    tdUser.textContent = e.username || '—';
    if (e.username) tdUser.title = e.username;
    tr.appendChild(tdUser);

    // 密码列：默认掩码，点「查看」后由服务端解密返回
    const tdPwd = document.createElement('td');
    tdPwd.className = 'mono';
    tdPwd.textContent = e.password_hint;
    tdPwd.dataset.entryId = String(e.id);
    tr.appendChild(tdPwd);

    const tdTime = document.createElement('td');
    tdTime.className = 'mono';
    tdTime.textContent = fmtTime(e.updated_at);
    tr.appendChild(tdTime);

    const tdAct = document.createElement('td');
    const box = document.createElement('div');
    box.className = 'row-actions';

    if (state.trash) {
      box.appendChild(mkBtn('恢复', async () => {
        await api('POST', `/api/entries/${e.id}/restore`);
        toast('已恢复');
        loadEntries();
      }));
      box.appendChild(mkBtn('彻底删', async () => {
        if (!confirm(`永久删除「${e.title}」？此操作不可恢复。`)) return;
        await api('DELETE', `/api/entries/${e.id}?purge=1`);
        toast('已永久删除');
        loadEntries();
      }));
    } else {
      box.appendChild(mkBtn('查看', () => revealInto(tdPwd, e.id)));
      box.appendChild(mkBtn('复制', async () => {
        const pw = await reveal(e.id);
        if (pw == null) return;
        await copyText(pw);
        toast('密码已复制');
      }));
      box.appendChild(mkBtn('编辑', () => openEntryDialog(e)));
      box.appendChild(mkBtn('删除', async () => {
        if (!confirm(`将「${e.title}」移入回收站？`)) return;
        await api('DELETE', `/api/entries/${e.id}`);
        toast('已移入回收站');
        loadEntries();
      }));
    }
    tdAct.appendChild(box);
    tr.appendChild(tdAct);

    tbody.appendChild(tr);
  });
}

function fmtTime(s) {
  // 后端的时间戳有两种来源，语义不同，必须分开处理：
  //   1) Go 侧写入的 "2026-10-22 13:24:31"（nowStr，本地时间、无时区标记）
  //   2) SQLite DEFAULT CURRENT_TIMESTAMP 写入的 "2026-10-22 05:24:31"（UTC、无时区标记）
  // 两者都无法从字面区分是本地还是 UTC，因此不能靠「有没有 Z」来判断。
  //
  // 原实现把所有时间都当作 UTC（拼上 Z 再 new Date），在东八区会把
  // Go 侧写入的本地时间显示成早 8 小时的时间。
  //
  // 现改为：后端统一用 RFC3339（含时区偏移）输出，前端按字符串里的偏移量
  // 精确换算成浏览器本地时间；无偏移的旧数据按 UTC 兜底（与 SQLite 默认值一致）。
  if (!s) return '';
  const raw = String(s).trim();
  const m = raw.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/);
  if (!m) return raw.slice(0, 16);
  const [, y, mo, d, h, mi, sec, tz] = m;
  const p = (n) => String(n).padStart(2, '0');
  // 带偏移量（或 Z）→ 按真实时刻换算；无偏移 → 按 UTC 解释（SQLite 默认值语义）
  const hasTZ = !!tz;
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${sec || '00'}${hasTZ ? (tz === 'Z' ? 'Z' : tz) : 'Z'}`;
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return `${y}-${mo}-${d} ${h}:${mi}`;
  return `${dt.getFullYear()}-${p(dt.getMonth() + 1)}-${p(dt.getDate())} ` +
         `${p(dt.getHours())}:${p(dt.getMinutes())}`;
}

function mkBtn(label, handler) {
  const b = document.createElement('button');
  b.type = 'button';
  b.textContent = label;
  b.addEventListener('click', () => { Promise.resolve(handler()).catch((err) => toast(err.message, true)); });
  return b;
}

async function reveal(id) {
  let pw = null;
  await withUnlock(async () => {
    const r = await api('POST', `/api/entries/${id}/reveal`);
    pw = r.password;
  });
  return pw;
}

async function revealInto(cell, id) {
  const pw = await reveal(id);
  if (pw == null) return;
  cell.textContent = pw;
  clearTimeout(cell._hideT);
  cell._hideT = setTimeout(() => { cell.textContent = '••••••••'; }, 15000);
}

// maskAllDecrypted 把表格里所有已解密的密码格重新遮回圆点。
// 锁定 / 退出登录 / 闲置超时都必须调用，否则明文会残留在页面 DOM 里。
function maskAllDecrypted() {
  document.querySelectorAll('#entryRows td.mono[data-entry-id]').forEach((td) => {
    clearTimeout(td._hideT);
    td.textContent = '••••••••';
  });
}

async function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try { await navigator.clipboard.writeText(text); return; } catch { /* 回退 */ }
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.className = 'copy-shim';
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
}

function renderPager() {
  const pages = Math.max(1, Math.ceil(state.total / state.limit));
  if (state.page > pages) state.page = pages;
  $('pageInfo').textContent = `${state.page} / ${pages}`;
  $('prevPage').disabled = state.page <= 1;
  $('nextPage').disabled = state.page >= pages;
}

$('prevPage').addEventListener('click', () => {
  if (state.page > 1) { state.page--; loadEntries(); }
});
$('nextPage').addEventListener('click', () => {
  const pages = Math.max(1, Math.ceil(state.total / state.limit));
  if (state.page < pages) { state.page++; loadEntries(); }
});

let searchTimer = null;
$('search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { state.page = 1; loadEntries(); }, 300);
});

$('linkTrash').addEventListener('click', (e) => {
  e.preventDefault();
  state.trash = true;
  state.categoryID = 0;
  state.page = 1;
  renderCategories();
  loadEntries();
});

// ---------- 添加 / 编辑 ----------

function openEntryDialog(entry) {
  state.editingID = entry ? entry.id : null;
  $('entryDialogTitle').textContent = entry ? '编辑密码' : '添加密码';
  $('eTitle').value = entry ? entry.title : '';
  $('eUrl').value = entry ? entry.url : '';
  $('eUsername').value = entry ? entry.username : '';
  $('eNotes').value = entry ? entry.notes : '';
  $('ePassword').value = '';
  $('ePassword').type = 'password';
  $('pwdHint').textContent = entry ? '（留空表示不修改）' : '';
  $('entryError').hidden = true;
  renderCategoryOptions();
  $('eCategory').value = String(entry ? entry.category_id : state.categoryID || 0);
  $('entryDialog').showModal();
  $('eTitle').focus();
}

$('btnAddEntry').addEventListener('click', () => {
  withUnlock(() => openEntryDialog(null));
});
$('entryCancel').addEventListener('click', () => $('entryDialog').close());

$('entryForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = $('entryError');
  errEl.hidden = true;

  const payload = {
    title: $('eTitle').value.trim(),
    url: $('eUrl').value.trim(),
    username: $('eUsername').value.trim(),
    password: $('ePassword').value,
    notes: $('eNotes').value,
    category_id: parseInt($('eCategory').value, 10) || 0,
  };
  if (!payload.title) { showError(errEl, '标题不能为空'); return; }
  if (!state.editingID && !payload.password) { showError(errEl, '密码不能为空'); return; }

  try {
    await withUnlock(async () => {
      if (state.editingID) {
        await api('PUT', `/api/entries/${state.editingID}`, payload);
      } else {
        await api('POST', '/api/entries', payload);
      }
    });
    $('entryDialog').close();
    toast(state.editingID ? '已保存' : '已添加');
    await loadEntries();
  } catch (err) { showError(errEl, err.message); }
});

$('btnGen').addEventListener('click', async () => {
  try {
    const r = await api('POST', '/api/generator', {
      length: 20, upper: true, lower: true, digits: true, symbols: true, avoid_amb: true,
    });
    $('ePassword').value = r.password;
    $('ePassword').type = 'text';
    toast(`已生成（强度：${r.strength.level}）`);
  } catch (err) { toast(err.message, true); }
});

// ---------- 备份 ----------

$('btnBackup').addEventListener('click', async () => {
  try {
    const r = await api('POST', '/api/backups');
    toast(`备份完成：${r.filename}（${r.size_formatted}）`);
  } catch (err) { toast(err.message, true); }
});

// ---------- 启动 ----------
boot();
