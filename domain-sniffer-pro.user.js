// ==UserScript==
// @name         Domain Sniffer Pro — сбор доменов + детектор блокировок (РФ)
// @namespace    http://tampermonkey.net/
// @version      3.5
// @description  Сбор доменов/поддоменов + блокировки (реестр, DPI, IP, ~16-20КБ) + маршрут (прокси/напрямую, Clash API) + региональная проверка по РФ через cheburcheck.ru (SNI/ТСПУ/DNS/CDN-блок по регионам)
// @match        *://*/*
// @run-at       document-start
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        unsafeWindow
// @connect      cheburcheck.ru
// @connect      *
// @homepageURL  https://github.com/Kakuzaaa/sniff
// @supportURL   https://github.com/Kakuzaaa/sniff/issues
// @updateURL    https://raw.githubusercontent.com/Kakuzaaa/sniff/main/domain-sniffer-pro.user.js
// @downloadURL  https://raw.githubusercontent.com/Kakuzaaa/sniff/main/domain-sniffer-pro.user.js
// ==/UserScript==

/*
  ═══════════════════════════════════════════════════════════════════════
  СБОР ДОМЕНОВ (с 0-й мс):
   • перехват fetch / XHR / WebSocket / EventSource(SSE) / sendBeacon /
     RTCPeerConnection (STUN/TURN) — через unsafeWindow, чтобы видеть
     запросы самого сайта;
   • PerformanceObserver (все реальные загрузки, включая неудачные);
   • скан DOM: src/href/data-src/poster/action/formaction/srcset/style,
     содержимое <style> и доступных CSS-листов (url()/@import);
   • в iframe скрипт работает без UI и пересылает найденные домены
     в верхний фрейм через postMessage — так ловятся домены встроенных
     сторонних виджетов (плееры, капча и т.п.).

  ПРОВЕРКА БЛОКИРОВОК (кнопка «🚫 Чек», нужен Tampermonkey/Violentmonkey):
   1. Реестр: списки-зеркала antifilter.download (domains.lst + subnet.lst
      + ip.lst), кэш на 12 ч в GM-хранилище. Проверяем и домен, и его IP
      (IP резолвим через DNS-over-HTTPS — так видны блоки хостингов
      типа Hetzner/Cloudflare по подсетям).
   2. Живые пробы GM_xmlhttpRequest к самому домену (без cookie):
      • сброс соединения сразу        → ⛔ похоже на DPI (по SNI/домену);
      • HTTPS сброс, а HTTP отвечает  → ⛔ почти наверняка DPI по SNI;
      • нет ответа (таймаут)          → 🕳 полная блокировка по IP;
      • обрыв после ~12–64КБ          → ✂️ «частичная» блокировка 16–20КБ;
      • устойчивая скорость < 16КБ/с  → 🐢 замедление (троттлинг). Меряем
        ПОСЛЕ первых 16КБ (TTFB/«сервер думает» не учитывается) и только
        если получено ≥48КБ; таймаут с данными = «очень медленно» или
        «встало после NКБ», а НЕ «полная блокировка»;
      • успешный ответ                → ✅ доступен.
   Способ блокировки в реестре не публикуется, поэтому тип определяется
   по фактическому поведению сети У ВАШЕГО провайдера — это эвристика.

  МАРШРУТ КАЖДОГО ДОМЕНА (через прокси или напрямую):
   • Если на роутере (Podkop / Forkop / NetShift) или локально на ПК
     (sing-box / clash / v2rayN с clash-api) включён Clash API
     (external_controller, обычно порт 9090 — в Podkop это «YACD /
     дашборд»), скрипт читает /connections и показывает для каждого
     домена: 🚀 через какую цепочку прокси он идёт или ⬇ напрямую и
     по какому правилу. Проба из «Чека» сама создаёт соединение,
     поэтому маршрут определяется и для доменов, которые сайт не грузит.
   • Без Clash API — только косвенно: сравниваем IP, который видят
     зарубежный и RU-сервис (детект сплит-маршрутизации и VPN-выхода).
     Поточечный маршрут в этом случае узнать нельзя.
   • 🔴 «заблокирован и НЕ в прокси» — домен блокируется, но в
     прокси-лист роутера не попал: вот почему сайт не работает.
   • БЕЗ Clash API — два косвенных признака (метки 🚀? / ⬇?):
     1) реестр + проба: домен в реестре, но доступен → скорее идёт
        через прокси; в реестре и блокируется → скорее напрямую;
     2) RU-хостинг + задержка: <60мс — как локально (напрямую),
        >90мс — как из-за границы (через зарубежный выход VPN).
        Гео IP берётся у ip-api.com, задержка — из живой пробы.
     CDN и европейские цели так не различить (RTT совпадает).

  РЕГИОНАЛЬНАЯ ПРОВЕРКА (кнопка «🌍 Рег.» или 🌍 на строке домена):
   • открытый API cheburcheck.ru: статика /api/v1/check (реестр +
     списки CDN-хостеров: Hetzner, Cloudflare и др.) и живой SSE-скан
     /api/v1/probe — десятки сканеров в регионах РФ присылают вердикты:
     SNI-блок (DPI), ТСПУ-блок (IP), подмена DNS, CDN-блок (16-20КБ),
     в белом списке, доступен.
   • даёт картину ПО ВСЕМ операторам, а не только у вашего провайдера:
     «SNI-блок 28/35 рег.» — домен режут почти везде.
   • кэш 6 ч на домен; сканы идут по одному — сервис бесплатный,
     комьюнити-сканеры не нагружаем параллельными запросами.
  ═══════════════════════════════════════════════════════════════════════
*/

(() => {
  'use strict';

  // ────────────────────────────── КОНФИГ ──────────────────────────────
  const CFG = {
    lists: {
      domains: 'https://antifilter.download/list/domains.lst', // домены из реестра
      subnet:  'https://antifilter.download/list/subnet.lst',  // подсети (CIDR)
      ip:      'https://antifilter.download/list/ip.lst',      // одиночные IP
    },
    listTtlMs: 12 * 60 * 60 * 1000, // обновление списков раз в 12 ч
    doh: ['https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query'],
    probeTimeoutMs: 8000,
    probeConcurrency: 6,
    probeMaxBody: 256 * 1024,   // получили столько байт → домен живой, пробу прерываем
    partialMin: 12 * 1024,      // «частичная» блокировка: обрыв тела в диапазоне…
    partialMax: 64 * 1024,      // …12–64КБ (типичный случай — 16–20КБ)
    slowBytesPerSec: 16 * 1024, // устойчивая скорость ниже → 🐢 замедление
    slowSkipBytes: 16 * 1024,   // первые 16КБ не меряем (TTFB, «сервер думает»)
    slowMinBytes: 48 * 1024,    // меньше этого объёма скорость не измеряем вообще
    stallSilentMs: 2500,        // данные пришли и замолчали надолго → «встало», не «медленно»
    route: {
      // Clash API (sing-box): локальный ПК + типичные адреса OpenWrt-роутеров
      candidates: ['http://127.0.0.1:9090', 'http://192.168.1.1:9090', 'http://192.168.8.1:9090', 'http://192.168.31.1:9090', 'http://192.168.0.1:9090'],
      pollMs: 4000,        // период опроса /connections
      probeDelayMs: 1200,  // пауза после пробы, чтобы соединение появилось в /connections
    },
    echo: {
      foreign: 'https://www.cloudflare.com/cdn-cgi/trace', // какой IP/страну видит зарубежный сервис
      ru: 'https://api.sypexgeo.net/json/',                // какой IP видит RU-сервис (детект сплита)
    },
    geoBatchUrl: 'http://ip-api.com/batch', // гео IP-адресов (бесплатно, без ключа, батч до 100)
    ruDirectMs: 60, // RU-цель отвечает быстрее → похоже напрямую
    ruFarMs: 90,    // RU-цель отвечает дольше → похоже через зарубежный выход
    chb: {
      base: 'https://cheburcheck.ru', // открытый API региональных проверок
      probeTtlMs: 6 * 60 * 60 * 1000, // кэш живого скана на домен
      probeTimeoutMs: 180000,         // SSE-скан идёт ~60-90с
    },
  };

  const SKEY = '__dsnf3_set';   // собранные домены + статусы (sessionStorage)
  const SOPEN = '__dsnf3_open'; // открыта ли панель

  // ────────────────────────────── ОКРУЖЕНИЕ ──────────────────────────────
  const isTop = (() => { try { return window.top === window.self; } catch { return false; } })();
  const uw = (() => { try { return typeof unsafeWindow !== 'undefined' ? unsafeWindow : window; } catch { return window; } })();
  const toPage = (fn) => { try { if (typeof exportFunction === 'function') return exportFunction(fn, uw); } catch {} return fn; };
  const hasGM = typeof GM_xmlhttpRequest === 'function';
  const gmGet = (k, d) => { try { return typeof GM_getValue === 'function' ? GM_getValue(k, d) : d; } catch { return d; } };
  const gmSet = (k, v) => { try { if (typeof GM_setValue === 'function') GM_setValue(k, v); } catch {} };

  const gmReq = (opt) => new Promise((res) => {
    try {
      GM_xmlhttpRequest(Object.assign(
        { timeout: 30000, onerror: (e) => res({ ok: false, err: String((e && e.error) || e || '') }), ontimeout: () => res({ ok: false, err: 'timeout' }), onload: (r) => res({ ok: true, r }) },
        opt
      ));
    } catch (e) { res({ ok: false, err: String(e) }); }
  });
  const gmText = async (url, timeout, headers) => {
    const a = await gmReq({ url, method: 'GET', timeout: timeout || 30000, headers: headers || {} });
    if (!a.ok) throw new Error(a.err || 'request failed');
    return a.r.responseText || '';
  };

  // ────────────────────────────── СОСТОЯНИЕ ──────────────────────────────
  const domains = new Map(); // host → true
  const info = new Map();    // host → { status:{icons,tag,blocked}, busy }
  let rootOnly = false;
  let statusMsg = '';

  // отложенный рендер (без UI во фреймах — просто no-op)
  let renderFn = null, renderTimer = 0;
  const renderSoon = () => { if (!renderFn || renderTimer || !isTop) return; renderTimer = setTimeout(() => { renderTimer = 0; try { renderFn(); } catch {} }, 200); };

  // ────────────────────────────── ДОМЕНЫ ──────────────────────────────
  const PS2 = new Set(('co.uk,org.uk,ac.uk,gov.uk,me.uk,net.uk,sch.uk,com.ua,net.ua,org.ua,in.ua,edu.ua,gov.ua,kiev.ua,com.ru,net.ru,org.ru,pp.ru,com.br,net.br,org.br,com.au,net.au,org.au,edu.au,gov.au,co.nz,net.nz,org.nz,co.jp,ne.jp,or.jp,ac.jp,go.jp,co.kr,or.kr,re.kr,co.in,net.in,org.in,firm.in,gen.in,net.cn,org.cn,gov.cn,edu.cn,com.tw,org.tw,idv.tw,com.hk,org.hk,edu.hk,gov.hk,com.sg,net.sg,org.sg,com.my,net.my,org.my,co.id,or.id,web.id,co.th,or.th,in.th,com.ph,com.vn,com.ar,com.mx,org.mx,gob.mx,com.co,net.co,org.co,com.pe,com.ve,gob.ve,com.ec,com.do,com.gt,com.ni,com.pa,com.py,com.sv,com.uy,com.bo,com.pk,com.bd,com.tr,com.eg,com.sa,com.ng,com.qa,com.kw,com.om').split(','));

  const getRoot = (host) => {
    const p = host.split('.');
    if (p.length <= 2) return host;
    const two = p.slice(-2).join('.');
    if (PS2.has(two)) return p.slice(-3).join('.');
    return two;
  };

  const baseHref = () => { try { return document.baseURI || location.href; } catch { return location.href; } };

  // мост iframe → верхний фрейм
  let sendTimer = 0; const pendingSend = new Set();
  const flushSend = () => { if (!pendingSend.size) return; const hosts = [...pendingSend]; pendingSend.clear(); try { window.top.postMessage({ __dsnf3: hosts }, '*'); } catch {} };
  const scheduleSend = () => { if (sendTimer) return; sendTimer = setTimeout(() => { sendTimer = 0; flushSend(); }, 700); };

  const addHost = (rawHost) => {
    const host = String(rawHost || '').toLowerCase().trim().replace(/\.$/, '');
    if (!host || host === 'localhost') return false;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return false;          // IPv4 — не домен
    if (host.includes(':') || host.includes('[')) return false;      // IPv6
    if (!/^[a-z0-9._-]+$/.test(host)) return false;                  // посторонние символы
    if (!host.includes('.')) return false;                           // односоставные имена (интранет)
    if (domains.has(host)) return false;
    domains.set(host, true);
    if (!isTop) { pendingSend.add(host); scheduleSend(); }
    scheduleSave(); renderSoon();
    return true;
  };

  const addUrl = (raw) => {
    if (!raw || typeof raw !== 'string') return;
    const s = raw.trim();
    try {
      const u = new URL(s, baseHref());
      if (u.protocol === 'http:' || u.protocol === 'https:' || u.protocol === 'ws:' || u.protocol === 'wss:') { addHost(u.hostname); return; }
      // stun:/turn: пишутся без «//», URL их не парсит — вытаскиваем вручную
      if (/^(stun|stuns|turn|turns):/i.test(u.protocol)) {
        const m = /^[a-z]+:(?:\/\/)?([^/:?]+)/i.exec(s);
        if (m) addHost(m[1]);
      }
    } catch {}
  };
  if (isTop) { try { window.addEventListener('message', (e) => { const d = e && e.data; if (d && Array.isArray(d.__dsnf3)) d.__dsnf3.forEach(addHost); }); } catch {} }

  // ────────────────── ПЕРЕХВАТ ЗАПРОСОВ (в контексте страницы) ──────────────────
  const patchPage = () => {
    try { if (uw.__dsnf3__) return; uw.__dsnf3__ = true; } catch {}
    try {
      const of_ = uw.fetch;
      if (of_) uw.fetch = toPage(function () {
        try { const a = arguments[0]; addUrl(typeof a === 'string' ? a : (a && a.url)); } catch {}
        return of_.apply(this, arguments);
      });
    } catch {}
    try {
      const oo = uw.XMLHttpRequest && uw.XMLHttpRequest.prototype && uw.XMLHttpRequest.prototype.open;
      if (oo) uw.XMLHttpRequest.prototype.open = toPage(function (_, url) {
        try { addUrl(String(url)); } catch {}
        return oo.apply(this, arguments);
      });
    } catch {}
    try {
      const OW = uw.WebSocket;
      if (OW) {
        const shim = function (url, protocols) {
          try { addUrl(url); } catch {}
          return protocols === undefined ? Reflect.construct(OW, [url]) : Reflect.construct(OW, [url, protocols]);
        };
        try { Object.setPrototypeOf(shim, OW); } catch {}
        shim.prototype = OW.prototype;
        uw.WebSocket = toPage(shim);
      }
    } catch {}
    try {
      const OE = uw.EventSource;
      if (OE) {
        const shim = function (url, cfg) {
          try { addUrl(url); } catch {}
          return cfg === undefined ? Reflect.construct(OE, [url]) : Reflect.construct(OE, [url, cfg]);
        };
        try { Object.setPrototypeOf(shim, OE); } catch {}
        shim.prototype = OE.prototype;
        uw.EventSource = toPage(shim);
      }
    } catch {}
    try {
      const OR = uw.RTCPeerConnection || uw.webkitRTCPeerConnection;
      if (OR) {
        const shim = function (cfg) {
          try {
            ((cfg && cfg.iceServers) || []).forEach((sv) => [].concat((sv && sv.urls) || []).forEach((u) => addUrl(u)));
          } catch {}
          return Reflect.construct(OR, arguments.length ? [cfg] : []);
        };
        try { Object.setPrototypeOf(shim, OR); } catch {}
        shim.prototype = OR.prototype;
        if (uw.RTCPeerConnection) uw.RTCPeerConnection = toPage(shim);
        else if (uw.webkitRTCPeerConnection) uw.webkitRTCPeerConnection = toPage(shim);
      }
    } catch {}
    try {
      const NP = Object.getPrototypeOf(uw.navigator);
      const ob = NP && NP.sendBeacon;
      if (ob) NP.sendBeacon = toPage(function (u, d) {
        try { addUrl(String(u)); } catch {}
        return ob.call(this, u, d);
      });
    } catch {}
  };

  // ────────────────── СЕТЕВОЙ БУФЕР БРАУЗЕРА ──────────────────
  try { performance.setResourceTimingBufferSize && performance.setResourceTimingBufferSize(20000); } catch {}
  try { new PerformanceObserver((l) => { l.getEntries().forEach((e) => addUrl(e.name)); }).observe({ type: 'resource', buffered: true }); } catch {}

  // ────────────────── СКАН DOM И CSS ──────────────────
  const URL_RE = /url\(\s*['"]?([^'")]+)['"]?\s*\)/gi;
  const cssTextUrls = (txt) => {
    if (!txt) return;
    URL_RE.lastIndex = 0;
    let m; while ((m = URL_RE.exec(txt))) { try { addUrl(m[1]); } catch {} }
  };

  const ATTRS = ['src', 'href', 'data-src', 'data-href', 'poster', 'action', 'formaction', 'data', 'background'];
  const SEL = '[src],[href],[data-src],[data-href],[poster],[action],[formaction],[data],[srcset],[style]';
  const scanEl = (el) => {
    try {
      const g = (a) => { const v = el.getAttribute && el.getAttribute(a); return v || ''; };
      for (const a of ATTRS) { const v = g(a); if (v) addUrl(v); }
      const ss = g('srcset'); if (ss) ss.split(',').forEach((p) => addUrl(p.trim().split(/\s+/)[0]));
      const st = g('style'); if (st) cssTextUrls(st);
      if (el.tagName === 'STYLE' && el.textContent) cssTextUrls(el.textContent);
    } catch {}
  };
  const scanNode = (n) => {
    if (!n || n.nodeType !== 1) return;
    scanEl(n);
    try { if (n.querySelectorAll) n.querySelectorAll(SEL).forEach(scanEl); } catch {}
  };
  const scanSheets = () => {
    let txt = '';
    try {
      for (const sh of document.styleSheets) { try { for (const r of sh.cssRules) txt += r.cssText + '\n'; } catch {} }
    } catch {}
    if (txt) cssTextUrls(txt);
  };
  const startWatch = () => {
    try { scanNode(document.documentElement); } catch {}
    try {
      new MutationObserver((ms) => ms.forEach((m) => m.addedNodes.forEach(scanNode)))
        .observe(document.documentElement, { childList: true, subtree: true });
    } catch {}
  };
  if (document.documentElement) startWatch();
  else {
    // document-start: documentElement ещё нет — дождёмся его появления
    try {
      const boot = new MutationObserver(() => { if (document.documentElement) { boot.disconnect(); startWatch(); } });
      boot.observe(document, { childList: true });
    } catch {}
  }

  // ────────────────── СОХРАНЕНИЕ МЕЖДУ ПЕРЕХОДАМИ (в рамках origin) ──────────────────
  let saveTimer = 0;
  const saveNow = () => {
    try {
      const st = {};
      for (const [h, s] of info) if (s && s.status) st[h] = {
        i: s.status.icons, t: s.status.tag, b: s.status.blocked ? 1 : 0,
        r: s.route ? { d: s.route.direct ? 1 : 0, v: s.route.via, f: s.route.inferred ? 1 : 0 } : null,
        c: s.reg && s.reg.total ? { w: s.reg.winner, n: s.reg.total, c: s.reg.counts } : null,
        s: s.regStatic ? { b: s.regStatic.blocked ? 1 : 0, o: s.regStatic.org, l: s.regStatic.loc, cd: s.regStatic.cdn } : null,
      };
      sessionStorage.setItem(SKEY, JSON.stringify({ hosts: [...domains.keys()], st }));
    } catch {}
  };
  function scheduleSave() {
    if (!isTop || saveTimer) return;
    saveTimer = setTimeout(() => { saveTimer = 0; saveNow(); }, 1500);
  }
  const restore = () => {
    try {
      const raw = sessionStorage.getItem(SKEY);
      if (!raw) return;
      const d = JSON.parse(raw);
      (d.hosts || []).forEach(addHost);
      const st = d.st || {};
      for (const h of Object.keys(st)) {
        const r = st[h].r, c = st[h].c, s = st[h].s;
        info.set(h, {
          status: { icons: st[h].i, tag: st[h].t, blocked: !!st[h].b },
          busy: false,
          route: r ? { direct: !!r.d, via: r.v || '', rule: '', inferred: !!r.f } : null,
          reg: c && c.n ? { counts: c.c || {}, total: c.n, winner: c.w, cached: true } : null,
          regStatic: s ? { blocked: !!s.b, org: s.o || '', loc: s.l || '', cdn: s.cd || [], rkn: '', subnets: 0 } : null,
        });
      }
    } catch {}
  };
  window.addEventListener('pagehide', () => { if (saveTimer) { clearTimeout(saveTimer); saveTimer = 0; } saveNow(); flushSend(); });

  // ────────────────── РЕЕСТР ЗАБЛОКИРОВАННЫХ (antifilter) ──────────────────
  const REG = { dom: null, nets: null, wide: null, t: 0, domCount: 0, netCount: 0, loading: false, err: '', promise: null };

  const ip2int = (s) => {
    const p = String(s).split('.');
    if (p.length !== 4 || !p.every((x) => /^\d+$/.test(x) && +x <= 255)) return null;
    return (((+p[0] << 24) | (+p[1] << 16) | (+p[2] << 8) | +p[3]) >>> 0);
  };
  const applyReg = (dText, nText) => {
    const set = new Set();
    (dText || '').split('\n').forEach((l) => {
      l = l.trim().toLowerCase();
      if (!l || l.startsWith('#')) return;
      if (l.startsWith('*.')) l = l.slice(2);
      if (l && /^[a-z0-9._-]+$/.test(l)) set.add(l);
    });
    const nets = new Map(); const wide = []; let netCount = 0;
    (nText || '').split('\n').forEach((l) => {
      l = l.trim();
      if (!l || l.startsWith('#')) return;
      const cut = l.indexOf('/');
      const ip = (cut === -1 ? l : l.slice(0, cut)).trim();
      const bits = cut === -1 ? 32 : +l.slice(cut + 1);
      if (!(bits >= 0 && bits <= 32)) return;
      const n = ip2int(ip); if (n === null) return;
      const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
      const net = (n & mask) >>> 0;
      const entry = { net, mask };
      if (bits < 8) wide.push(entry);
      else { const o = net >>> 24; if (!nets.has(o)) nets.set(o, []); nets.get(o).push(entry); }
      netCount++;
    });
    REG.dom = set; REG.nets = nets; REG.wide = wide; REG.domCount = set.size; REG.netCount = netCount;
  };
  const ipInReg = (ip) => {
    if (!REG.nets) return false;
    const n = ip2int(ip); if (n === null) return false;
    const test = (e) => ((n & e.mask) >>> 0) === e.net;
    const arr = REG.nets.get(n >>> 24);
    return (arr ? arr.some(test) : false) || REG.wide.some(test);
  };
  const domInReg = (host) => {
    if (!REG.dom) return false;
    if (REG.dom.has(host)) return true;
    let i = host.indexOf('.');
    while (i !== -1) { if (REG.dom.has(host.slice(i + 1))) return true; i = host.indexOf('.', i + 1); }
    return false;
  };
  const loadLists = (force) => {
    if (!hasGM) { REG.err = 'нет GM_xmlhttpRequest'; return Promise.resolve(false); }
    if (!force && REG.dom) return Promise.resolve(true);
    if (!force) {
      const c = gmGet('__dsnf3_reg', null);
      if (c && c.t && Date.now() - c.t < CFG.listTtlMs && typeof c.d === 'string') {
        applyReg(c.d, c.n || ''); REG.t = c.t; return Promise.resolve(true);
      }
    }
    if (REG.loading) return REG.promise;
    REG.loading = true; REG.err = '';
    REG.promise = (async () => {
      try {
        const [d, s, ip] = await Promise.all([
          gmText(CFG.lists.domains, 120000),
          gmText(CFG.lists.subnet, 120000).catch(() => ''),
          gmText(CFG.lists.ip, 120000).catch(() => ''),
        ]);
        applyReg(d, (s ? s + '\n' : '') + (ip || ''));
        REG.t = Date.now();
        gmSet('__dsnf3_reg', { t: REG.t, d, n: (s ? s + '\n' : '') + (ip || '') }); // если не влезет в кэш — просто без кэша
        renderSoon();
        return true;
      } catch (e) {
        REG.err = 'списки реестра не загрузились';
        renderSoon();
        return false;
      } finally { REG.loading = false; }
    })();
    return REG.promise;
  };

  // ────────────────── МАРШРУТ: Clash API (Podkop/Forkop/NetShift на роутере, sing-box/clash на ПК) ──────────────────
  const ROUTE = { base: null, secret: '', ok: false, ver: '', hostIdx: new Map(), ipIdx: new Map(), lastPoll: 0, timer: 0, echo: null };

  const routeHeaders = () => (ROUTE.secret ? { Authorization: 'Bearer ' + ROUTE.secret } : {});
  const tryRouteUrl = async (url) => {
    url = String(url || '').replace(/\/+$/, '');
    if (!/^https?:\/\/.+/.test(url)) return false;
    try {
      const a = await gmReq({ url: url + '/version', method: 'GET', timeout: 2500, headers: routeHeaders() });
      if (a.ok && a.r.responseText && a.r.responseText.indexOf('version') !== -1) {
        ROUTE.base = url; ROUTE.ok = true;
        try { ROUTE.ver = JSON.parse(a.r.responseText).version || ''; } catch {}
        return true;
      }
    } catch {}
    return false;
  };
  const connectRoute = async (url, secret, save) => {
    if (!hasGM) return 'GM недоступен';
    ROUTE.secret = String(secret || '').trim();
    ROUTE.ok = false;
    if (await tryRouteUrl(url)) {
      if (save) gmSet('__dsnf3_route', { url: ROUTE.base, secret: ROUTE.secret });
      startRoutePolling();
      echoCheck();
      return '✅ Подключено: ' + ROUTE.base + (ROUTE.ver ? ' (ядро ' + ROUTE.ver + ')' : '');
    }
    return '❌ Не отвечает. Включите Clash API/дашборд на роутере (обычно порт 9090) и проверьте адрес.';
  };
  const detectRoute = async () => {
    if (!hasGM) return;
    const saved = gmGet('__dsnf3_route', null);
    if (saved && saved.url && await connectRoute(saved.url, saved.secret, false)) return;
    for (const u of CFG.route.candidates) if (await connectRoute(u, saved && saved.secret ? saved.secret : '', false)) return;
  };
  const buildRouteIndex = (conns) => {
    const now = Date.now();
    for (const c of (conns || [])) {
      try {
        const m = c.metadata || {};
        const host = String(m.host || m.sni || m.serverName || '').toLowerCase().replace(/\.$/, '');
        const chains = (c.chains || []).map(String);
        if (!host && !m.destinationIP) continue;
        const ent = { via: chains.join('→') || '?', direct: chains.some((x) => /direct|bypass/i.test(x)), rule: [c.rule, c.rulePayload].filter(Boolean).join(':'), ip: m.destinationIP || '', t: now };
        if (host && host.includes('.')) ROUTE.hostIdx.set(host, ent);
        if (ent.ip) ROUTE.ipIdx.set(ent.ip, ent);
      } catch {}
    }
    if (ROUTE.hostIdx.size > 5000) { for (const [k, v] of ROUTE.hostIdx) if (now - v.t > 300000) ROUTE.hostIdx.delete(k); }
    if (ROUTE.ipIdx.size > 5000) { for (const [k, v] of ROUTE.ipIdx) if (now - v.t > 300000) ROUTE.ipIdx.delete(k); }
  };
  const matchRoute = (host, ips) => {
    if (!ROUTE.ok) return null;
    let ent = ROUTE.hostIdx.get(host);
    if (!ent) { let i = host.indexOf('.'); while (i !== -1 && !ent) { ent = ROUTE.hostIdx.get(host.slice(i + 1)); i = host.indexOf('.', i + 1); } }
    if (!ent && ips) for (const ip of ips) { const e = ROUTE.ipIdx.get(ip); if (e) { ent = e; break; } }
    return ent ? { direct: ent.direct, via: ent.via, rule: ent.rule } : null;
  };
  const pollRoute = async () => {
    if (!ROUTE.ok || !hasGM) return;
    try {
      const a = await gmReq({ url: ROUTE.base + '/connections', method: 'GET', timeout: 4000, headers: routeHeaders() });
      if (a.ok) {
        try { buildRouteIndex(JSON.parse(a.r.responseText).connections); } catch {}
        ROUTE.lastPoll = Date.now();
        let touched = false;
        for (const h of domains.keys()) {
          const s = info.get(h);
          if (s && (!s.route || s.route.inferred || Date.now() - (s.routeT || 0) > 60000)) {
            const r = matchRoute(h, s.ips);
            if (r) { s.route = r; s.routeT = Date.now(); touched = true; }
          }
        }
        if (touched) renderSoon();
      }
    } catch {}
    renderSoon();
  };
  const startRoutePolling = () => { if (!ROUTE.ok || ROUTE.timer) return; pollRoute(); ROUTE.timer = setInterval(() => { if (!document.hidden) pollRoute(); }, CFG.route.pollMs); };
  const stopRoutePolling = () => { if (ROUTE.timer) { clearInterval(ROUTE.timer); ROUTE.timer = 0; } };

  // какой IP видят зарубежный и RU-сервис → детект сплит-маршрутизации / VPN-выхода
  const echoCheck = async () => {
    if (!hasGM) return;
    const out = { cf: null, ru: null };
    try {
      const t = await gmText(CFG.echo.foreign, 8000);
      const ip = /^ip=(.*)$/m.exec(t); const loc = /^loc=(.*)$/m.exec(t);
      out.cf = { ip: ip ? ip[1].trim() : '', loc: loc ? loc[1].trim() : '' };
    } catch {}
    try {
      const j = JSON.parse(await gmText(CFG.echo.ru, 8000));
      const loc = (j.country && (j.country.iso || j.country.code)) || (typeof j.country === 'string' ? j.country : '') || '';
      out.ru = { ip: j.ip || '', loc: loc };
    } catch {}
    ROUTE.echo = out; renderSoon();
  };
  const echoText = () => {
    const e = ROUTE.echo;
    if (!e || (!e.cf && !e.ru)) return '';
    const f = e.cf ? 'мир видит ' + (e.cf.ip || '?') + (e.cf.loc ? ' (' + e.cf.loc + ')' : '') : '';
    const r = e.ru ? ' · RU видит ' + (e.ru.ip || '?') + (e.ru.loc ? ' (' + e.ru.loc + ')' : '') : '';
    if (e.cf && e.ru && e.cf.ip && e.ru.ip && e.cf.ip !== e.ru.ip) return '🌐 ' + f + r + ' → сплит-маршрутизация';
    if (e.cf && e.cf.loc && e.cf.loc !== 'RU') return '🌐 ' + f + r + ' → выход через VPN/прокси';
    return '🌐 ' + f + r;
  };

  // ────────────────── ГЕО IP (для латентностной эвристики маршрута) ──────────────────
  const GEO = new Map(); // ip → countryCode
  const geoLookup = async (ips) => {
    const need = [...new Set(ips || [])].filter((ip) => ip && !GEO.has(ip)).slice(0, 100);
    if (!need.length) return;
    try {
      const a = await gmReq({ url: CFG.geoBatchUrl + '?fields=status,countryCode,query', method: 'POST', timeout: 10000, headers: { 'Content-Type': 'application/json' }, data: JSON.stringify(need) });
      if (!a.ok) return;
      JSON.parse(a.r.responseText).forEach((e) => { if (e && e.query) GEO.set(e.query, e.countryCode || '?'); });
    } catch {}
  };

  // ────────────────── РЕГИОНАЛЬНАЯ ПРОВЕРКА (cheburcheck.ru) ──────────────────
  // Статика: /api/v1/check?target= — реестр + списки CDN-хостеров + ASN.
  // Живая часть: /api/v1/probe/{id} — SSE-поток вердиктов от сканеров
  // в регионах РФ (region/provider/asn у каждого). Вердикты: sni_block /
  // tspu_block / dns_spoofing / cdn_block (16-20КБ) / whitelist / ok.
  const CHB = { busy: false, active: '', parts: 0, online: 0 };
  const chbQueue = [];

  const CHB_V = {
    sni_block:    { i: '⛔', t: 'SNI-блок (DPI)' },
    tspu_block:   { i: '🕳', t: 'ТСПУ-блок (IP)' },
    dns_spoofing: { i: '🌀', t: 'подмена DNS' },
    cdn_block:    { i: '✂️', t: 'CDN-блок (16-20КБ)' },
    whitelist:    { i: '🟢', t: 'в белом списке' },
    ok:           { i: '✅', t: 'доступен' },
    uncertain:    { i: '❔', t: 'неясно' },
  };
  const CHB_PRIO = ['tspu_block', 'sni_block', 'dns_spoofing', 'whitelist', 'cdn_block', 'ok', 'uncertain'];

  // разбор SSE: пары "event:…\ndata:{…}"; результата могут прилетать кусками,
  // поэтому парсим только законченные строки; ev хранится в pos — событие
  // и его data могут приехать в разных чанках
  const chbCollect = (txt, pos, sink) => {
    if (!txt || txt.length <= pos.last) return;
    const cut = txt.lastIndexOf('\n');
    if (cut <= pos.last) return;
    const chunk = txt.slice(pos.last, cut);
    pos.last = cut;
    for (const l of chunk.split('\n')) {
      if (l.startsWith('event:')) pos.ev = l.slice(6).trim();
      else if (l.startsWith('data:')) {
        try { sink(pos.ev, JSON.parse(l.slice(5))); } catch {}
        pos.ev = null;
      }
    }
  };

  // голосование как у фронтенда cheburcheck: у каждого сканера берём самый
  // «тяжёлый» вердикт по приоритету, потом считаем голоса
  const chbAgg = (probes) => {
    const counts = {}; const seen = new Set();
    for (const p of probes) {
      if (!p.verdicts || !p.verdicts.length || seen.has(p.probe_id)) continue; // пустые не голосуют — как у их фронтенда
      seen.add(p.probe_id);
      let sel = 'uncertain';
      for (const v of CHB_PRIO) if (p.verdicts.includes(v)) { sel = v; break; }
      counts[sel] = (counts[sel] || 0) + 1;
    }
    let winner = null;
    for (const v of CHB_PRIO) if (counts[v] && (!winner || counts[v] > counts[winner])) winner = v;
    return { counts, total: seen.size, winner };
  };

  const chbScan = async (host, onPart) => {
    const a = await gmReq({ url: CFG.chb.base + '/api/v1/check?target=' + encodeURIComponent(host), method: 'GET', timeout: 30000, headers: { accept: 'application/json' } });
    if (!a.ok) throw new Error('cheburcheck: недоступен');
    let j = null;
    try { j = JSON.parse(a.r.responseText); } catch { throw new Error('cheburcheck: неверный ответ'); }
    const stat = {
      blocked: !!j.blocked,
      rkn: j.rkn_domain || '',
      cdn: Object.keys(j.cdn_providers || {}).slice(0, 4), // хостеры: hetzner, cloudflare…
      subnets: (j.blocked_subnets || []).length,
      org: (j.geo && j.geo.organisation) || '',
      loc: (j.geo && j.geo.location) || '',
    };
    gmSet('__dsnf3_chbs_' + host, { t: Date.now(), d: stat });
    if (!j.id) return { stat, agg: null };
    const probes = [];
    const pos = { last: 0 };
    const b = await gmReq({
      url: CFG.chb.base + '/api/v1/probe/' + encodeURIComponent(j.id),
      method: 'GET', timeout: CFG.chb.probeTimeoutMs,
      headers: { accept: 'text/event-stream' },
      onprogress: (e) => {
        chbCollect(e.responseText, pos, (ev, d) => {
          if (ev === 'started' && d.online_probes) CHB.online = d.online_probes;
          else if (ev === 'result' && d.verdicts && !probes.some((p) => p.probe_id === d.probe_id)) {
            probes.push(d); CHB.parts = probes.length;
            onPart({ stat, agg: chbAgg(probes), parts: probes.length, online: CHB.online });
          }
        });
      },
      onload: (r) => {
        chbCollect(r.responseText, pos, (ev, d) => {
          if (ev === 'result' && d.verdicts && !probes.some((p) => p.probe_id === d.probe_id)) { probes.push(d); CHB.parts = probes.length; }
          if (ev === 'started' && d.online_probes) CHB.online = d.online_probes;
        });
      },
    });
    if (!b.ok && !probes.length) throw new Error('cheburcheck: скан не удался');
    const agg = chbAgg(probes);
    if (agg.total) gmSet('__dsnf3_chbp_' + host, { t: Date.now(), c: agg.counts, n: agg.total, w: agg.winner });
    return { stat, agg, parts: probes.length };
  };

  const chbPump = async () => {
    if (CHB.busy) return;
    const host = chbQueue.shift();
    if (!host || !hasGM) return;
    CHB.busy = true; CHB.active = host; CHB.parts = 0; CHB.online = 0;
    const st = info.get(host) || {}; info.set(host, st);
    st.chbBusy = true; delete st.regErr; renderSoon();
    try {
      const c = gmGet('__dsnf3_chbp_' + host, null);
      if (c && c.t && Date.now() - c.t < CFG.chb.probeTtlMs && c.n) {
        st.reg = { counts: c.c, total: c.n, winner: c.w, cached: true }; // свежий кэш — не дёргаем сканеры
        const cs = gmGet('__dsnf3_chbs_' + host, null);
        if (cs && cs.d) st.regStatic = cs.d;
      } else {
        const res = await chbScan(host, ({ stat, agg }) => {
          st.regStatic = stat;
          if (agg && agg.total) { st.reg = agg; renderSoon(); }
        });
        st.regStatic = res.stat;
        if (res.agg && res.agg.total) st.reg = res.agg;
        else {
          const old = gmGet('__dsnf3_chbp_' + host, null);
          if (old && old.n) st.reg = { counts: old.c, total: old.n, winner: old.w, cached: true };
          else st.regErr = 'сканеры не ответили';
        }
      }
    } catch (e) {
      const c = gmGet('__dsnf3_chbp_' + host, null);
      if (c && c.n) st.reg = { counts: c.c, total: c.n, winner: c.w, cached: true };
      else st.regErr = String((e && e.message) || e || 'ошибка региональной проверки');
      setTimeout(() => { delete st.regErr; renderSoon(); }, 10000);
    } finally {
      st.chbBusy = false; CHB.busy = false; CHB.active = ''; renderSoon();
      if (chbQueue.length) chbPump();
    }
  };

  const chbTag = (st) => {
    if (st.chbBusy) return '🌍 сканирую по регионам РФ…' + (CHB.parts ? ' (' + CHB.parts + (CHB.online ? '/' + CHB.online : '') + ')' : '');
    if (st.regErr) return '🌍 ' + st.regErr;
    if (!st.reg || !st.reg.total) return '';
    const a = st.reg;
    const w = CHB_V[a.winner];
    const top = CHB_PRIO.filter((v) => a.counts[v]).slice(0, 4).map((v) => (CHB_V[v] ? CHB_V[v].i : '?') + a.counts[v]).join(' ');
    let s = '🌍 ' + (w ? w.t : 'неясно') + ' [' + top + '] · ' + a.total + ' рег.' + (a.cached ? ' (кэш)' : '');
    const rs = st.regStatic;
    if (rs) {
      if (rs.blocked) s += ' · 📋 в списках cheburcheck';
      if (rs.cdn && rs.cdn.length) s += ' · 🖥 ' + rs.cdn.join(', ');
      else if (rs.loc) s += ' · 🖥 ' + rs.loc;
    }
    return s;
  };

  // ────────────────── DNS-OVER-HTTPS (узнать IP домена) ──────────────────
  const dohQuery = async (host) => {
    for (const base of CFG.doh) {
      try {
        const hdr = base.includes('cloudflare') ? { accept: 'application/dns-json' } : {};
        const txt = await gmText(base + '?name=' + encodeURIComponent(host) + '&type=A', 8000, hdr);
        const j = JSON.parse(txt);
        const ans = (j.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
        if (ans.length) return ans;
      } catch {}
    }
    return [];
  };

  // ────────────────── ЖИВЫЕ ПРОБЫ ──────────────────
  // Возвращает {kind:'ok'|'err'|'timeout'|'abort', status, loaded, ms, sustained, silentMs}
  //   sustained — устойчивая скорость (Б/с) ПОСЛЕ первых slowSkipBytes, окно ≥0.5с;
  //   TTFB и «сервер думает» в скорость не попадают. null = не измерить (мало данных).
  //   silentMs — сколько миллисекунд до конца не было ни одного байта (детект «встало»).
  const probeUrl = (url) => new Promise((res) => {
    let loaded = 0, t0 = 0, done = false, ctrl = null;
    let anchorB = -1, anchorT = 0, lastBumpT = 0;
    t0 = performance.now(); lastBumpT = t0;
    const finish = (o) => {
      if (done) return; done = true;
      let sustained = null;
      if (anchorB >= 0) {
        const dt = (performance.now() - anchorT) / 1000;
        if (dt >= 0.5 && loaded > anchorB) sustained = (loaded - anchorB) / dt;
      }
      res(Object.assign({ loaded, ms: performance.now() - t0, sustained, silentMs: performance.now() - lastBumpT }, o));
    };
    try {
      ctrl = GM_xmlhttpRequest({
        url, method: 'GET', timeout: CFG.probeTimeoutMs, anonymous: true,
        onprogress: (e) => {
          if (e.loaded > loaded) {
            loaded = e.loaded; lastBumpT = performance.now();
            if (anchorB < 0 && loaded >= CFG.slowSkipBytes) { anchorB = loaded; anchorT = lastBumpT; }
            if (loaded >= CFG.probeMaxBody && ctrl) { try { ctrl.abort(); } catch {} }
          }
        },
        onload: (r) => finish({ kind: 'ok', status: r.status }),
        onerror: (e) => finish({ kind: 'err', err: String((e && e.error) || '') }),
        ontimeout: () => finish({ kind: 'timeout' }),
        onabort: () => finish({ kind: 'abort' }),
      });
    } catch (e) { finish({ kind: 'err', err: String(e) }); }
  });

  const classify = (p1, p2, regDom, regIp, ips) => {
    const parts = [];
    if (regDom) parts.push({ b: true, i: '📋', t: 'домен в реестре' });
    if (regIp) {
      const hit = (ips || []).filter(ipInReg).slice(0, 2).join(', ');
      parts.push({ b: true, i: '📍', t: 'IP-подсеть в реестре' + (hit ? ' (' + hit + ')' : '') });
    }
    const okP2 = p2 && (p2.kind === 'ok' || p2.kind === 'abort');
    const maxLoaded = Math.max(p1 ? p1.loaded : 0, p2 ? p2.loaded : 0);
    const kb = (n) => Math.round(n / 1024);
    const rate = (p) => (p && p.sustained !== null ? ' · ~' + Math.round(p.sustained / 1024) + 'КБ/с' : '');
    if (p1 && (p1.kind === 'ok' || p1.kind === 'abort')) {
      if (p1.sustained !== null && p1.sustained < CFG.slowBytesPerSec && p1.loaded >= CFG.slowMinBytes) {
        parts.push({ b: true, i: '🐢', t: 'замедление (~' + Math.round(p1.sustained / 1024) + 'КБ/с устойчиво)' });
      }
      parts.push({ b: false, i: '✅', t: (p1.kind === 'ok' ? 'доступен (HTTP ' + p1.status + ')' : 'доступен') + rate(p1) });
    } else if (okP2) {
      parts.push({ b: true, i: '⛔', t: 'HTTPS не отвечает/сброшен, HTTP отвечает — похоже на DPI по SNI (или нет TLS)' + rate(p2) });
    } else if (p1 && p1.kind === 'timeout' && p1.loaded > 0) {
      // байты шли, но за таймаут не докачались: медленно или «встало» — НЕ «полная блокировка»
      if (p1.silentMs > CFG.stallSilentMs) {
        parts.push({ b: true, i: '✂️', t: 'встало после ~' + kb(p1.loaded) + 'КБ — частичная блокировка/обрыв' });
      } else {
        parts.push({ b: true, i: '🐢', t: 'очень медленно: ' + kb(p1.loaded) + 'КБ за ' + Math.round(p1.ms / 1000) + 'с' + rate(p1) });
      }
    } else if (maxLoaded >= CFG.partialMin && maxLoaded <= CFG.partialMax && ((p1 && p1.kind === 'err') || (p2 && p2.kind === 'err'))) {
      parts.push({ b: true, i: '✂️', t: 'обрыв после ~' + kb(maxLoaded) + 'КБ — частичная блокировка (16-20КБ)' });
    } else if (maxLoaded > CFG.partialMax && ((p1 && p1.kind === 'err') || (p2 && p2.kind === 'err'))) {
      parts.push({ b: true, i: '⚠️', t: 'обрыв после ' + kb(maxLoaded) + 'КБ' + rate(p1 || p2) });
    } else if (p1 && p1.kind === 'timeout' && (!p2 || p2.kind === 'timeout')) {
      parts.push({ b: true, i: '🕳', t: 'нет ответа (0 байт) — похоже на полную блокировку по IP' });
    } else {
      parts.push({ b: true, i: '⛔', t: 'сброс соединения — похоже на DPI' });
    }
    const icons = [...new Set(parts.map((p) => p.i))].join('');
    return { blocked: parts.some((p) => p.b), icons, tag: parts.map((p) => p.t).join(' · ') };
  };

  const checkDomain = async (host) => {
    let st = info.get(host);
    if (!st) { st = {}; info.set(host, st); }
    st.busy = true; renderSoon();
    try {
      const regDom = domInReg(host);
      const ips = hasGM ? await dohQuery(host) : [];
      await geoLookup(ips);
      st.ips = ips;
      st.geo = (ips.map((ip) => GEO.get(ip)).find((c) => c) || '');
      st.ms = null;
      const regIp = ips.some(ipInReg);
      const p1 = hasGM ? await probeUrl('https://' + host + '/') : null;
      let p2 = null;
      if (p1 && p1.kind !== 'ok' && p1.kind !== 'abort') p2 = await probeUrl('http://' + host + '/');
      st.status = classify(p1, p2, regDom, regIp, ips);
      if (p1) st.ms = Math.round(p1.ms);
      // маршрут точно: наша проба сама создала соединение на роутере — читаем /connections
      if (ROUTE.ok) {
        await new Promise((r) => setTimeout(r, CFG.route.probeDelayMs));
        await pollRoute();
        const rt = matchRoute(host, ips);
        if (rt) { st.route = rt; st.routeT = Date.now(); }
      }
      // маршрут косвенно (Clash API не подключён): реестр+проба, затем латентность RU-целей
      if (!st.route && p1) {
        const okHttps = p1.kind === 'ok' || p1.kind === 'abort';
        if (regDom && okHttps) {
          st.route = { direct: false, via: 'прокси (косвенно: в реестре, но доступен)', rule: '', inferred: true };
        } else if (regDom) {
          st.route = { direct: true, via: 'напрямую (косвенно: в реестре и блокируется)', rule: '', inferred: true };
        } else if (st.geo === 'RU' && okHttps) {
          if (p1.ms > CFG.ruFarMs) st.route = { direct: false, via: 'похоже прокси (RU-сервер, но ' + Math.round(p1.ms) + 'мс — как из-за границы)', rule: '', inferred: true };
          else if (p1.ms < CFG.ruDirectMs) st.route = { direct: true, via: 'похоже напрямую (RU-сервер, ' + Math.round(p1.ms) + 'мс — локально быстро)', rule: '', inferred: true };
        }
        if (st.route) st.routeT = Date.now();
      }
    } catch {} finally { st.busy = false; renderSoon(); }
  };

  // ────────────────── ОЧЕРЕДЬ ПРОВЕРОК ──────────────────
  const queue = [];
  let running = false, stopReq = false;
  const runChecks = async () => {
    if (running) return;
    running = true; stopReq = false; renderSoon();
    const worker = async () => {
      while (queue.length && !stopReq) {
        const h = queue.shift();
        try { await checkDomain(h); } catch {}
        renderSoon();
      }
    };
    const n = Math.max(1, Math.min(CFG.probeConcurrency, queue.length || 1));
    await Promise.all(Array.from({ length: n }, worker));
    running = false; renderSoon();
  };
  const checkAll = async () => {
    if (running) { stopReq = true; return; }
    if (!hasGM) { statusMsg = '⚠️ Проверка недоступна: нужен Tampermonkey/Violentmonkey (GM_xmlhttpRequest)'; renderSoon(); return; }
    if (!REG.dom) {
      statusMsg = '⏳ Загружаю списки реестра (первый раз ~10-20 МБ, кэш 12 ч)…'; renderSoon();
      await loadLists(false);
      statusMsg = ''; renderSoon();
    }
    const list = [...domains.keys()].filter((h) => { const s = info.get(h); return !(s && s.status); });
    for (const h of list) if (!queue.includes(h)) queue.push(h);
    await runChecks();
  };

  // ────────────────── СПИСОК ДЛЯ КОПИРОВАНИЯ ──────────────────
  const getListText = () => {
    const arr = rootOnly ? [...new Set([...domains.keys()].map(getRoot))] : [...domains.keys()];
    return arr.sort((a, b) => getRoot(a).localeCompare(getRoot(b)) || a.localeCompare(b)).join('\n');
  };

  // ────────────────── UI (только в верхнем фрейме) ──────────────────
  const initUI = () => {
    if (document.getElementById('__dsnf3_box')) return;
    let isOpen = false;
    try { isOpen = sessionStorage.getItem(SOPEN) === '1'; } catch {}
    const setOpen = (v) => { try { v ? sessionStorage.setItem(SOPEN, '1') : sessionStorage.removeItem(SOPEN); } catch {} };
    let viewFilter = 'all'; // 'all' | 'bad' | 'ok'
    let showHelp = false;

    scanSheets();
    setTimeout(scanSheets, 2000); setTimeout(scanSheets, 8000); // CSS догружаются позже

    const mkBtn = (label, bg, hint) => {
      const b = document.createElement('button');
      b.textContent = label;
      if (hint) b.title = hint;
      Object.assign(b.style, { background: bg || '#21262d', color: '#e6edf3', border: '1px solid #30363d', borderRadius: '6px', padding: '3px 7px', cursor: 'pointer', font: 'inherit', fontSize: '11px', whiteSpace: 'nowrap' });
      return b;
    };

    const pill = document.createElement('button');
    pill.id = '__dsnf3_pill';
    pill.title = 'Domain Sniffer: показать собранные домены';
    Object.assign(pill.style, { position: 'fixed', bottom: '14px', right: '14px', zIndex: 2147483647, background: '#14161a', color: '#58a6ff', border: '1px solid #30363d', borderRadius: '999px', padding: '6px 12px', font: '600 12px/1 ui-monospace,Consolas,monospace', cursor: 'pointer', boxShadow: '0 4px 16px rgba(0,0,0,.45)' });

    const box = document.createElement('div');
    box.id = '__dsnf3_box';
    Object.assign(box.style, { position: 'fixed', bottom: '14px', right: '14px', zIndex: 2147483647, width: '560px', maxWidth: 'calc(100vw - 20px)', background: '#14161a', color: '#e6edf3', border: '1px solid #30363d', borderRadius: '10px', font: '12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace', boxShadow: '0 8px 28px rgba(0,0,0,.55)', padding: '10px' });

    const header = document.createElement('div');
    Object.assign(header.style, { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '4px', marginBottom: '8px', flexWrap: 'wrap' });
    const title = document.createElement('strong');
    Object.assign(title.style, { fontSize: '12px', color: '#58a6ff', whiteSpace: 'nowrap' });
    const btnGroup = document.createElement('div');
    Object.assign(btnGroup.style, { display: 'flex', gap: '4px', flexWrap: 'wrap' });

    const reloadBtn = mkBtn('🔄', '#1f6feb', 'Перезагрузить сайт и собрать все домены с нуля (список накапливается)');
    const modeBtn = mkBtn('Поддомены', '#21262d', 'Показывать все поддомены или только корневые домены');
    const copyBtn = mkBtn('Копировать', '#238636', 'Скопировать список доменов');
    const checkBtn = mkBtn('🚫 Проверить', '#7c3aed', 'Проверить все собранные домены: реестр блокировок + IP-подсети + живые пробы у вашего провайдера (DPI / полная / ~16-20КБ / замедление)');
    const chbBtn = mkBtn('🌍 Регионы', '#0d5c91', 'Проверить домен текущего сайта по регионам РФ (cheburcheck.ru): десятки сканеров покажут SNI-блок/ТСПУ/подмену DNS/CDN 16-20КБ по всем операторам (~1-2 мин, кэш 6 ч)');
    const clearBtn = mkBtn('🧹', '#21262d', 'Очистить собранный список');
    const helpBtn = mkBtn('?', '#21262d', 'Справка: что означают статусы и кнопки');
    const minBtn = mkBtn('—', '#21262d', 'Свернуть');
    const gearBtn = mkBtn('⚙', '#21262d', 'Маршрут через прокси: подключение к Clash API роутера/ПК (Podkop/Forkop/NetShift/sing-box/clash)');

    // настройки подключения к Clash API
    const settings = document.createElement('div');
    Object.assign(settings.style, { display: 'none', marginTop: '8px', borderTop: '1px solid #21262d', paddingTop: '8px' });
    const urlIn = document.createElement('input');
    urlIn.placeholder = 'Clash API, напр. http://192.168.1.1:9090';
    Object.assign(urlIn.style, { display: 'block', width: '100%', boxSizing: 'border-box', background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', color: '#e6edf3', font: 'inherit', fontSize: '11px', padding: '4px 6px', marginBottom: '4px' });
    const secIn = document.createElement('input');
    secIn.placeholder = 'секрет (если задан на роутере)';
    secIn.type = 'password';
    Object.assign(secIn.style, { display: 'block', width: '100%', boxSizing: 'border-box', background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', color: '#e6edf3', font: 'inherit', fontSize: '11px', padding: '4px 6px', marginBottom: '4px' });
    const applyBtn = mkBtn('Подключить', '#1f6feb', 'Проверить адрес и подключиться');
    const setStat = document.createElement('span');
    Object.assign(setStat.style, { fontSize: '10px', color: '#8b949e', marginLeft: '6px' });
    applyBtn.onclick = async () => { setStat.textContent = '…проверяю'; setStat.textContent = await connectRoute(urlIn.value, secIn.value, true); render(); };
    const srow = document.createElement('div');
    Object.assign(srow.style, { display: 'flex', alignItems: 'center', gap: '4px' });
    srow.append(applyBtn, setStat);
    settings.append(urlIn, secIn, srow);
    gearBtn.onclick = () => {
      const show = settings.style.display === 'none';
      settings.style.display = show ? 'block' : 'none';
      if (show) { const saved = gmGet('__dsnf3_route', null); urlIn.value = (saved && saved.url) || (ROUTE.base || ''); secIn.value = (saved && saved.secret) || ''; }
    };

    const list = document.createElement('div');
    Object.assign(list.style, { maxHeight: '340px', overflow: 'auto', background: '#0d1117', border: '1px solid #21262d', borderRadius: '6px', padding: '6px', userSelect: 'text' });

    // фильтры-чипсы: сразу видно, сколько проблем и сколько доступно
    const filters = document.createElement('div');
    Object.assign(filters.style, { display: 'flex', gap: '4px', marginBottom: '6px', flexWrap: 'wrap' });
    const mkChip = (key) => {
      const c = document.createElement('button');
      Object.assign(c.style, { background: '#21262d', color: '#e6edf3', border: '1px solid #30363d', borderRadius: '999px', padding: '3px 10px', cursor: 'pointer', font: 'inherit', fontSize: '11px', whiteSpace: 'nowrap' });
      c.onclick = () => { viewFilter = key; render(); };
      filters.append(c);
      return c;
    };
    const chipAll = mkChip('all');
    const chipBad = mkChip('bad');
    const chipOk = mkChip('ok');

    // вся документация — внутри панели по кнопке «?»
    const help = document.createElement('div');
    Object.assign(help.style, { display: 'none', background: '#0d1117', border: '1px solid #21262d', borderRadius: '6px', padding: '10px 12px', fontSize: '11px', lineHeight: '1.55', color: '#c9d1d9', overflow: 'auto', maxHeight: '340px', userSelect: 'text' });
    const hSec = (txt) => { const e = document.createElement('div'); e.textContent = txt; Object.assign(e.style, { color: '#58a6ff', fontWeight: '600', margin: '10px 0 3px' }); return e; };
    const hLine = (txt) => { const e = document.createElement('div'); e.textContent = txt; Object.assign(e.style, { marginBottom: '3px' }); return e; };
    help.append(
      hSec('Что это'),
      hLine('Скрипт собирает все домены, которые загружает сайт, и проверяет, какие из них заблокированы у вашего провайдера — чтобы было видно, почему сайт не работает или работает плохо.'),
      hSec('Кнопки'),
      hLine('🚫 Проверить — проверить все собранные домены: реестр блокировок + живые пробы у вашего провайдера.'),
      hLine('🌍 Регионы — домен текущего сайта проверяют десятки сканеров по России (cheburcheck.ru): видно, блокировка общая или только у вашего оператора. Долго (~1-2 мин), кэш 6 ч.'),
      hLine('🔄 — перезагрузить сайт и собрать домены заново · 🧹 — очистить список · Копировать — список в буфер обмена.'),
      hLine('⚙ — подключение к Clash API роутера (Podkop/Forkop/NetShift) или локального прокси: тогда видно, какой домен идёт через прокси, а какой напрямую.'),
      hSec('Статусы (проверка у вашего провайдера)'),
      hLine('✅ доступен'),
      hLine('⛔ сброс соединения — похоже на DPI-блокировку по имени домена'),
      hLine('🕳 нет ответа — похоже на полную блокировку по IP'),
      hLine('✂️ обрыв после ~16-20КБ — «частичная» блокировка страницы'),
      hLine('🐢 очень медленно — похоже на замедление (троттлинг)'),
      hLine('📋 домен есть в реестре блокировок · 📍 его IP в заблокированных подсетях (хостинг типа Hetzner/Cloudflare)'),
      hSec('Маршрут (нужен ⚙ Clash API)'),
      hLine('🚀 домен идёт через прокси (показана цепочка) · ⬇ идёт напрямую (и по какому правилу)'),
      hLine('🚀? / ⬇? — определено косвенно, без Clash API (по реестру и задержкам)'),
      hLine('🔴 — заблокирован И идёт напрямую: добавьте этот домен в прокси-лист роутера, и сайт заработает.'),
      hSec('Мелочи'),
      hLine('🌍 на строке — регион-чек этого домена по РФ'),
      hLine('клик по строке — перепроверить один домен · число справа — задержка в мс'),
      hLine('Список доменов и статусы сохраняются при переходах по сайту (до закрытия вкладки).'),
    );

    const statusbar = document.createElement('div');
    Object.assign(statusbar.style, { marginTop: '6px', fontSize: '10px', lineHeight: '1.5', color: '#8b949e' });

    const routebar = document.createElement('div');
    Object.assign(routebar.style, { marginTop: '2px', fontSize: '10px', lineHeight: '1.5', color: '#79c0ff' });
    routebar.title = 'Маршрутизация: кто идёт через прокси (🚀), кто напрямую (⬇). Без Clash API — только внешний IP/сплит';

    const CHIP_STYLE = {
      ok:   { bg: 'rgba(63,185,80,.15)',  fg: '#3fb950' },
      bad:  { bg: 'rgba(248,81,73,.18)',  fg: '#f85149' },
      none: { bg: 'rgba(139,148,158,.12)', fg: '#8b949e' },
      busy: { bg: 'rgba(88,166,255,.15)', fg: '#58a6ff' },
    };
    const mkRow = (r) => {
      const mood = r.busy ? 'busy' : (r.st || 'none');
      const cs = CHIP_STYLE[mood] || CHIP_STYLE.none;
      const row = document.createElement('div');
      Object.assign(row.style, { display: 'flex', flexDirection: 'column', gap: '1px', padding: '4px 6px', borderRadius: '6px', cursor: r.click ? 'pointer' : 'default', marginBottom: '2px' });
      if (mood === 'bad') row.style.background = 'rgba(248,81,73,.07)';
      if (r.danger) row.style.borderLeft = '2px solid #f85149';
      row.onmouseenter = () => { row.style.background = mood === 'bad' ? 'rgba(248,81,73,.14)' : '#161b22'; };
      row.onmouseleave = () => { row.style.background = mood === 'bad' ? 'rgba(248,81,73,.07)' : 'transparent'; };

      const l1 = document.createElement('div');
      Object.assign(l1.style, { display: 'flex', alignItems: 'center', gap: '8px' });
      const chip = document.createElement('span');
      chip.textContent = r.busy ? '⏳' : (r.icons || '·');
      Object.assign(chip.style, { flex: '0 0 auto', background: cs.bg, color: cs.fg, borderRadius: '5px', padding: '2px 5px', fontSize: '11px', whiteSpace: 'nowrap' });
      const host = document.createElement('span');
      host.textContent = r.host;
      Object.assign(host.style, { flex: '1 1 auto', minWidth: '0', overflowWrap: 'anywhere', color: mood === 'bad' ? '#ffb0ac' : '#e6edf3' });
      l1.append(chip, host);
      if (r.ms) { const ms = document.createElement('span'); ms.textContent = r.ms + 'мс'; Object.assign(ms.style, { flex: '0 0 auto', color: '#8b949e', fontSize: '10px' }); l1.append(ms); }
      if (hasGM && r.host && r.host.includes('.')) {
        const rb = document.createElement('span');
        rb.textContent = '🌍';
        rb.title = 'Регион-чек: блокировки по РФ через cheburcheck.ru (~1-2 мин, кэш 6 ч)';
        Object.assign(rb.style, { flex: '0 0 auto', cursor: 'pointer', opacity: '.8', fontSize: '12px' });
        rb.onmouseenter = () => { rb.style.opacity = '1'; };
        rb.onmouseleave = () => { rb.style.opacity = '.8'; };
        rb.onclick = (ev) => { ev.stopPropagation(); if (!chbQueue.includes(r.host)) chbQueue.push(r.host); chbPump(); };
        l1.append(rb);
      }
      row.append(l1);
      // вторая строка — подробности (маршрут, регион, хостинг), только если есть что сказать
      const extra = (r.tag || '').trim();
      if (extra) {
        const l2 = document.createElement('div');
        l2.textContent = extra;
        Object.assign(l2.style, { fontSize: '10px', lineHeight: '1.45', color: '#8b949e', paddingLeft: '38px', overflowWrap: 'anywhere' });
        row.append(l2);
        row.title = extra;
      }
      if (r.click) row.onclick = () => { if (!hasGM) return; loadLists(false).then(() => { queue.push(r.click); runChecks(); }); };
      return row;
    };

    const rowsFor = () => {
      const out = [];
      if (!rootOnly) {
        for (const h of domains.keys()) {
          const s = info.get(h) || {};
          const parts = [];
          let danger = !!(s.status && s.status.blocked && s.route && s.route.direct);
          if (danger) parts.push('🔴 заблокирован и НЕ в прокси — добавьте в список');
          if (s.route) parts.push(s.route.direct ? '⬇' + (s.route.inferred ? '?' : '') + ' напрямую' + (s.route.rule ? ' [' + s.route.rule + ']' : '') : '🚀' + (s.route.inferred ? '?' : '') + ' ' + s.route.via);
          const ct = chbTag(s);
          if (ct) parts.push(ct);
          if (s.status) parts.push(s.status.tag);
          const blocked = !!(s.status && s.status.blocked);
          out.push({
            host: h,
            icons: (danger ? '🔴' : '') + (s.status ? s.status.icons : '') + (s.route ? ((s.route.direct ? '⬇' : '🚀') + (s.route.inferred ? '?' : '')) : '') + (s.reg && s.reg.total && s.reg.winner && CHB_V[s.reg.winner] ? CHB_V[s.reg.winner].i : ''),
            tag: parts.join(' · '),
            blocked,
            danger,
            st: (blocked || danger) ? 'bad' : (s.status && !s.status.blocked ? 'ok' : 'none'),
            ms: s.ms || null,
            busy: !!s.busy,
            click: hasGM ? h : null,
          });
        }
      } else {
        const map = new Map();
        for (const h of domains.keys()) {
          const r = getRoot(h);
          let e = map.get(r);
          if (!e) { e = { host: r, subs: 0, blocked: 0, checked: 0, icons: '', prox: 0, direct: 0 }; map.set(r, e); }
          e.subs++;
          const s = info.get(h);
          if (s && s.status) { e.checked++; if (s.status.blocked) e.blocked++; if (s.status.icons) e.icons += s.status.icons; }
          if (s && s.route) {
            if (s.route.direct) e.direct++; else e.prox++;
            const mark = (s.route.direct ? '⬇' : '🚀') + (s.route.inferred ? '?' : '');
            if (!e.icons.includes(mark)) e.icons += mark;
          }
        }
        for (const e of map.values()) {
          const parts = [];
          if (e.prox || e.direct) parts.push((e.prox ? e.prox + '🚀' : '') + (e.direct ? ' ' + e.direct + '⬇' : '') + ' из ' + e.subs);
          if (e.blocked) parts.push(e.blocked + '/' + e.subs + ' заблок.');
          else if (e.checked) parts.push('ок');
          out.push({ host: e.host, icons: e.icons, tag: parts.join(' · '), blocked: e.blocked > 0, danger: e.blocked > 0 && e.direct > 0 && e.prox === 0, st: e.blocked > 0 ? 'bad' : (e.checked && !e.blocked ? 'ok' : 'none'), ms: null, busy: false, click: null });
        }
      }
      // проблемные — всегда сверху
      out.sort((a, b) => ((b.blocked ? 1 : 0) - (a.blocked ? 1 : 0)) || ((b.danger ? 1 : 0) - (a.danger ? 1 : 0)) || getRoot(a.host).localeCompare(getRoot(b.host)) || a.host.localeCompare(b.host));
      return out;
    };

    const defaultStatus = () => {
      if (statusMsg) return statusMsg;
      if (CHB.busy) return '🌍 Регион-чек ' + CHB.active + ': ответов ' + CHB.parts + (CHB.online ? ' / ' + CHB.online + ' сканеров' : '') + (chbQueue.length ? ' · в очереди ' + chbQueue.length : '');
      if (running) return '⏳ Проверяю: осталось ' + queue.length + '…';
      if (REG.loading) return '⏳ Загружаю списки реестра…';
      if (REG.t) return '📋 Реестр: ' + REG.domCount.toLocaleString('ru-RU') + ' дом., ' + REG.netCount.toLocaleString('ru-RU') + ' подсетей · от ' + new Date(REG.t).toLocaleString('ru-RU');
      if (REG.err) return '⚠️ ' + REG.err + ' — проверка только живыми пробами';
      if (!hasGM) return '⚠️ GM_xmlhttpRequest недоступен — чек блокировок не работает';
      return 'Домены: ' + domains.size + ' · «🚫 Проверить» — проверить блокировки';
    };

    let lastSig = '';
    const render = () => {
      const all = rowsFor();
      const badN = all.filter((r) => r.st === 'bad').length;
      const okN = all.filter((r) => r.st === 'ok').length;
      const rows = viewFilter === 'all' ? all : all.filter((r) => r.st === viewFilter);
      pill.textContent = '🌐 ' + all.length + (badN ? ' ⛔' + badN : '');
      pill.style.color = badN ? '#f85149' : '#58a6ff';
      title.textContent = (rootOnly ? 'Корневые: ' : 'Домены: ') + all.length;
      checkBtn.textContent = running ? '⏹ Стоп (' + queue.length + ')' : '🚫 Проверить';
      chipAll.textContent = 'Все · ' + all.length;
      chipBad.textContent = '⛔ Проблемные · ' + badN;
      chipOk.textContent = '✅ Доступные · ' + okN;
      for (const [c, k] of [[chipAll, 'all'], [chipBad, 'bad'], [chipOk, 'ok']]) {
        c.style.background = viewFilter === k ? '#1f6feb' : '#21262d';
        c.style.borderColor = viewFilter === k ? '#388bfd' : '#30363d';
      }
      help.style.display = showHelp ? 'block' : 'none';
      list.style.display = showHelp ? 'none' : 'block';
      helpBtn.style.background = showHelp ? '#1f6feb' : '#21262d';
      const sig = JSON.stringify([rootOnly, statusMsg, running, queue.length, REG.t, REG.err, viewFilter, showHelp, all.length, badN, okN, rows.map((r) => [r.host, r.icons, r.tag, r.blocked, r.busy])]);
      if (sig !== lastSig) {
        lastSig = sig;
        list.textContent = '';
        const frag = document.createDocumentFragment();
        if (!rows.length) {
          const d = document.createElement('div');
          d.textContent = all.length
            ? (viewFilter === 'bad' ? 'Проблемных доменов не найдено 🎉' : 'В этой категории пусто')
            : 'Пока пусто: домены появятся, когда сайт начнёт что-то загружать. Нажмите «🚫 Проверить», чтобы проверить найденные.';
          Object.assign(d.style, { color: '#8b949e', padding: '6px 2px' });
          frag.append(d);
        } else {
          rows.forEach((r) => frag.append(mkRow(r)));
        }
        list.append(frag);
      }
      const rt = ROUTE.ok
        ? '🛣 ' + ROUTE.base.replace(/^https?:\/\//, '') + (ROUTE.lastPoll ? ' · опрос ' + new Date(ROUTE.lastPoll).toLocaleTimeString('ru-RU') : '')
        : (hasGM ? '🛣 Clash API не найден — авто-поиск ПК/роутер, задайте вручную (⚙)' : '');
      const rtxt = [rt, echoText()].filter(Boolean).join('  |  ');
      if (routebar.textContent !== rtxt) routebar.textContent = rtxt;
      const st = defaultStatus();
      if (statusbar.textContent !== st) statusbar.textContent = st;
    };
    renderFn = render;

    const syncVisibility = () => { pill.style.display = isOpen ? 'none' : 'block'; box.style.display = isOpen ? 'block' : 'none'; };
    pill.onclick = () => { isOpen = true; setOpen(true); syncVisibility(); if (ROUTE.ok) startRoutePolling(); render(); };
    helpBtn.onclick = () => { showHelp = !showHelp; render(); };
    minBtn.onclick = () => { isOpen = false; setOpen(false); stopRoutePolling(); syncVisibility(); };
    reloadBtn.onclick = () => { saveNow(); isOpen = true; setOpen(true); location.reload(); };
    modeBtn.onclick = () => { rootOnly = !rootOnly; modeBtn.textContent = rootOnly ? 'Корневые' : 'Поддомены'; render(); };
    clearBtn.onclick = () => { domains.clear(); info.clear(); queue.length = 0; try { sessionStorage.removeItem(SKEY); } catch {} render(); };
    copyBtn.onclick = async () => {
      const text = getListText();
      try { await navigator.clipboard.writeText(text); } catch {
        try {
          const ta = document.createElement('textarea');
          ta.value = text;
          Object.assign(ta.style, { position: 'fixed', left: '-9999px', top: '0' });
          document.documentElement.appendChild(ta);
          ta.select(); document.execCommand('copy'); ta.remove();
        } catch {}
      }
      copyBtn.textContent = 'Готово ✓';
      setTimeout(() => { copyBtn.textContent = 'Копировать'; }, 1200);
    };
    checkBtn.onclick = () => { checkAll(); };
    chbBtn.onclick = () => {
      const h = String(location.hostname || '');
      if (!h.includes('.')) { statusMsg = '🌍 Регион-чек доступен только для доменов'; renderSoon(); setTimeout(() => { statusMsg = ''; renderSoon(); }, 6000); return; }
      if (!chbQueue.includes(h)) chbQueue.push(h);
      chbPump();
    };

    btnGroup.append(reloadBtn, modeBtn, copyBtn, checkBtn, chbBtn, gearBtn, helpBtn, clearBtn, minBtn);
    header.append(title, btnGroup);
    box.append(header, filters, list, help, statusbar, routebar, settings);
    document.documentElement.append(pill, box);
    syncVisibility();
    render();
    if (hasGM) { detectRoute(); echoCheck(); } // найти Clash API (ПК/роутер) и выходной IP
    renderSoon(); // дорисовать после restore и т.п.
  };

  // ────────────────── СТАРТ ──────────────────
  restore();
  addUrl(location.href);
  patchPage();
  if (isTop) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initUI, { once: true });
    else initUI();
  }
})();
