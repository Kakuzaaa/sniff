// ==UserScript==
// @name         Domain Sniffer Pro — сбор доменов + детектор блокировок (РФ)
// @namespace    http://tampermonkey.net/
// @version      4.13
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
// @updateURL    https://cdn.jsdelivr.net/gh/Kakuzaaa/sniff@main/domain-sniffer-pro.user.js
// @downloadURL  https://cdn.jsdelivr.net/gh/Kakuzaaa/sniff@main/domain-sniffer-pro.user.js
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

  ПРОВЕРКА БЛОКИРОВОК (кнопка «Проверить», нужен Tampermonkey/Violentmonkey):
   1. Реестр: списки-зеркала antifilter.download (domains.lst + subnet.lst
      + ip.lst), кэш на 12 ч в GM-хранилище. Проверяем и домен, и его IP
      (IP резолвим через DNS-over-HTTPS — так видны блоки хостингов
      типа Hetzner/Cloudflare по подсетям).
   2. Живые пробы GM_xmlhttpRequest к самому домену (без cookie), бейдж
      статуса = цветная точка + короткая подпись:
      • сброс соединения сразу        → ● DPI — похоже на DPI (по SNI);
      • HTTPS сброс, а HTTP отвечает  → ● DPI — почти наверняка DPI по SNI;
      • нет ответа (таймаут)          → ● IP — полная блокировка по IP;
      • обрыв после ~12–64КБ          → ● 16-20КБ — «частичная» блокировка;
      • устойчивая скорость < 16КБ/с  → ● медленно — замедление. Меряем
        ПОСЛЕ первых 16КБ (TTFB/«сервер думает» не учитывается) и только
        если получено ≥48КБ; таймаут с данными = «очень медленно» или
        «встало после NКБ», а НЕ «полная блокировка»;
      • успешный ответ                → ● OK — доступен.
   Способ блокировки в реестре не публикуется, поэтому тип определяется
   по фактическому поведению сети У ВАШЕГО провайдера — это эвристика.

  МАРШРУТ КАЖДОГО ДОМЕНА (через прокси или напрямую):
   • Если на роутере (Podkop / Forkop / NetShift) или локально на ПК
     (sing-box / clash / v2rayN с clash-api) включён Clash API
     (external_controller, обычно порт 9090 — в Podkop это «YACD /
     дашборд»), скрипт читает /connections и показывает для каждого
     домена: «через прокси» (с какой цепочкой) или «напрямую» и
     по какому правилу. Проба из «Чека» сама создаёт соединение,
     поэтому маршрут определяется и для доменов, которые сайт не грузит.
   • Без Clash API — только косвенно: сравниваем IP, который видят
     зарубежный и RU-сервис (детект сплит-маршрутизации и VPN-выхода).
     Поточечный маршрут в этом случае узнать нельзя.
   • красный бейдж «не в прокси» — домен блокируется, но в
     прокси-лист роутера не попал: вот почему сайт не работает.
   • БЕЗ Clash API — два косвенных признака (метки со знаком «?»):
     1) реестр + проба: домен в реестре, но доступен → скорее идёт
        через прокси; в реестре и блокируется → скорее напрямую;
     2) RU-хостинг + задержка: <60мс — как локально (напрямую),
        >90мс — как из-за границы (через зарубежный выход VPN).
        Гео IP берётся у ip-api.com, задержка — из живой пробы.
     CDN и европейские цели так не различить (RTT совпадает).

  РЕГИОНАЛЬНАЯ ПРОВЕРКА (кнопка «Регионы» или иконка глобуса на строке):
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
    slowBytesPerSec: 16 * 1024, // устойчивая скорость ниже → «медленно» (замедление)
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
    sanity: { hosts: ['ya.ru', 'vk.com', 'sberbank.com'], ttl: 10 * 60 * 1000 }, // контрольные точки достоверности
    post16TimeoutMs: 10000, // POST 64КБ: таймаут = TSPU обрезает исходящий поток
    tspu: { timeoutMs: 10000, hosts: [ // тестовые хосты на подсетях крупных провайдеров (из suite.json hyperion-cs)
      { p: 'Cloudflare', h: 'img.wzstats.gg' },
      { p: 'DigitalOcean', h: 'carishealthcare.com' },
      { p: 'Fastly', h: 'ssl.p.jwpcdn.com' },
      { p: 'AWS', h: 'www.getscope.com' },
      { p: 'Contabo', h: 'www.cateringexner.cz' },
    ] },
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
  const domains = new Map(); // host → { net: реально загружался, dom: был ссылкой в DOM }
  const info = new Map();    // host → { status:{primary,tag,blocked}, busy }
  let rootOnly = false;
  let linkOnly = (() => { try { return gmGet('__dsnf3_linkonly', true) !== false; } catch { return true; } })(); // по умолчанию «Только трафик»
  let statusMsg = '';
  const SANITY = { t: 0, ok: [], fail: [] }; // контрольные точки последней «Проверить»

  // пользовательский игнор-лист (маски с *) и режим сбора ссылок со страницы
  const parseIgnore = (txt) => String(txt || '').split('\n').map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith('#'));
  const ignoreMatch = (host, arr) => {
    for (const m of arr) {
      if (m.indexOf('*') === -1) { if (host === m || host.endsWith('.' + m)) return true; }
      else {
        try { if (new RegExp('^' + m.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$').test(host)) return true; } catch {}
      }
    }
    return false;
  };
  const IGNORE = { arr: parseIgnore((() => { try { return gmGet('__dsnf3_ignore', ''); } catch { return ''; } })()) };
  let LINKMODE = (() => { try { const v = gmGet('__dsnf3_linkmode', 'all'); return v === 'internal' || v === 'off' ? v : 'all'; } catch { return 'all'; } })(); // all | internal | off

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

  // мост iframe → верхний фрейм (передаём и источник: 'net' сильнее 'dom')
  let sendTimer = 0; const pendingSend = new Map();
  const flushSend = () => {
    if (!pendingSend.size) return;
    const hosts = [...pendingSend].map(([h, s]) => [h, s]);
    pendingSend.clear();
    try { window.top.postMessage({ __dsnf3: hosts }, '*'); } catch {}
  };
  const scheduleSend = () => { if (sendTimer) return; sendTimer = setTimeout(() => { sendTimer = 0; flushSend(); }, 700); };

  const addHost = (rawHost, src) => {
    src = src === 'dom' ? 'dom' : 'net'; // по умолчанию считаем трафиком
    const host = String(rawHost || '').toLowerCase().trim().replace(/\.$/, '');
    if (!host || host === 'localhost') return false;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return false;          // IPv4 — не домен
    if (host.includes(':') || host.includes('[')) return false;      // IPv6
    if (!/^[a-z0-9._-]+$/.test(host)) return false;                  // посторонние символы
    if (!host.includes('.')) return false;                           // односоставные имена (интранет)
    if (IGNORE.arr.length && ignoreMatch(host, IGNORE.arr)) return false; // пользовательский игнор-лист: не собирать вовсе
    if (src === 'dom') {                                             // режим сбора ссылок со страницы
      if (LINKMODE === 'off') return false;
      if (LINKMODE === 'internal' && getRoot(host) !== getRoot(location.hostname)) return false;
    }
    const rec = domains.get(host);
    if (rec) { rec[src] = true; return false; }                      // источник дополняем даже у знакомых
    domains.set(host, { net: src === 'net', dom: src === 'dom' });
    if (!isTop) {
      const prev = pendingSend.get(host);
      if (prev !== 'net') pendingSend.set(host, src);
      scheduleSend();
    }
    scheduleSave(); renderSoon();
    return true;
  };

  const addUrl = (raw, src) => {
    if (!raw || typeof raw !== 'string') return;
    const s = raw.trim();
    try {
      const u = new URL(s, baseHref());
      if (u.protocol === 'http:' || u.protocol === 'https:' || u.protocol === 'ws:' || u.protocol === 'wss:') { addHost(u.hostname, src); return; }
      // stun:/turn: пишутся без «//», URL их не парсит — вытаскиваем вручную
      if (/^(stun|stuns|turn|turns):/i.test(u.protocol)) {
        const m = /^[a-z]+:(?:\/\/)?([^/:?]+)/i.exec(s);
        if (m) addHost(m[1], src);
      }
    } catch {}
  };
  if (isTop) { try { window.addEventListener('message', (e) => { const d = e && e.data; if (d && Array.isArray(d.__dsnf3)) d.__dsnf3.forEach((p) => addHost(p[0], p[1])); }); } catch {} }

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
  try {
    new PerformanceObserver((l) => {
      l.getEntries().forEach((e) => {
        // спекулятивные запросы Chrome (prefetch/prerender ссылок из выдачи) —
        // по смыслу это «ссылки», а не трафик страницы
        const spec = e.deliveryType === 'prefetch' || e.deliveryType === 'prerender';
        addUrl(e.name, spec ? 'dom' : 'net');
      });
    }).observe({ type: 'resource', buffered: true });
  } catch {}

  // ────────────────── СКАН DOM И CSS ──────────────────
  const URL_RE = /url\(\s*['"]?([^'")]+)['"]?\s*\)/gi;
  const cssTextUrls = (txt) => {
    if (!txt) return;
    URL_RE.lastIndex = 0;
    let m; while ((m = URL_RE.exec(txt))) { try { addUrl(m[1], 'dom'); } catch {} }
  };

  const ATTRS = ['src', 'href', 'data-src', 'data-href', 'poster', 'action', 'formaction', 'data', 'background'];
  const SEL = '[src],[href],[data-src],[data-href],[poster],[action],[formaction],[data],[srcset],[style]';
  const scanEl = (el) => {
    try {
      const g = (a) => { const v = el.getAttribute && el.getAttribute(a); return v || ''; };
      for (const a of ATTRS) { const v = g(a); if (v) addUrl(v, 'dom'); }
      const ss = g('srcset'); if (ss) ss.split(',').forEach((p) => addUrl(p.trim().split(/\s+/)[0], 'dom'));
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
        p: s.status.primary || '', t: s.status.tag, b: s.status.blocked ? 1 : 0,
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
      (d.hosts || []).forEach((h) => addHost(h, 'dom')); // источник уточнится реальным трафиком при загрузке
      const st = d.st || {};
      for (const h of Object.keys(st)) {
        const r = st[h].r, c = st[h].c, s = st[h].s;
        info.set(h, {
          status: { primary: st[h].p || '', tag: st[h].t, blocked: !!st[h].b },
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
      return 'Подключено: ' + ROUTE.base + (ROUTE.ver ? ' (ядро ' + ROUTE.ver + ')' : '');
    }
    return 'Не отвечает. Включите Clash API/дашборд на роутере (обычно порт 9090) и проверьте адрес.';
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
    if (e.cf && e.ru && e.cf.ip && e.ru.ip && e.cf.ip !== e.ru.ip) return 'Выход: ' + f + r + ' → сплит-маршрутизация';
    if (e.cf && e.cf.loc && e.cf.loc !== 'RU') return 'Выход: ' + f + r + ' → через VPN/прокси';
    return 'Выход: ' + f + r;
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
  const CHB = { busy: false, active: '', parts: 0, online: 0, startedAt: 0, abort: null, cancelled: false };
  const chbQueue = [];

  const CHB_V = {
    sni_block:    { t: 'SNI-блок (DPI)' },
    tspu_block:   { t: 'ТСПУ-блок (IP)' },
    dns_spoofing: { t: 'подмена DNS' },
    cdn_block:    { t: 'CDN-блок (16-20КБ)' },
    whitelist:    { t: 'в белом списке' },
    ok:           { t: 'доступен' },
    uncertain:    { t: 'неясно' },
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
    const pos = { last: 0, ev: null };
    // SSE-скан: отмена через статус-бар + сторож тишины (60с без единого байта → обрыв, не ждём 180с)
    let gotBytes = false;
    const b = await new Promise((resolve) => {
      let handle = null;
      const done = (v) => { clearTimeout(watchdog); resolve(v); };
      const watchdog = setTimeout(() => { if (!gotBytes) { try { handle && handle.abort(); } catch {} } }, 60000);
      try {
        handle = GM_xmlhttpRequest({
          url: CFG.chb.base + '/api/v1/probe/' + encodeURIComponent(j.id),
          method: 'GET', timeout: CFG.chb.probeTimeoutMs,
          headers: { accept: 'text/event-stream' },
          onprogress: (e) => {
            if (e.responseText && e.responseText.length) { gotBytes = true; clearTimeout(watchdog); }
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
            done({ ok: true, r });
          },
          onerror: () => done({ ok: false, aborted: false }),
          ontimeout: () => done({ ok: false, aborted: false, timeout: true }),
          onabort: () => done({ ok: false, aborted: true }),
        });
      } catch (err) { done({ ok: false, aborted: false }); }
      CHB.abort = () => { try { handle && handle.abort(); } catch {} };
    });
    CHB.abort = null;
    if (!b.ok && !probes.length && !CHB.cancelled) throw new Error(gotBytes ? 'cheburcheck: скан не удался' : 'cheburcheck: поток скана молчит (сервис перегружен?)');
    const agg = chbAgg(probes);
    if (agg.total) gmSet('__dsnf3_chbp_' + host, { t: Date.now(), c: agg.counts, n: agg.total, w: agg.winner });
    return { stat, agg, parts: probes.length };
  };

  const chbPump = async () => {
    if (CHB.busy) return;
    const host = chbQueue.shift();
    if (!host || !hasGM) return;
    CHB.busy = true; CHB.active = host; CHB.parts = 0; CHB.online = 0; CHB.startedAt = Date.now(); CHB.cancelled = false;
    const tick = setInterval(() => { if (CHB.busy) renderSoon(); else clearInterval(tick); }, 1000); // живой таймер в статус-баре
    const st = info.get(host) || {}; info.set(host, st);
    st.chbBusy = true; delete st.regErr; renderSoon();
    try {
      const c = gmGet('__dsnf3_chbp_' + host, null);
      if (c && c.t && Date.now() - c.t < CFG.chb.probeTtlMs && c.n) {
        st.reg = { counts: c.c, total: c.n, winner: c.w, cached: true }; // свежий кэш — не дёргаем сканеры
        const cs = gmGet('__dsnf3_chbs_' + host, null);
        if (cs && cs.d) st.regStatic = cs.d;
      } else {
        let res = null, failMsg = '';
        for (let attempt = 1; attempt <= 2 && !CHB.cancelled; attempt++) {
          try {
            res = await chbScan(host, ({ stat, agg }) => {
              st.regStatic = stat;
              if (agg && agg.total) { st.reg = agg; renderSoon(); }
            });
            if (res.agg && res.agg.total) break;
            failMsg = 'сканеры не ответили';
          } catch (err) {
            if (CHB.cancelled) break;
            failMsg = String((err && err.message) || err || 'ошибка скана');
          }
          if (attempt < 2) { st.regErr = failMsg + ' — пробую ещё раз…'; renderSoon(); }
        }
        st.regStatic = res && res.stat ? res.stat : st.regStatic;
        if (res && res.agg && res.agg.total) {
          st.reg = res.agg;
        } else if (!CHB.cancelled) {
          const old = gmGet('__dsnf3_chbp_' + host, null);
          if (old && old.n) {
            st.reg = { counts: old.c, total: old.n, winner: old.w, cached: true };
          } else {
            st.regErr = failMsg;
            statusMsg = 'Регион-чек ' + host + ': ' + failMsg + ' — сервис перегружен, попробуйте позже'; renderSoon();
            setTimeout(() => { if (statusMsg.indexOf('Регион-чек') === 0) { statusMsg = ''; renderSoon(); } }, 12000);
            setTimeout(() => { delete st.regErr; renderSoon(); }, 12000);
          }
        }
      }
    } catch (e) {
      if (!CHB.cancelled) { // при отмене не пугаем пользователя ошибкой
        const c = gmGet('__dsnf3_chbp_' + host, null);
        if (c && c.n) st.reg = { counts: c.c, total: c.n, winner: c.w, cached: true };
        else st.regErr = String((e && e.message) || e || 'ошибка региональной проверки');
        setTimeout(() => { delete st.regErr; renderSoon(); }, 10000);
      }
    } finally {
      st.chbBusy = false; CHB.busy = false; CHB.active = ''; renderSoon();
      if (chbQueue.length) chbPump();
    }
  };

  const chbTag = (st) => {
    if (st.chbBusy) return 'Регион-чек: сканирую… ' + Math.max(0, Math.round((Date.now() - CHB.startedAt) / 1000)) + 'с' + (CHB.parts ? ' · ' + CHB.parts + (CHB.online ? '/' + CHB.online : '') + ' сканеров' : '');
    if (st.regErr) return 'Регион-чек: ' + st.regErr;
    if (!st.reg || !st.reg.total) return '';
    const a = st.reg;
    const w = CHB_V[a.winner];
    const top = CHB_PRIO.filter((v) => a.counts[v]).slice(0, 4).map((v) => (CHB_V[v] ? CHB_V[v].t : '?') + ' ' + a.counts[v]).join(', ');
    let s = 'Регионы РФ: ' + (w ? w.t : 'неясно') + ' (' + top + ') · ' + a.total + ' сканеров' + (a.cached ? ' · кэш' : '');
    const rs = st.regStatic;
    if (rs) {
      if (rs.blocked) s += ' · в списках cheburcheck';
      if (rs.cdn && rs.cdn.length) s += ' · хостинг: ' + rs.cdn.join(', ');
      else if (rs.loc) s += ' · хостинг: ' + rs.loc;
    }
    return s;
  };

  // ────────────────── ПОДТВЕРЖДЕНИЕ TSPU 16-20 ИСХОДЯЩИМ POST (методика hyperion-cs/dpi-checkers) ──────────────────
  // ТСПУ считает байты соединения в ОБЕ стороны: живой хост + POST 64КБ, который
  // обрезается по таймауту без ответа = детерминированный вердикт «заморозки»,
  // не зависящий от размера страницы сайта.
  let POST_BODY = null;
  const getPostBody = () => {
    if (!POST_BODY) {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      let s = '';
      for (let i = 0; i < 68 * 1024; i++) s += chars[(Math.random() * chars.length) | 0];
      POST_BODY = s;
    }
    return POST_BODY;
  };
  const probePost16 = (url) => new Promise((res) => {
    let t0 = performance.now(), done = false;
    const finish = (o) => { if (done) return; done = true; res(Object.assign({ ms: performance.now() - t0 }, o)); };
    try {
      GM_xmlhttpRequest({
        url: url + (url.includes('?') ? '&' : '?') + '_dpich=' + Math.floor(Math.random() * 1e9),
        method: 'POST', timeout: CFG.post16TimeoutMs, anonymous: true,
        headers: { 'Content-Type': 'text/plain' },
        data: getPostBody(),
        onload: (r) => finish({ kind: 'ok', status: r.status }),
        onerror: () => finish({ kind: 'err' }),
        ontimeout: () => finish({ kind: 'timeout' }),
        onabort: () => finish({ kind: 'abort' }),
      });
    } catch (e) { finish({ kind: 'err' }); }
  });

  // ────────────────── TSPU-ТЕСТ ПРОВАЙДЕРА (по suite.json hyperion-cs/dpi-checkers) ──────────────────
  const TSPU = { busy: false, last: '' };
  const runTspuTest = async () => {
    if (!hasGM || TSPU.busy) return;
    TSPU.busy = true;
    statusMsg = 'Проверка доступности зарубежных хостингов: отправляем 64 КБ данных на 5 популярных хостингов (Cloudflare, AWS, Fastly…), смотрим, где обрыв…'; renderSoon();
    const res = await Promise.all(CFG.tspu.hosts.map(async ({ p, h }) => {
      const alive = await probeUrl('https://' + h + '/', 'HEAD');
      if (alive.kind !== 'ok' && alive.kind !== 'abort') return { p, st: 'dead' };
      const post = await probePost16('https://' + h + '/');
      return { p, st: (post.kind === 'timeout' || post.kind === 'abort') ? 'cut' : 'ok' };
    }));
    const cut = res.filter((r) => r.st === 'cut').map((r) => r.p);
    const dead = res.filter((r) => r.st === 'dead').map((r) => r.p);
    const aliveN = res.filter((r) => r.st !== 'dead').length;
    TSPU.busy = false;
    // детализация по каждой подсети — показывается в тултипе статус-бара и кнопки
    TSPU.last = 'детализация: ' + res.map((r) => r.p + ' — ' + (r.st === 'cut' ? 'ОБРЕЗАН (заморозка)' : r.st === 'dead' ? 'недоступен' : 'прошёл')).join('; ');
    let msg;
    const okList = res.filter((r) => r.st === 'ok').map((r) => r.p);
    if (aliveN === 0) {
      msg = 'Проверка доступности хостингов: ни один из 5 зарубежных хостингов не ответил — проверьте свою сеть и VPN. ' + TSPU.last;
    } else if (cut.length >= 2) {
      msg = 'Доступность зарубежных хостингов: НЕДОСТУПНЫ ПОЛНОСТЬЮ (обрыв после ~16-20 КБ): ' + cut.join(', ') + '. Сайты, хостящиеся на них, будут открываться не полностью: текст есть, а картинки, файлы и видео не догружаются. Решение: добавить такие сайты в VPN/прокси-лист роутера. Доступны: ' + (okList.join(', ') || 'никакие') + '. ' + TSPU.last;
    } else if (cut.length === 1) {
      msg = 'Доступность зарубежных хостингов: ' + cut[0] + ' отвечает на запросы, но передача данных обрывается после ~16-20 КБ — «заморозка» действует на эту подсеть. Сайты, хостящиеся на ' + cut[0] + ', будут открываться не полностью. Доступны: ' + (okList.join(', ') || 'никакие') + '. Повторите тест — результат должен повториться (если нет — хост просто был медленным в тот момент). ' + TSPU.last;
    } else {
      msg = 'Доступность зарубежных хостингов: все ' + aliveN + ' проверенных хостингов доступны, обрывов передачи нет — «заморозка» у вашего провайдера не применяется. ' + TSPU.last;
    }
    statusMsg = msg; renderSoon();
    setTimeout(() => { if (statusMsg === msg) { statusMsg = ''; renderSoon(); } }, 30000);
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
  const probeUrl = (url, method) => new Promise((res) => {
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
        url, method: method || 'GET', timeout: CFG.probeTimeoutMs, anonymous: true,
        onprogress: (e) => {
          if (e.loaded > loaded) {
            loaded = e.loaded; lastBumpT = performance.now();
            if (anchorB < 0 && loaded >= CFG.slowSkipBytes) { anchorB = loaded; anchorT = lastBumpT; }
            if (loaded >= CFG.probeMaxBody && ctrl) { try { ctrl.abort(); } catch {} }
          }
        },
        onload: (r) => finish({ kind: 'ok', status: r.status, resp: (r.responseText || '').slice(0, 4000) }),
        onerror: (e) => finish({ kind: 'err', err: String((e && e.error) || '') }),
        ontimeout: () => finish({ kind: 'timeout' }),
        onabort: () => finish({ kind: 'abort' }),
      });
    } catch (e) { finish({ kind: 'err', err: String(e) }); }
  });

  // сетевой вердикт → бейдж {текст, цвет}; 'reg'/'regip' — только реестр без живой пробы
  const KIND_META = {
    ok:      { t: 'OK',      c: '#3fb950' },
    dpi:     { t: 'DPI',     c: '#f85149' },
    ip:      { t: 'IP',      c: '#f85149' },
    partial: { t: '16-20КБ', c: '#d29922' },
    stub:    { t: 'стаб-страница', c: '#d29922' },
    tear:    { t: 'обрыв',   c: '#d29922' },
    slow:    { t: 'медленно', c: '#d29922' },
    reg:     { t: 'в реестре', c: '#a371f7' },
    regip:   { t: 'IP-реестр', c: '#a371f7' },
  };
  const classify = (p1, p2, regDom, regIp, ips) => {
    const parts = [];
    if (regDom) parts.push({ k: 'reg', b: true, t: 'домен в реестре блокировок' });
    if (regIp) {
      const hit = (ips || []).filter(ipInReg).slice(0, 2).join(', ');
      parts.push({ k: 'regip', b: true, t: 'IP-подсеть в реестре' + (hit ? ' (' + hit + ')' : '') });
    }
    const okP2 = p2 && (p2.kind === 'ok' || p2.kind === 'abort');
    const maxLoaded = Math.max(p1 ? p1.loaded : 0, p2 ? p2.loaded : 0);
    const kb = (n) => Math.round(n / 1024);
    const rate = (p) => (p && p.sustained !== null ? ' · ~' + Math.round(p.sustained / 1024) + 'КБ/с' : '');
    if (p1 && (p1.kind === 'ok' || p1.kind === 'abort')) {
      if (p1.sustained !== null && p1.sustained < CFG.slowBytesPerSec && p1.loaded >= CFG.slowMinBytes) {
        parts.push({ k: 'slow', b: true, t: 'замедление (~' + Math.round(p1.sustained / 1024) + 'КБ/с устойчиво)' });
      }
      parts.push({ k: 'ok', b: false, t: (p1.kind === 'ok' ? 'доступен (HTTP ' + p1.status + ')' : 'доступен') + rate(p1) });
    } else if (okP2) {
      parts.push({ k: 'dpi', b: true, t: 'HTTPS не отвечает/сброшен, HTTP отвечает — похоже на DPI по SNI (или нет TLS)' + rate(p2) });
    } else if (p1 && p1.kind === 'timeout' && p1.loaded > 0) {
      // байты шли, но за таймаут не докачались: медленно или «встало» — НЕ «полная блокировка»
      if (p1.silentMs > CFG.stallSilentMs) {
        parts.push({ k: 'partial', b: true, t: 'встало после ~' + kb(p1.loaded) + 'КБ — частичная блокировка/обрыв' });
      } else {
        parts.push({ k: 'slow', b: true, t: 'очень медленно: ' + kb(p1.loaded) + 'КБ за ' + Math.round(p1.ms / 1000) + 'с' + rate(p1) });
      }
    } else if (maxLoaded >= CFG.partialMin && maxLoaded <= CFG.partialMax && ((p1 && p1.kind === 'err') || (p2 && p2.kind === 'err'))) {
      parts.push({ k: 'partial', b: true, t: 'обрыв после ~' + kb(maxLoaded) + 'КБ — частичная блокировка (16-20КБ)' });
    } else if (maxLoaded > CFG.partialMax && ((p1 && p1.kind === 'err') || (p2 && p2.kind === 'err'))) {
      parts.push({ k: 'tear', b: true, t: 'обрыв после ' + kb(maxLoaded) + 'КБ' + rate(p1 || p2) });
    } else if (p1 && p1.kind === 'timeout' && (!p2 || p2.kind === 'timeout')) {
      parts.push({ k: 'ip', b: true, t: 'нет ответа (0 байт) — похоже на полную блокировку по IP' });
    } else {
      parts.push({ k: 'dpi', b: true, t: 'сброс соединения — похоже на DPI' });
    }
    // первичный сетевой вердикт приоритетнее «сервисных» пометок реестра
    const NET_ORDER = ['dpi', 'ip', 'partial', 'tear', 'slow', 'ok'];
    const net = parts.map((p) => p.k).find((k) => NET_ORDER.includes(k));
    const primary = net || parts.map((p) => p.k).find((k) => k === 'reg' || k === 'regip') || 'reg';
    return { blocked: parts.some((p) => p.b), primary, tag: parts.map((p) => p.t).join(' · ') };
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
      // заглушка провайдера: маленький 200-ответ с маркерами блокировки (rkn-block-checker)
      if (p1 && p1.kind === 'ok' && p1.status === 200 && p1.resp && p1.resp.length < 15000 &&
          /ограничен доступ|заблокирова|запрещ[её]н|роскомнадзор|roskomnadzor|access (denied|restricted)|blocked by/i.test(p1.resp.slice(0, 3000))) {
        st.status.primary = 'stub';
        st.status.blocked = true;
        st.status.tag += ' · провайдер отдаёт заглушку вместо сайта';
      }
      // подтверждение TSPU 16-20 исходящим POST 64КБ (только для живых доменов)
      if (p1 && (p1.kind === 'ok' || p1.kind === 'abort')) {
        const post = await probePost16('https://' + host + '/');
        if (post.kind === 'timeout' || post.kind === 'abort') {
          st.status.primary = 'partial';
          st.status.blocked = true;
          st.status.tag += ' · подтверждено тестом: провайдер обрывает передачу данных (заморозка 16-20КБ)';
        } else if (post.kind === 'err') {
          // метод 2 hyperion: серия HEAD с ~7КБ в request line — накопление байтов аплинка
          const t02 = performance.now();
          let cut = false;
          while (performance.now() - t02 < 12000) {
            const rr = await probeUrl('https://' + host + '/?x=' + getPostBody().slice(0, 7 * 1024) + '&n=' + Math.floor(Math.random() * 1e9), 'HEAD');
            if (rr.kind !== 'ok') { cut = true; break; }
          }
          if (cut) {
            st.status.primary = 'partial';
            st.status.blocked = true;
            st.status.tag += ' · вероятно заморозка: обрыв при проверке передачи';
          }
        }
      }
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
    if (!hasGM) { statusMsg = 'Проверка недоступна: нужен Tampermonkey/Violentmonkey (GM_xmlhttpRequest)'; renderSoon(); return; }
    if (!REG.dom) {
      statusMsg = '⏳ Загружаю списки реестра (первый раз ~10-20 МБ, кэш 12 ч)…'; renderSoon();
      await loadLists(false);
      statusMsg = ''; renderSoon();
    }
    // контрольные точки: известные незаблокированные RU-сервисы (методика MayersScott/rkn-block-checker) —
    // если они не отвечают, значит сломана сеть/VPN, и все результаты проверки недостоверны
    const now = Date.now();
    if (!SANITY.t || now - SANITY.t > CFG.sanity.ttl) {
      statusMsg = 'Контрольные точки: проверяю ' + CFG.sanity.hosts.join(', ') + '…'; renderSoon();
      const res = await Promise.all(CFG.sanity.hosts.map(async (h) => {
        const p = await probeUrl('https://' + h + '/');
        return { h, ok: p.kind === 'ok' || p.kind === 'abort' };
      }));
      SANITY.t = now;
      SANITY.ok = res.filter((r) => r.ok).map((r) => r.h);
      SANITY.fail = res.filter((r) => !r.ok).map((r) => r.h);
      statusMsg = ''; renderSoon();
    }
    if (SANITY.fail && SANITY.fail.length) {
      statusMsg = 'Контрольные точки недоступны (' + SANITY.fail.join(', ') + ') — проверка всё равно пройдёт, но результаты могут быть недостоверны';
      renderSoon();
      setTimeout(() => { if (statusMsg.indexOf('Контрольные точки') === 0) { statusMsg = ''; renderSoon(); } }, 15000);
    }
    const list = [...domains.keys()].filter((h) => { const s = info.get(h); return !(s && s.status); });
    for (const h of list) if (!queue.includes(h)) queue.push(h);
    await runChecks();
  };

  // ────────────────── СПИСОК ДЛЯ КОПИРОВАНИЯ ──────────────────
  const getListText = () => {
    const arr = [...domains.keys()].filter((h) => { const rec = domains.get(h); return !linkOnly || (rec && rec.net); });
    const list = rootOnly ? [...new Set(arr.map(getRoot))] : arr;
    return list.sort((a, b) => getRoot(a).localeCompare(getRoot(b)) || a.localeCompare(b)).join('\n');
  };

  // ────────────────── ОЧИСТКА ПО ИГНОРУ/РЕЖИМУ ССЫЛОК ──────────────────
  const purgeIgnored = () => {
    let removed = 0;
    for (const h of [...domains.keys()]) {
      if (ignoreMatch(h, IGNORE.arr)) { domains.delete(h); info.delete(h); removed++; }
    }
    renderSoon();
    return removed;
  };
  const purgeLinkMode = () => {
    if (LINKMODE === 'all') return;
    for (const h of [...domains.keys()]) {
      const rec = domains.get(h);
      if (rec && !rec.net && (LINKMODE === 'off' || (LINKMODE === 'internal' && getRoot(h) !== getRoot(location.hostname)))) { domains.delete(h); info.delete(h); }
    }
    renderSoon();
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

    // ── Liquid Glass: тема (auto/dark/light), монохромные SVG-иконки вместо эмодзи ──
    const THEME_KEY = '__dsnf3_theme';
    let theme = (() => { try { return gmGet(THEME_KEY, 'auto'); } catch { return 'auto'; } })();
    let blurOK = true;
    try { blurOK = window.CSS && CSS.supports && (CSS.supports('backdrop-filter', 'blur(1px)') || CSS.supports('-webkit-backdrop-filter', 'blur(1px)')); } catch { blurOK = false; }
    const isLight = () => theme === 'light' || (theme === 'auto' && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);

    const ICONS = {
      globe: 'M8 2.6a5.4 5.4 0 1 1 0 10.8 5.4 5.4 0 0 1 0-10.8Zm-5.4 5.4h10.8M8 2.6c2 1.6 2 9.2 0 10.8M8 2.6c-2 1.6-2 9.2 0 10.8',
      copy: 'M10.5 3.5h-5a1 1 0 0 0-1 1v6m1 1h5.5a1 1 0 0 0 1-1v-6a1 1 0 0 0-1-1M2.5 5.5h5a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-5a1 1 0 0 1-1-1v-6a1 1 0 0 1 1-1Z',
      refresh: 'M13.3 6.7A5.6 5.6 0 1 0 13.9 9M13.6 2.6v3.4h-3.4',
      gear: 'M8 5.9A2.1 2.1 0 1 0 8 10.1 2.1 2.1 0 0 0 8 5.9ZM8 1.6v2M8 12.4v2M1.6 8h2M12.4 8h2M3.5 3.5l1.4 1.4M11.1 11.1l1.4 1.4M12.5 3.5l-1.4 1.4M4.9 11.1l-1.4 1.4',
      trash: 'M2.5 4.2h11M6.2 4.2V2.8h3.6v1.4M3.9 4.2l.5 8.4a1 1 0 0 0 1 .9h5.2a1 1 0 0 0 1-.9l.5-8.4M6.4 7v4m3.2-4v4',
      minus: 'M3.5 8h9',
      grip: 'M5.7 3.6v.01M5.7 6.5v.01M5.7 9.4v.01M5.7 12.3v.01M10.3 3.6v.01M10.3 6.5v.01M10.3 9.4v.01M10.3 12.3v.01',
      theme: 'M8 2.75A5.25 5.25 0 1 1 8 13.25 5.25 5.25 0 0 1 8 2.75Z|M8 2.75a5.25 5.25 0 0 1 0 10.5Z',
    };
    const svgIcon = (name, size) => {
      const NS = 'http://www.w3.org/2000/svg';
      const svg = document.createElementNS(NS, 'svg');
      svg.setAttribute('viewBox', '0 0 16 16');
      svg.setAttribute('width', size || 14); svg.setAttribute('height', size || 14);
      svg.setAttribute('fill', 'none');
      svg.setAttribute('stroke', 'currentColor');
      svg.setAttribute('stroke-width', '1.4');
      svg.setAttribute('stroke-linecap', 'round');
      svg.style.display = 'block';
      svg.style.flex = '0 0 auto';
      for (const d of (ICONS[name] || '').split('|')) {
        const p = document.createElementNS(NS, 'path');
        p.setAttribute('d', d);
        if (name === 'theme' && d.indexOf('M8 2.75a5.25') === 0) { p.setAttribute('fill', 'currentColor'); p.setAttribute('stroke', 'none'); }
        svg.append(p);
      }
      return svg;
    };

    const mkBtn = (label, hint, icon) => {
      const b = document.createElement('button');
      if (icon) b.append(svgIcon(icon, 14));
      if (label) {
        const sp = document.createElement('span');
        sp.textContent = label;
        if (icon) sp.style.marginLeft = '6px';
        b.append(sp);
      }
      if (hint) b.title = hint;
      Object.assign(b.style, { display: 'inline-flex', alignItems: 'center', justifyContent: 'center', background: 'var(--btn)', color: 'var(--txt)', border: '1px solid var(--border-soft)', borderRadius: '8px', padding: icon && !label ? '5px' : '4px 10px', cursor: 'pointer', font: 'inherit', fontSize: '11px', whiteSpace: 'nowrap', transition: 'background .12s ease' });
      b.onmouseenter = () => { b.style.background = 'var(--btn-hover)'; };
      b.onmouseleave = () => { b.style.background = 'var(--btn)'; };
      return b;
    };

    const pill = document.createElement('button');
    pill.id = '__dsnf3_pill';
    pill.title = 'Domain Sniffer: показать собранные домены';
    const pillDot = document.createElement('span');
    Object.assign(pillDot.style, { width: '8px', height: '8px', borderRadius: '50%', background: '#3fb950', flex: '0 0 auto' });
    const pillTxt = document.createElement('span');
    pillTxt.textContent = '0';
    Object.assign(pill.style, { position: 'fixed', bottom: '14px', right: '14px', zIndex: 2147483647, display: 'none', alignItems: 'center', gap: '7px', background: blurOK ? 'var(--glass)' : 'var(--glass-solid)', backdropFilter: blurOK ? 'blur(20px) saturate(1.5)' : 'none', WebkitBackdropFilter: blurOK ? 'blur(20px) saturate(1.5)' : 'none', color: 'var(--txt)', border: '1px solid var(--border)', borderRadius: '14px', padding: '8px 13px', font: '600 12px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace', cursor: 'pointer', boxShadow: 'var(--shadow)' });
    pill.append(pillDot, pillTxt);

    const box = document.createElement('div');
    box.id = '__dsnf3_box';
    Object.assign(box.style, { position: 'fixed', bottom: '14px', right: '14px', zIndex: 2147483647, width: '640px', maxWidth: 'calc(100vw - 20px)', maxHeight: 'calc(100vh - 24px)', display: 'none', flexDirection: 'column', background: blurOK ? 'var(--glass)' : 'var(--glass-solid)', backdropFilter: blurOK ? 'blur(24px) saturate(1.5)' : 'none', WebkitBackdropFilter: blurOK ? 'blur(24px) saturate(1.5)' : 'none', color: 'var(--txt)', border: '1px solid var(--border)', borderRadius: '16px', font: '12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace', boxShadow: 'var(--shadow), inset 0 1px 0 var(--hl)', padding: '12px' });

    // панель не должна вылезать за экран (например, при 125% зуме и открытом ⚙)
    const clampPanel = () => {
      try {
        const r = box.getBoundingClientRect();
        if (r.top < 8 || r.bottom > window.innerHeight - 8 || r.right > window.innerWidth - 4) {
          box.style.top = Math.max(8, Math.min(r.top, window.innerHeight - r.height - 8)) + 'px';
          box.style.left = Math.max(4, Math.min(r.left, window.innerWidth - r.width - 4)) + 'px';
          box.style.right = 'auto';
          box.style.bottom = 'auto';
        }
      } catch {}
    };
    window.addEventListener('resize', clampPanel);

    const applyTheme = () => {
      const L = isLight();
      const V = L ? {
        '--glass': 'rgba(255,255,255,.70)', '--glass-solid': 'rgba(250,250,251,.97)',
        '--border': 'rgba(0,0,0,.16)', '--border-soft': 'rgba(0,0,0,.09)',
        '--txt': '#1f2328', '--muted': '#59636e', '--accent': '#0969da',
        '--btn': 'rgba(0,0,0,.05)', '--btn-hover': 'rgba(0,0,0,.10)',
        '--list': 'rgba(0,0,0,.045)', '--row-hover': 'rgba(0,0,0,.06)',
        '--chip': 'rgba(0,0,0,.07)', '--bad': '#cf222e', '--badbg': 'rgba(207,34,46,.07)',
        '--hl': 'rgba(255,255,255,.65)', '--shadow': '0 16px 48px rgba(0,0,0,.22)',
      } : {
        '--glass': 'rgba(22,24,28,.82)', '--glass-solid': 'rgba(20,22,26,.96)',
        '--border': 'rgba(255,255,255,.16)', '--border-soft': 'rgba(255,255,255,.09)',
        '--txt': '#e6edf3', '--muted': '#9198a1', '--accent': '#4493f8',
        '--btn': 'rgba(255,255,255,.07)', '--btn-hover': 'rgba(255,255,255,.13)',
        '--list': 'rgba(0,0,0,.28)', '--row-hover': 'rgba(255,255,255,.06)',
        '--chip': 'rgba(255,255,255,.08)', '--bad': '#ff7b72', '--badbg': 'rgba(248,81,73,.10)',
        '--hl': 'rgba(255,255,255,.10)', '--shadow': '0 16px 48px rgba(0,0,0,.5)',
      };
      for (const el of [pill, box]) for (const [k, v] of Object.entries(V)) el.style.setProperty(k, v);
      themeBtn.title = 'Тема: ' + (theme === 'auto' ? 'как у системы' : theme === 'dark' ? 'тёмная' : 'светлая') + ' (клик — переключить)';
    };

    const header = document.createElement('div');
    Object.assign(header.style, { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '6px', marginBottom: '8px', cursor: 'move', userSelect: 'none' });
    const hLeft = document.createElement('div');
    Object.assign(hLeft.style, { display: 'flex', alignItems: 'center', gap: '8px', flex: '0 1 auto', overflow: 'hidden' });
    const grip = svgIcon('grip', 14);
    grip.style.color = 'var(--muted)';
    const title = document.createElement('span');
    title.textContent = 'Domain Sniffer';
    Object.assign(title.style, { fontSize: '12px', fontWeight: '700', letterSpacing: '.02em', color: 'var(--txt)', whiteSpace: 'nowrap' });
    hLeft.append(grip, title);
    const btnGroup = document.createElement('div');
    Object.assign(btnGroup.style, { display: 'flex', gap: '3px', alignItems: 'center', flex: '0 0 auto' });
    header.append(hLeft, btnGroup);

    // перетаскивание панели за шапку + запоминание позиции
    header.onmousedown = (e) => {
      if (e.button !== 0 || (e.target.closest && e.target.closest('button'))) return;
      e.preventDefault();
      const r = box.getBoundingClientRect();
      let sx = e.clientX - r.left, sy = e.clientY - r.top;
      box.style.left = r.left + 'px'; box.style.top = r.top + 'px';
      box.style.right = 'auto'; box.style.bottom = 'auto';
      const move = (ev) => {
        // тащить можно только в пределах экрана — панель не уйдёт за край
        const x = Math.max(4, Math.min(ev.clientX - sx, window.innerWidth - r.width - 4));
        const y = Math.max(8, Math.min(ev.clientY - sy, window.innerHeight - r.height - 8));
        box.style.left = x + 'px'; box.style.top = y + 'px';
      };
      const up = () => {
        document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up);
        try {
          if (UI_CFG.pos === 'remember') {
            const rr = box.getBoundingClientRect();
            gmSet('__dsnf3_pos', { x: Math.round(Math.max(4, rr.left)), y: Math.round(Math.max(8, rr.top)) });
          }
        } catch {}
      };
      document.addEventListener('mousemove', move); document.addEventListener('mouseup', up);
    };

    const reloadBtn = mkBtn('', 'Перезагрузить сайт и собрать домены заново (список накапливается)', 'refresh');
    const modeBtn = mkBtn('Поддомены', 'Показывать все поддомены или только корневые домены');
    const copyBtn = mkBtn('Список', 'Скопировать весь список доменов');
    const probBtn = mkBtn('Проблемные', 'Скопировать только заблокированные и «не в прокси» домены — готовый список для прокси-листа роутера');
    const checkBtn = mkBtn('Проверить', 'Проверить все собранные домены: реестр блокировок + IP-подсети + живые пробы у вашего провайдера (DPI / полная / ~16-20КБ / замедление)');
    const chbBtn = mkBtn('Регионы', 'Проверить домен текущего сайта по регионам РФ (cheburcheck.ru): ~1-2 мин на домен, сканируются по одному, кэш 6 ч. Shift+клик — поставить в очередь все видимые домены');
    const tspuBtn = mkBtn('Доступность хостингов', 'Проверка доступности популярных зарубежных хостингов (Cloudflare, AWS, Fastly…): обрывает ли провайдер передачу после ~16-20 КБ — из-за этого сайты на таких хостингах открываются не полностью. Тест шлёт 64 КБ данных на 5 хостингов и показывает, где обрыв (~15 сек)');
    const clearBtn = mkBtn('', 'Очистить собранный список', 'trash');
    const helpBtn = mkBtn('?', 'Справка: что означают статусы и кнопки');
    const themeBtn = mkBtn('', 'Тема (клик — переключить: система / тёмная / светлая)', 'theme');
    const minBtn = mkBtn('—', 'Свернуть');
    const gearBtn = mkBtn('', 'Маршрут через прокси: подключение к Clash API роутера/ПК (Podkop/Forkop/NetShift/sing-box/clash)', 'gear');
    applyTheme();

    // настройки интерфейса: автоскрытие в fullscreen, прозрачность в покое, хоткей
    const UI_CFG = (() => { try { return Object.assign({ fsHide: true, pillOp: 100, panelOp: 100, pos: 'corner' }, gmGet('__dsnf3_ui', {}) || {}); } catch { return { fsHide: true, pillOp: 100, panelOp: 100, pos: 'corner' }; } })();
    let uiHidden = false; // полное скрытие по Alt+Shift+D
    const saveUi = () => { try { gmSet('__dsnf3_ui', UI_CFG); } catch {} };
    const applyUiCfg = () => {
      pill.style.opacity = String(UI_CFG.pillOp / 100);
      box.style.opacity = String(UI_CFG.panelOp / 100);
      pill.style.transition = 'opacity .15s ease';
      pill.onmouseenter = () => { pill.style.opacity = '1'; };
      pill.onmouseleave = () => { pill.style.opacity = String(UI_CFG.pillOp / 100); };
      if (UI_CFG.panelOp < 100) {
        box.style.transition = 'opacity .15s ease';
        box.onmouseenter = () => { box.style.opacity = '1'; };
        box.onmouseleave = () => { box.style.opacity = String(UI_CFG.panelOp / 100); };
      }
    };

    // строка действий (текстовые кнопки) — под шапкой, чтобы ничего не ломалось на узких экранах
    const actionRow = document.createElement('div');
    Object.assign(actionRow.style, { display: 'flex', gap: '5px', marginBottom: '8px', flexWrap: 'wrap' });

    // настройки подключения к Clash API
    const settings = document.createElement('div');
    Object.assign(settings.style, { display: 'none', marginTop: '10px', borderTop: '1px solid var(--border-soft)', paddingTop: '10px', flex: '0 1 auto', minHeight: '80px', overflowY: 'auto' });
    const urlIn = document.createElement('input');
    urlIn.placeholder = 'Clash API, напр. http://192.168.1.1:9090';
    Object.assign(urlIn.style, { display: 'block', width: '100%', boxSizing: 'border-box', background: 'var(--list)', border: '1px solid var(--border-soft)', borderRadius: '8px', color: 'var(--txt)', font: 'inherit', fontSize: '11px', padding: '5px 8px', marginBottom: '6px' });
    const secIn = document.createElement('input');
    secIn.placeholder = 'секрет (если задан на роутере)';
    secIn.type = 'password';
    Object.assign(secIn.style, { display: 'block', width: '100%', boxSizing: 'border-box', background: 'var(--list)', border: '1px solid var(--border-soft)', borderRadius: '8px', color: 'var(--txt)', font: 'inherit', fontSize: '11px', padding: '5px 8px', marginBottom: '6px' });
    const applyBtn = mkBtn('Подключить', 'Проверить адрес и подключиться');
    const setStat = document.createElement('span');
    Object.assign(setStat.style, { fontSize: '10px', color: 'var(--muted)', marginLeft: '6px' });
    applyBtn.onclick = async () => { setStat.textContent = '…проверяю'; setStat.textContent = await connectRoute(urlIn.value, secIn.value, true); render(); };
    const srow = document.createElement('div');
    Object.assign(srow.style, { display: 'flex', alignItems: 'center', gap: '4px' });
    srow.append(applyBtn, setStat);
    settings.append(urlIn, secIn, srow);

    // режим сбора ссылок со страницы
    const lmLabel = document.createElement('div');
    lmLabel.textContent = 'Сбор ссылок со страницы:';
    Object.assign(lmLabel.style, { fontSize: '10px', color: 'var(--muted)', margin: '12px 0 4px' });
    const lmSel = document.createElement('select');
    [['all', 'Все ссылки (по умолчанию)'], ['internal', 'Только внутренние (свой корневой домен)'], ['off', 'Не собирать ссылки вообще']].forEach(([v, t]) => { const o = document.createElement('option'); o.value = v; o.textContent = t; lmSel.append(o); });
    lmSel.value = LINKMODE;
    Object.assign(lmSel.style, { width: '100%', boxSizing: 'border-box', background: 'var(--list)', border: '1px solid var(--border-soft)', borderRadius: '8px', color: 'var(--txt)', font: 'inherit', fontSize: '11px', padding: '5px 8px' });
    const lmHint = document.createElement('div');
    lmHint.textContent = 'Ссылки — домены, которые страница не загружала, а просто упоминала (выдача поиска, футеры, README). Уже собранные лишние убираются сразу.';
    Object.assign(lmHint.style, { fontSize: '10px', color: 'var(--muted)', marginTop: '4px' });
    lmSel.onchange = () => { LINKMODE = lmSel.value; try { gmSet('__dsnf3_linkmode', LINKMODE); } catch {} purgeLinkMode(); render(); };
    settings.append(lmLabel, lmSel, lmHint);

    // игнор-лист с масками
    const igLabel = document.createElement('div');
    igLabel.textContent = 'Игнор-лист — домены по маскам не собирать вовсе:';
    Object.assign(igLabel.style, { fontSize: '10px', color: 'var(--muted)', margin: '12px 0 4px' });
    const igTa = document.createElement('textarea');
    igTa.rows = 3;
    igTa.placeholder = '*.doubleclick.net\nads.*\n*betting*';
    Object.assign(igTa.style, { display: 'block', width: '100%', boxSizing: 'border-box', background: 'var(--list)', border: '1px solid var(--border-soft)', borderRadius: '8px', color: 'var(--txt)', font: 'inherit', fontSize: '11px', padding: '5px 8px', resize: 'vertical' });
    const igSave = mkBtn('Сохранить', 'Применить маски и удалить совпавшие домены из списка');
    const igStat = document.createElement('span');
    Object.assign(igStat.style, { fontSize: '10px', color: 'var(--muted)', marginLeft: '6px' });
    igSave.onclick = () => {
      try { gmSet('__dsnf3_ignore', igTa.value); } catch {}
      IGNORE.arr = parseIgnore(igTa.value);
      const removed = purgeIgnored();
      igStat.textContent = 'Масок: ' + IGNORE.arr.length + (removed ? ' · удалено из списка: ' + removed : '');
      render();
      setTimeout(() => { igStat.textContent = ''; }, 4000);
    };
    const igRow = document.createElement('div');
    Object.assign(igRow.style, { display: 'flex', alignItems: 'center', gap: '4px', marginTop: '6px' });
    igRow.append(igSave, igStat);
    settings.append(igLabel, igTa, igRow);

    // интерфейс: скрытие в fullscreen, прозрачность, хоткей
    const uiHead = document.createElement('div');
    uiHead.textContent = 'Интерфейс:';
    Object.assign(uiHead.style, { fontSize: '10px', color: 'var(--muted)', margin: '12px 0 4px' });
    const fsChk = document.createElement('input');
    fsChk.type = 'checkbox';
    fsChk.checked = !!UI_CFG.fsHide;
    fsChk.style.accentColor = 'var(--accent)';
    const fsLbl = document.createElement('span');
    fsLbl.textContent = 'скрывать кнопку и панель в полноэкранном режиме (видео, F11)';
    Object.assign(fsLbl.style, { fontSize: '10px', color: 'var(--txt)' });
    const fsRow = document.createElement('label');
    Object.assign(fsRow.style, { display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px', cursor: 'pointer' });
    fsRow.append(fsChk, fsLbl);
    fsChk.onchange = () => { UI_CFG.fsHide = fsChk.checked; saveUi(); syncVisibility(); };
    const mkUiSel = (key, label, opts) => {
      const row = document.createElement('label');
      Object.assign(row.style, { display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px', fontSize: '10px', color: 'var(--txt)' });
      const sp = document.createElement('span'); sp.textContent = label;
      const sel = document.createElement('select');
      opts.forEach(([v, t]) => { const o = document.createElement('option'); o.value = String(v); o.textContent = t; sel.append(o); });
      sel.value = String(UI_CFG[key]);
      Object.assign(sel.style, { background: 'var(--list)', border: '1px solid var(--border-soft)', borderRadius: '6px', color: 'var(--txt)', font: 'inherit', fontSize: '10px', padding: '2px 4px' });
      sel.onchange = () => { UI_CFG[key] = +sel.value; saveUi(); applyUiCfg(); };
      row.append(sp, sel);
      return row;
    };
    const pillSelRow = mkUiSel('pillOp', 'Прозрачность кнопки (в покое):', [[100, 'обычная'], [70, '70%'], [40, '40%'], [20, 'почти невидима']]);
    const panelSelRow = mkUiSel('panelOp', 'Прозрачность панели (в покое):', [[100, 'обычная'], [85, '85%'], [70, '70%']]);
    const posSelRow = mkUiSel('pos', 'Положение панели:', [['corner', 'Всегда справа снизу'], ['remember', 'Запоминать перетаскивание']]);
    const posSel = posSelRow.querySelector('select');
    posSel.value = UI_CFG.pos;
    posSel.onchange = () => { UI_CFG.pos = posSel.value; saveUi(); syncVisibility(); };
    const hkHint = document.createElement('div');
    hkHint.textContent = 'Alt+Shift+D — быстро скрыть/показать всю панель и кнопку (работает и без настроек).';
    Object.assign(hkHint.style, { fontSize: '10px', color: 'var(--muted)', marginTop: '4px' });
    settings.append(uiHead, fsRow, pillSelRow, panelSelRow, posSelRow, hkHint);

    gearBtn.onclick = () => {
      const show = settings.style.display === 'none';
      settings.style.display = show ? 'block' : 'none';
      if (show) {
        const saved = gmGet('__dsnf3_route', null);
        urlIn.value = (saved && saved.url) || (ROUTE.base || '');
        secIn.value = (saved && saved.secret) || '';
        try { igTa.value = String(gmGet('__dsnf3_ignore', '') || ''); } catch {}
        lmSel.value = LINKMODE;
      }
      requestAnimationFrame(clampPanel); // после роста панели — вписать её в экран
    };

    const list = document.createElement('div');
    Object.assign(list.style, { maxHeight: '420px', minHeight: '120px', flex: '0 1 auto', overflow: 'auto', background: 'var(--list)', border: '1px solid var(--border-soft)', borderRadius: '10px', padding: '6px', userSelect: 'text' });

    // фильтры-чипсы: сразу видно, сколько проблем и сколько доступно
    const filters = document.createElement('div');
    Object.assign(filters.style, { display: 'flex', gap: '5px', marginBottom: '8px', flexWrap: 'wrap' });
    const mkChip = (key) => {
      const c = document.createElement('button');
      Object.assign(c.style, { background: 'var(--chip)', color: 'var(--txt)', border: '1px solid transparent', borderRadius: '999px', padding: '4px 11px', cursor: 'pointer', font: 'inherit', fontSize: '11px', whiteSpace: 'nowrap', transition: 'background .12s ease' });
      c.onclick = () => { viewFilter = key; render(); };
      filters.append(c);
      return c;
    };
    const chipAll = mkChip('all');
    const chipBad = mkChip('bad');
    const chipOk = mkChip('ok');
    // «Только трафик»: скрыть домены-ссылки (например, результаты поиска или футеры) —
    // показать лишь то, что страница реально загружала
    const chipNet = mkChip('net');
    chipNet.onclick = () => { linkOnly = !linkOnly; try { gmSet('__dsnf3_linkonly', linkOnly); } catch {} render(); };
    chipNet.title = 'Переключить: только реально загруженные домены / все вместе с доменами-ссылками';

    // живой поиск по доменам
    let query = '';
    const searchIn = document.createElement('input');
    searchIn.placeholder = 'Поиск по доменам…';
    searchIn.title = 'Живой фильтр: показываются домены, содержащие введённый текст (Esc — очистить)';
    Object.assign(searchIn.style, { display: 'block', width: '100%', boxSizing: 'border-box', background: 'var(--list)', border: '1px solid var(--border-soft)', borderRadius: '999px', color: 'var(--txt)', font: 'inherit', fontSize: '11px', padding: '5px 12px', outline: 'none', marginBottom: '8px' });
    searchIn.oninput = () => { query = searchIn.value.trim().toLowerCase(); render(); };
    searchIn.onkeydown = (e) => { if (e.key === 'Escape') { searchIn.value = ''; query = ''; render(); } };

    // вся документация — внутри панели по кнопке «?»
    const help = document.createElement('div');
    Object.assign(help.style, { display: 'none', background: 'var(--list)', border: '1px solid var(--border-soft)', borderRadius: '10px', padding: '10px 12px', fontSize: '11px', lineHeight: '1.55', color: 'var(--txt)', overflow: 'auto', maxHeight: '420px', minHeight: '120px', flex: '0 1 auto', userSelect: 'text' });
    const hSec = (txt) => { const e = document.createElement('div'); e.textContent = txt; Object.assign(e.style, { color: 'var(--accent)', fontWeight: '700', margin: '10px 0 3px', letterSpacing: '.02em' }); return e; };
    const hLine = (txt) => { const e = document.createElement('div'); e.textContent = txt; Object.assign(e.style, { marginBottom: '3px' }); return e; };
    help.append(
      hSec('Что это'),
      hLine('Скрипт собирает все домены, которые загружает сайт, и проверяет, какие из них заблокированы у вашего провайдера — чтобы было видно, почему сайт не работает или работает плохо.'),
      hSec('Кнопки'),
      hLine('«Проверить» — проверить все собранные домены: реестр блокировок + живые пробы у вашего провайдера.'),
      hLine('«Регионы» — домен текущего сайта проверяют десятки сканеров по России (cheburcheck.ru): видно, блокировка общая или только у вашего оператора. Долго (~1-2 мин), кэш 6 ч.'),
      hLine('Иконки в шапке: обновить (перезагрузить сайт и собрать заново) · шестерёнка (подключение к Clash API роутера Podkop/Forkop/NetShift) · тема · корзина (очистить) · «—» (свернуть).'),
      hLine('«Список» — скопировать весь список доменов в буфер обмена · «Проблемные» — только заблокированные и «не в прокси» (готовый список для прокси-листа роутера).'),
      hLine('Шестерёнка также содержит: режим сбора ссылок (все / только внутренние / не собирать) и игнор-лист с масками (*.doubleclick.net, ads.*, *betting* — домены по маскам не собираются вовсе).'),
      hSec('Статусы (проверка у вашего провайдера)'),
      hLine('● OK — доступен (зелёная точка)'),
      hLine('● DPI — сброс соединения, похоже на блокировку по имени домена (SNI)'),
      hLine('● IP — нет ответа, похоже на полную блокировку по IP'),
      hLine('● 16-20КБ — обрыв после ~16-20КБ, «частичная» блокировка страницы'),
      hLine('● обрыв — соединение оборвалось после большого объёма'),
      hLine('● медленно — похоже на замедление (троттлинг)'),
      hLine('В подробностях под строкой: «домен в реестре блокировок», «IP-подсеть в реестре» (хостинг типа Hetzner/Cloudflare).'),
      hLine('HTTP 403/405 у некоторых сайтов — это анти-бот проверка, а не блокировка (так отвечают даже там, где не заблокированы).'),
      hSec('Про «заморозку» (обрыв после 16-20 КБ)'),
      hLine('Оборудование провайдера обрывает соединение к некоторым зарубежным хостингам после передачи ~16-20 КБ. Страница успевает открыться (текст виден), но картинки, файлы и видео не догружаются — сайт «виснет».'),
      hLine('Кнопка «Доступность хостингов» проверяет это: отправляет 64 КБ данных на 5 крупных зарубежных хостингов (Cloudflare, AWS, Fastly…) и смотрит, где передача обрывается.'),
      hLine('Что делать: добавить такой сайт в прокси/VPN-лист роутера — через VPN заморозка не действует.'),
      hSec('Маршрут (нужен Clash API — шестерёнка)'),
      hLine('«через прокси» — домен идёт через VPN/прокси (показана цепочка) · «напрямую» — идёт в обход (и по какому правилу)'),
      hLine('со знаком «?» — определено косвенно, без Clash API (по реестру и задержкам)'),
      hLine('Красная строка «заблокирован и НЕ в прокси» — добавьте домен в прокси-лист роутера, и сайт заработает.'),
      hSec('Мелочи'),
      hLine('Иконка глобуса на строке — регион-чек этого домена по РФ'),
      hLine('клик по имени домена или иконке копирования — скопировать этот домен'),
      hLine('клик по остальной строке — перепроверить один домен · число справа — задержка в мс'),
      hLine('По умолчанию показываются только домены, которые страница реально загружала. Чип «Только трафик» переключает: появятся домены-ссылки — приглушённые строки с бейджем «ссылка» внизу списка (результаты поиска, футеры, README — страница их не загружала).'),
      hLine('Строка поиска над списком — живой фильтр по подстроке (Esc — очистить).'),
      hLine('Шапку можно тащить мышью. По умолчанию панель всегда открывается справа снизу; в ⚙ можно включить «Запоминать перетаскивание». Панель всегда вписывается в экран.'),
      hLine('Alt+Shift+D — быстро скрыть/показать скрипт. В ⚙ есть автоскрытие в полноэкранном режиме и прозрачность кнопки/панели.'),
      hLine('Список доменов и статусы сохраняются при переходах по сайту (до закрытия вкладки).'),
    );

    const statusbar = document.createElement('div');
    Object.assign(statusbar.style, { marginTop: '8px', fontSize: '10px', lineHeight: '1.5', color: 'var(--muted)', cursor: 'pointer' });
    statusbar.title = 'Во время регион-чека: клик здесь — отменить текущий скан и очистить очередь';

    const routebar = document.createElement('div');
    Object.assign(routebar.style, { marginTop: '2px', fontSize: '10px', lineHeight: '1.5', color: 'var(--accent)' });
    routebar.title = 'Маршрутизация: кто идёт через прокси, кто напрямую. Без Clash API — только внешний IP/сплит';

    // копирование в буфер (Clipboard API + запасной textarea); feedback — в статус-строке
    const copyText = async (text) => {
      try { await navigator.clipboard.writeText(text); return true; } catch {}
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        Object.assign(ta.style, { position: 'fixed', left: '-9999px', top: '0' });
        document.documentElement.appendChild(ta);
        ta.select(); document.execCommand('copy'); ta.remove();
        return true;
      } catch { return false; }
    };
    const flashStatus = (msg) => { statusMsg = msg; renderSoon(); setTimeout(() => { if (statusMsg === msg) { statusMsg = ''; renderSoon(); } }, 2000); };

    // бейдж статуса: цветная точка + короткая подпись (без эмодзи)
    // бейдж статуса: цветная точка + подпись; непроверенные — тихая полая точка без чипа
    const mkBadge = (badge, busy) => {
      const wrap = document.createElement('span');
      Object.assign(wrap.style, { display: 'inline-flex', alignItems: 'center', gap: '5px', flex: '0 0 auto', padding: '3px 8px', borderRadius: '7px', whiteSpace: 'nowrap' });
      const dot = document.createElement('span');
      dot.style.width = '7px'; dot.style.height = '7px'; dot.style.borderRadius = '50%';
      const label = document.createElement('span');
      label.style.fontSize = '10px';
      label.style.fontWeight = '600';
      if (busy) {
        wrap.style.background = 'var(--chip)';
        dot.style.background = '#58a6ff';
        dot.style.animation = '__dsnf3_pulse 1.2s ease-in-out infinite';
        label.textContent = 'проверка';
        label.style.color = '#58a6ff';
        wrap.append(dot, label);
      } else if (badge && badge.t) {
        wrap.style.background = 'var(--chip)';
        dot.style.background = badge.c || 'var(--muted)';
        label.textContent = badge.t;
        label.style.color = badge.c || 'var(--muted)';
        wrap.append(dot, label);
      } else {
        dot.style.border = '1.5px solid var(--muted)';
        dot.style.opacity = '.5';
        wrap.style.padding = '3px 4px';
        wrap.append(dot);
      }
      return wrap;
    };

    const mkRow = (r) => {
      const mood = r.busy ? 'busy' : (r.st || 'none');
      const row = document.createElement('div');
      Object.assign(row.style, { display: 'flex', flexDirection: 'column', gap: '1px', padding: '5px 7px', borderRadius: '9px', cursor: r.click ? 'pointer' : 'default', marginBottom: '3px', transition: 'background .1s ease, opacity .15s ease' });
      if (mood === 'bad') row.style.background = 'var(--badbg)';
      if (r.danger) row.style.borderLeft = '2px solid #f85149';
      if (r.linkOnly) row.style.opacity = '.58'; // наглядно: домен-ссылка приглушён целиком
      row.onmouseenter = () => { row.style.background = mood === 'bad' ? 'var(--badbg)' : 'var(--row-hover)'; row.style.opacity = '1'; };
      row.onmouseleave = () => { row.style.background = mood === 'bad' ? 'var(--badbg)' : 'transparent'; row.style.opacity = r.linkOnly ? '.58' : '1'; };

      const l1 = document.createElement('div');
      Object.assign(l1.style, { display: 'flex', alignItems: 'center', gap: '9px' });
      l1.append(mkBadge(r.badge, r.busy));
      const host = document.createElement('span');
      host.textContent = r.host;
      Object.assign(host.style, { flex: '1 1 auto', minWidth: '0', overflowWrap: 'anywhere', color: mood === 'bad' ? 'var(--bad)' : 'var(--txt)' });
      host.style.cursor = 'pointer';
      host.title = 'Нажмите, чтобы скопировать домен' + (r.linkOnly ? ' · домен-ссылка: страница его не загружала, он просто стоит ссылкой на странице' : '');
      host.onclick = (ev) => {
        ev.stopPropagation(); // не запускаем перепроверку строки
        copyText(r.host).then((okk) => flashStatus(okk ? 'Скопировано: ' + r.host : 'Не удалось скопировать'));
      };
      l1.append(host);
      if (r.ms) { const ms = document.createElement('span'); ms.textContent = r.ms + ' мс'; Object.assign(ms.style, { flex: '0 0 auto', color: 'var(--muted)', fontSize: '10px' }); l1.append(ms); }
      const cb = document.createElement('span');
      cb.title = 'Скопировать этот домен';
      Object.assign(cb.style, { flex: '0 0 auto', cursor: 'pointer', opacity: '.55', color: 'var(--muted)', display: 'flex' });
      cb.append(svgIcon('copy', 13));
      cb.onmouseenter = () => { cb.style.opacity = '1'; };
      cb.onmouseleave = () => { cb.style.opacity = '.55'; };
      cb.onclick = (ev) => {
        ev.stopPropagation();
        copyText(r.host).then((okk) => flashStatus(okk ? 'Скопировано: ' + r.host : 'Не удалось скопировать'));
      };
      l1.append(cb);
      if (hasGM && r.host && r.host.includes('.')) {
        const rb = document.createElement('span');
        rb.title = 'Регион-чек: блокировки по РФ через cheburcheck.ru (~1-2 мин, кэш 6 ч)';
        Object.assign(rb.style, { flex: '0 0 auto', cursor: 'pointer', opacity: '.55', color: 'var(--muted)', display: 'flex' });
        rb.append(svgIcon('globe', 13));
        rb.onmouseenter = () => { rb.style.opacity = '1'; };
        rb.onmouseleave = () => { rb.style.opacity = '.55'; };
        rb.onclick = (ev) => { ev.stopPropagation(); if (!chbQueue.includes(r.host)) chbQueue.push(r.host); chbPump(); };
        l1.append(rb);
      }
      row.append(l1);
      // вторая строка — подробности (маршрут, регион, хостинг), только если есть что сказать
      const extra = (r.tag || '').trim();
      if (extra) {
        const l2 = document.createElement('div');
        l2.textContent = extra;
        Object.assign(l2.style, { fontSize: '10px', lineHeight: '1.45', color: 'var(--muted)', paddingLeft: '9px', overflowWrap: 'anywhere' });
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
          const rec = domains.get(h) || {};
          if (linkOnly && !rec.net) continue; // «Только трафик»: скрыть домены-ссылки
          if (query && !h.includes(query)) continue; // живой поиск
          const s = info.get(h) || {};
          const parts = [];
          let danger = !!(s.status && s.status.blocked && s.route && s.route.direct);
          if (danger) parts.push('заблокирован и НЕ в прокси — добавьте в прокси-лист роутера');
          if (s.route) parts.push(s.route.direct ? 'напрямую' + (s.route.inferred ? '?' : '') + (s.route.rule ? ' [' + s.route.rule + ']' : '') : 'через прокси' + (s.route.inferred ? '?' : '') + ': ' + s.route.via);
          const ct = chbTag(s);
          if (ct) parts.push(ct);
          if (s.status) parts.push(s.status.tag);
          const blocked = !!(s.status && s.status.blocked);
          let badge = null;
          if (danger) badge = { t: 'не в прокси', c: '#f85149' };
          else if (s.status && s.status.primary && KIND_META[s.status.primary]) badge = { t: KIND_META[s.status.primary].t, c: KIND_META[s.status.primary].c };
          else if (s.status && s.status.blocked) badge = { t: 'в реестре', c: '#a371f7' };
          else if (!rec.net) badge = { t: 'ссылка', c: '#8b949e' }; // наглядная пометка домена-ссылки
          out.push({
            host: h,
            badge,
            tag: parts.join(' · '),
            blocked,
            danger,
            st: (blocked || danger) ? 'bad' : (s.status && !s.status.blocked ? 'ok' : 'none'),
            ms: s.ms || null,
            linkOnly: !rec.net,
            busy: !!s.busy,
            click: hasGM ? h : null,
          });
        }
      } else {
        const map = new Map();
        for (const h of domains.keys()) {
          const rec = domains.get(h) || {};
          if (linkOnly && !rec.net) continue;
          const r = getRoot(h);
          if (query && !r.includes(query)) continue;
          let e = map.get(r);
          if (!e) { e = { host: r, subs: 0, blocked: 0, checked: 0, prox: 0, direct: 0 }; map.set(r, e); }
          e.subs++;
          const s = info.get(h);
          if (s && s.status) { e.checked++; if (s.status.blocked) e.blocked++; }
          if (s && s.route) { if (s.route.direct) e.direct++; else e.prox++; }
        }
        for (const e of map.values()) {
          const parts = [];
          if (e.prox || e.direct) parts.push('маршрут: ' + (e.prox ? 'через прокси ' + e.prox : '') + (e.prox && e.direct ? ' · ' : '') + (e.direct ? 'напрямую ' + e.direct : '') + ' из ' + e.subs);
          if (e.blocked) parts.push(e.blocked + '/' + e.subs + ' заблокированы');
          else if (e.checked) parts.push('проблем не найдено');
          out.push({
            host: e.host,
            badge: e.blocked > 0 ? { t: e.blocked + '/' + e.subs, c: '#f85149' } : (e.checked ? { t: 'OK', c: '#3fb950' } : null),
            tag: parts.join(' · '),
            blocked: e.blocked > 0,
            danger: e.blocked > 0 && e.direct > 0 && e.prox === 0,
            st: e.blocked > 0 ? 'bad' : (e.checked && !e.blocked ? 'ok' : 'none'),
            ms: null,
            busy: false,
            click: null,
          });
        }
      }
      // проблемные — сверху, домены-ссылки — внизу
      out.sort((a, b) => ((b.blocked ? 1 : 0) - (a.blocked ? 1 : 0)) || ((b.danger ? 1 : 0) - (a.danger ? 1 : 0)) || ((a.linkOnly ? 1 : 0) - (b.linkOnly ? 1 : 0)) || getRoot(a.host).localeCompare(getRoot(b.host)) || a.host.localeCompare(b.host));
      return out;
    };

    const defaultStatus = () => {
      if (statusMsg) return statusMsg;
      if (CHB.busy) return 'Регион-чек ' + CHB.active + ' — ' + Math.max(0, Math.round((Date.now() - CHB.startedAt) / 1000)) + 'с (до ~' + Math.round(CFG.chb.probeTimeoutMs / 1000) + 'с) · ответов ' + CHB.parts + (CHB.online ? '/' + CHB.online : '') + (chbQueue.length ? ' · в очереди ' + chbQueue.length : '') + ' · клик здесь — отменить';
      if (running) return 'Проверка: осталось ' + queue.length + '…';
      if (REG.loading) return 'Загрузка списков реестра…';
      if (SANITY.t && SANITY.fail && SANITY.fail.length) return 'Контрольные точки недоступны (' + SANITY.fail.join(', ') + ') — результаты могут быть недостоверны';
      if (REG.t) return 'Реестр: ' + REG.domCount.toLocaleString('ru-RU') + ' дом., ' + REG.netCount.toLocaleString('ru-RU') + ' подсетей · от ' + new Date(REG.t).toLocaleString('ru-RU');
      if (REG.err) return REG.err + ' — проверка только живыми пробами';
      if (!hasGM) return 'GM_xmlhttpRequest недоступен — проверка блокировок не работает';
      return 'Домены: ' + domains.size + ' · «Проверить» — проверить блокировки';
    };

    let lastSig = '';
    const render = () => {
      const all = rowsFor();
      const badN = all.filter((r) => r.st === 'bad').length;
      const okN = all.filter((r) => r.st === 'ok').length;
      const rows = viewFilter === 'all' ? all : all.filter((r) => r.st === viewFilter);
      pillTxt.textContent = String(all.length) + (badN ? ' / ' + badN : '');
      pillDot.style.background = badN ? '#f85149' : '#3fb950';
      checkBtn.textContent = running ? 'Стоп (' + queue.length + ')' : 'Проверить';
      chipAll.textContent = 'Все · ' + all.length;
      chipBad.textContent = 'Проблемные · ' + badN;
      chipOk.textContent = 'Доступные · ' + okN;
      chipNet.textContent = 'Только трафик' + (linkOnly ? ' ✓' : '');
      for (const [c, k] of [[chipAll, 'all'], [chipBad, 'bad'], [chipOk, 'ok']]) {
        c.style.background = viewFilter === k ? 'var(--accent)' : 'var(--chip)';
        c.style.color = viewFilter === k ? '#fff' : 'var(--txt)';
        c.style.borderColor = 'transparent';
      }
      chipNet.style.background = linkOnly ? 'var(--accent)' : 'var(--chip)';
      chipNet.style.color = linkOnly ? '#fff' : 'var(--txt)';
      help.style.display = showHelp ? 'block' : 'none';
      list.style.display = showHelp ? 'none' : 'block';
      helpBtn.style.background = showHelp ? 'var(--accent)' : 'var(--btn)';
      helpBtn.style.color = showHelp ? '#fff' : 'var(--txt)';
      const sig = JSON.stringify([rootOnly, statusMsg, running, queue.length, REG.t, REG.err, viewFilter, showHelp, linkOnly, query, all.length, badN, okN, rows.map((r) => [r.host, r.badge && r.badge.t, r.tag, r.blocked, r.busy])]);
      if (sig !== lastSig) {
        lastSig = sig;
        const keepScroll = list.scrollTop; // сохраняем позицию прокрутки при перерисовке
        list.textContent = '';
        const frag = document.createDocumentFragment();
        if (!rows.length) {
          const d = document.createElement('div');
          d.textContent = query
            ? 'Ничего не найдено по запросу «' + query + '»'
            : all.length
              ? (viewFilter === 'bad' ? 'Проблемных доменов не найдено' : 'В этой категории пусто')
              : 'Пока пусто: домены появятся, когда сайт начнёт что-то загружать. Нажмите «Проверить», чтобы проверить найденные.';
          Object.assign(d.style, { color: 'var(--muted)', padding: '8px 4px' });
          frag.append(d);
        } else {
          rows.forEach((r) => frag.append(mkRow(r)));
        }
        list.append(frag);
        list.scrollTop = keepScroll;
      }
      const rt = ROUTE.ok
        ? 'Маршрут: ' + ROUTE.base.replace(/^https?:\/\//, '') + (ROUTE.lastPoll ? ' · опрос ' + new Date(ROUTE.lastPoll).toLocaleTimeString('ru-RU') : '')
        : (hasGM ? 'Маршрут: Clash API не найден — включите дашборд на роутере (Podkop/Forkop/NetShift) и задайте адрес в настройках' : '');
      const rtxt = [rt, echoText()].filter(Boolean).join('   ·   ');
      if (routebar.textContent !== rtxt) routebar.textContent = rtxt;
      const st = defaultStatus();
      if (statusbar.textContent !== st) statusbar.textContent = st;
      // тултип: последняя проверка хостингов или подсказка про отмену регион-чека
      const sbTitle = TSPU.last ? 'Последняя проверка хостингов — ' + TSPU.last : 'Во время регион-чека: клик здесь — отменить';
      if (statusbar.title !== sbTitle) statusbar.title = sbTitle;
      const tbTitle = TSPU.last ? 'Проверка доступности хостингов (клик — повторить). Последний результат: ' + TSPU.last : 'Проверка доступности популярных зарубежных хостингов (Cloudflare, AWS, Fastly…): обрывает ли провайдер передачу после ~16-20 КБ — из-за этого сайты на таких хостингах открываются не полностью. Тест шлёт 64 КБ данных на 5 хостингов и показывает, где обрыв (~15 сек)';
      if (tspuBtn.title !== tbTitle) tspuBtn.title = tbTitle;
    };
    renderFn = render;

    const syncVisibility = () => {
      const hideAll = uiHidden || (UI_CFG.fsHide && document.fullscreenElement);
      pill.style.display = (!hideAll && !isOpen) ? 'flex' : 'none';
      box.style.display = (!hideAll && isOpen) ? 'flex' : 'none';
      if (isOpen && !hideAll) {
        if (UI_CFG.pos === 'corner') { // предсказуемое место по умолчанию
          box.style.left = ''; box.style.top = '';
          box.style.right = '14px'; box.style.bottom = '14px';
        }
        requestAnimationFrame(clampPanel); // в любом случае — вписать в экран
      }
    };
    // хоткей Alt+Shift+D — скрыть/показать весь UI (не зависит от раскладки: e.code)
    window.addEventListener('keydown', (e) => {
      if (e.altKey && e.shiftKey && !e.ctrlKey && !e.metaKey && e.code === 'KeyD') {
        e.preventDefault();
        uiHidden = !uiHidden;
        syncVisibility();
      }
    });
    document.addEventListener('fullscreenchange', syncVisibility);
    pill.onclick = () => { isOpen = true; setOpen(true); syncVisibility(); if (ROUTE.ok) startRoutePolling(); render(); };
    helpBtn.onclick = () => { showHelp = !showHelp; render(); };
    themeBtn.onclick = () => { theme = theme === 'auto' ? 'dark' : theme === 'dark' ? 'light' : 'auto'; try { gmSet(THEME_KEY, theme); } catch {} applyTheme(); };
    minBtn.onclick = () => { isOpen = false; setOpen(false); stopRoutePolling(); syncVisibility(); };
    reloadBtn.onclick = () => { saveNow(); isOpen = true; setOpen(true); location.reload(); };
    modeBtn.onclick = () => { rootOnly = !rootOnly; modeBtn.textContent = rootOnly ? 'Корневые' : 'Поддомены'; render(); };
    clearBtn.onclick = () => { domains.clear(); info.clear(); queue.length = 0; try { sessionStorage.removeItem(SKEY); } catch {} render(); };
    copyBtn.onclick = async () => {
      if (await copyText(getListText())) { copyBtn.textContent = 'Готово ✓'; setTimeout(() => { copyBtn.textContent = 'Список'; }, 1200); }
      else flashStatus('Не удалось скопировать список');
    };
    checkBtn.onclick = () => { checkAll(); };
    chbBtn.onclick = (e) => {
      let hosts;
      if (e.shiftKey) {
        hosts = [...domains.keys()].filter((h) => { const rec = domains.get(h); return !linkOnly || (rec && rec.net); });
        if (!hosts.length) { flashStatus('Нет доменов для регион-чека'); return; }
      } else {
        const h = String(location.hostname || '');
        if (!h.includes('.')) { statusMsg = 'Регион-чек доступен только для доменов'; renderSoon(); setTimeout(() => { statusMsg = ''; renderSoon(); }, 6000); return; }
        hosts = [h];
      }
      for (const h of hosts) if (!chbQueue.includes(h)) chbQueue.push(h);
      chbPump();
    };

    probBtn.onclick = () => {
      const rows = rowsFor().filter((r) => r.st === 'bad');
      const text = [...new Set(rows.map((r) => r.host))].sort((a, b) => getRoot(a).localeCompare(getRoot(b)) || a.localeCompare(b)).join('\n');
      if (!text) { flashStatus('Проблемных доменов нет — сначала нажмите «Проверить»'); return; }
      copyText(text).then((okk) => flashStatus(okk ? 'Скопировано проблемных: ' + rows.length : 'Не удалось скопировать'));
    };

    tspuBtn.onclick = () => runTspuTest();

    btnGroup.append(reloadBtn, gearBtn, helpBtn, themeBtn, clearBtn, minBtn);
    actionRow.append(checkBtn, chbBtn, tspuBtn, copyBtn, probBtn, modeBtn);
    box.append(header, actionRow, filters, searchIn, list, help, statusbar, routebar, settings);
    document.documentElement.append(pill, box);
    // анимация пульсации точки «проверка» + восстановление сохранённой позиции панели
    if (!document.getElementById('__dsnf3_style')) {
      const st = document.createElement('style');
      st.id = '__dsnf3_style';
      st.textContent = '@keyframes __dsnf3_pulse { 0%,100% { opacity: 1 } 50% { opacity: .35 } }';
      document.head.append(st);
    }
    try {
      const p = gmGet('__dsnf3_pos', null);
      if (UI_CFG.pos === 'remember' && p && typeof p.x === 'number' && typeof p.y === 'number') {
        box.style.left = Math.max(4, Math.min(p.x, window.innerWidth - 100)) + 'px';
        box.style.top = Math.max(8, Math.min(p.y, window.innerHeight - 60)) + 'px';
        box.style.right = 'auto'; box.style.bottom = 'auto';
      }
    } catch {}
    syncVisibility();
    applyUiCfg();
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
