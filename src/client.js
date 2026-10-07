// Клиент внутренних вызовов: сервис → сервис по HTTP с токеном сервиса от auth.
//
// Токен берётся у auth (POST /auth/internal/v1/token), держится в памяти и
// обновляется заранее, за refreshAheadSec до истечения. Одновременные вызовы
// делят один запрос токена. Если владелец эндпоинта ответил 401 (например,
// auth перевыпустил ключ), токен сбрасывается и вызов повторяется один раз.
//
// Ходим на 127.0.0.1:<порт> мимо nginx — это и требует сторона-получатель
// (requireDirect): запрос через nginx она не примет.

class InternalCallError extends Error {
    constructor({ service, method, path, status, body, cause }) {
        const where = `${method} ${service}${path}`;
        super(status ? `внутренний вызов ${where} → ${status}` : `внутренний вызов ${where} не выполнен: ${cause && cause.message}`);
        this.name = 'InternalCallError';
        this.service = service;
        this.method = method;
        this.path = path;
        this.status = status || 0;     // 0 — ответа не было (таймаут, сеть)
        this.body = body;
        if (cause) this.cause = cause;
    }
}

function required(name, value) {
    if (!value) throw new Error(`@totaling/internal: не задан ${name}`);
    return value;
}

function trimSlash(url) {
    return String(url).replace(/\/+$/, '');
}

async function readBody(res) {
    const type = res.headers.get('content-type') || '';
    const text = await res.text();
    if (type.includes('application/json') && text) {
        try { return JSON.parse(text); } catch { return text; }
    }
    return text;
}

function createInternalClient(options = {}) {
    const authUrl = trimSlash(required('authUrl', options.authUrl));
    const clientId = required('clientId', options.clientId);
    const clientSecret = required('clientSecret', options.clientSecret);
    const services = required('services', options.services);
    const refreshAheadMs = (options.refreshAheadSec ?? 60) * 1000;
    const timeoutMs = options.timeoutMs ?? 5000;
    const fetchImpl = options.fetch || globalThis.fetch;
    const now = options.now || Date.now;

    if (typeof fetchImpl !== 'function') {
        throw new Error('@totaling/internal: нет fetch — нужен node 18+ или опция fetch');
    }

    let token = null;          // { value, expiresAt }
    let inflight = null;       // общий промис для одновременных вызовов

    async function requestToken() {
        let res;
        try {
            res = await fetchImpl(`${authUrl}/auth/internal/v1/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ clientId, clientSecret }),
                signal: AbortSignal.timeout(timeoutMs),
            });
        } catch (cause) {
            throw new InternalCallError({ service: 'auth', method: 'POST', path: '/auth/internal/v1/token', cause });
        }
        const body = await readBody(res);
        if (!res.ok || !body || !body.accessToken) {
            // тело ответа auth безопасно: секрета в нём нет никогда
            throw new InternalCallError({ service: 'auth', method: 'POST', path: '/auth/internal/v1/token', status: res.status, body });
        }
        return { value: body.accessToken, expiresAt: now() + Number(body.expiresIn) * 1000 };
    }

    async function getToken() {
        if (token && now() < token.expiresAt - refreshAheadMs) return token.value;
        if (!inflight) {
            inflight = requestToken()
                .then((t) => { token = t; return t.value; })
                .finally(() => { inflight = null; });
        }
        return inflight;
    }

    function buildUrl(service, path, query) {
        const base = services[service];
        if (!base) throw new Error(`@totaling/internal: неизвестный сервис "${service}" (есть: ${Object.keys(services).join(', ')})`);
        const url = new URL(trimSlash(base) + path);
        for (const [k, v] of Object.entries(query || {})) {
            if (v === undefined || v === null) continue;
            if (Array.isArray(v)) v.forEach((x) => url.searchParams.append(k, String(x)));
            else url.searchParams.set(k, String(v));
        }
        return url;
    }

    async function request(service, method, path, { query, body } = {}) {
        const url = buildUrl(service, path, query);

        for (let attempt = 1; ; attempt++) {
            const bearer = await getToken();
            let res;
            try {
                res = await fetchImpl(url, {
                    method,
                    headers: {
                        Authorization: `Bearer ${bearer}`,
                        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
                    },
                    body: body !== undefined ? JSON.stringify(body) : undefined,
                    signal: AbortSignal.timeout(timeoutMs),
                });
            } catch (cause) {
                throw new InternalCallError({ service, method, path, cause });
            }

            // 401 от владельца: токен устарел раньше срока — берём новый и пробуем ещё раз
            if (res.status === 401 && attempt === 1) {
                token = null;
                await res.text().catch(() => {});
                continue;
            }

            const data = await readBody(res);
            if (!res.ok) throw new InternalCallError({ service, method, path, status: res.status, body: data });
            return data;
        }
    }

    return {
        request,
        get: (service, path, query) => request(service, 'GET', path, { query }),
        post: (service, path, body, query) => request(service, 'POST', path, { body, query }),
        // для диагностики и тестов; токен наружу не отдаём
        _state: () => ({ hasToken: !!token, expiresAt: token && token.expiresAt }),
    };
}

// Конфигурация из окружения. Адреса сервисов НЕ угадываются: порты у окружений
// разные (прод 3001/3002, staging 3031/3032), поэтому всё задаётся явно, а при
// нехватке переменной сервис падает на старте, а не на первом вызове.
//   INTERNAL_AUTH_URL       http://127.0.0.1:3004
//   INTERNAL_CLIENT_ID      client-api
//   INTERNAL_CLIENT_SECRET  …
//   INTERNAL_URL_<СЕРВИС>   INTERNAL_URL_MANAGER=http://127.0.0.1:3001, INTERNAL_URL_LAB=…
createInternalClient.fromEnv = function fromEnv(env = process.env, extra = {}) {
    const services = {};
    for (const [k, v] of Object.entries(env)) {
        const m = /^INTERNAL_URL_([A-Z0-9_]+)$/.exec(k);
        if (m && v) services[m[1].toLowerCase()] = v;
    }
    const missing = ['INTERNAL_AUTH_URL', 'INTERNAL_CLIENT_ID', 'INTERNAL_CLIENT_SECRET'].filter((k) => !env[k]);
    if (missing.length) throw new Error(`@totaling/internal: не заданы ${missing.join(', ')}`);
    if (!Object.keys(services).length) throw new Error('@totaling/internal: не задан ни один INTERNAL_URL_<СЕРВИС>');
    return createInternalClient({
        authUrl: env.INTERNAL_AUTH_URL,
        clientId: env.INTERNAL_CLIENT_ID,
        clientSecret: env.INTERNAL_CLIENT_SECRET,
        services,
        ...extra,
    });
};

module.exports = { createInternalClient, InternalCallError };
