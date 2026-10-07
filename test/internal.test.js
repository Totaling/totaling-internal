// npm test — встроенный node:test, настоящие HTTP-серверы: поддельный auth
// выдаёт токены, поддельный сервис-владелец закрыт requireInternal.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const { createInternalClient, InternalCallError, requireInternal } = require('..');

const ISSUER = 'totaling-auth';
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const SECRETS = { 'client-api': 's3cret', 'lab-api': 'lab-secret' };
const SCOPES = { 'client-api': ['lab:content:read'], 'lab-api': ['manager:content-usage'] };

// ── инфраструктура тестов ───────────────────────────────────────────────────

function listen(handler) {
    return new Promise((resolve) => {
        const srv = http.createServer(handler);
        srv.listen(0, '127.0.0.1', () => resolve({ srv, url: `http://127.0.0.1:${srv.address().port}` }));
    });
}

function readJson(req) {
    return new Promise((resolve) => {
        let b = '';
        req.on('data', (c) => { b += c; });
        req.on('end', () => resolve(b ? JSON.parse(b) : {}));
    });
}

// express-подобные res.status().json() поверх голого http
function expressish(req, res) {
    res.status = (c) => { res.statusCode = c; return res; };
    res.json = (b) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(b)); return res; };
    req.originalUrl = req.url;
    return [req, res];
}

const auth = { calls: 0, expiresIn: 900, srv: null, url: null };
const owner = { hits: 0, mode: 'ok', rejectBefore: 0, srv: null, url: null };

const internal = requireInternal({ publicKey, issuer: ISSUER, log: () => {} });
const routes = {
    '/internal/v1/content': internal('lab:content:read'),
    '/internal/v1/usage': internal('manager:content-usage'),
};

before(async () => {
    ({ srv: auth.srv, url: auth.url } = await listen(async (req, res) => {
        auth.calls++;
        const { clientId, clientSecret } = await readJson(req);
        res.setHeader('content-type', 'application/json');
        if (!SECRETS[clientId] || SECRETS[clientId] !== clientSecret) {
            res.statusCode = 401;
            return res.end(JSON.stringify({ message: ['Invalid client credentials'] }));
        }
        const accessToken = jwt.sign({ scope: SCOPES[clientId] }, privateKey, {
            algorithm: 'RS256', audience: 'internal', issuer: ISSUER, subject: clientId, expiresIn: auth.expiresIn,
        });
        res.end(JSON.stringify({ accessToken, tokenType: 'Bearer', expiresIn: auth.expiresIn }));
    }));

    ({ srv: owner.srv, url: owner.url } = await listen((rawReq, rawRes) => {
        owner.hits++;
        const [req, res] = expressish(rawReq, rawRes);
        if (owner.mode === 'hang') return;                         // не отвечаем вовсе
        if (owner.mode === 'forbidden') return res.status(403).json({ message: ['nope'] });
        if (owner.mode === 'always401') return res.status(401).json({ message: ['Invalid token'] });
        // «auth перевыпустил ключ»: токены, выданные раньше метки, больше не принимаются
        if (owner.rejectBefore) {
            const iat = jwt.decode((req.headers.authorization || '').split(' ')[1] || '')?.iat || 0;
            if (iat * 1000 < owner.rejectBefore) return res.status(401).json({ message: ['Invalid token'] });
        }
        const path = req.url.split('?')[0];
        const guard = routes[path];
        if (!guard) return res.status(404).json({ message: ['Not found'] });
        guard(req, res, () => res.status(200).json({ service: req.service.id, query: req.url.split('?')[1] || '' }));
    }));
});

after(() => { auth.srv.close(); owner.srv.close(); });

function reset() {
    auth.calls = 0; auth.expiresIn = 900;
    owner.hits = 0; owner.mode = 'ok'; owner.rejectBefore = 0;
}

function client(extra = {}) {
    return createInternalClient({
        authUrl: auth.url,
        clientId: 'client-api',
        clientSecret: SECRETS['client-api'],
        services: { lab: owner.url, manager: owner.url },
        ...extra,
    });
}

// ── клиент ──────────────────────────────────────────────────────────────────

test('сквозной вызов: токен у auth, проверка у владельца, req.service', async () => {
    reset();
    const r = await client().get('lab', '/internal/v1/content');
    assert.equal(r.service, 'client-api');
});

test('токен переиспользуется: три вызова подряд — один запрос к auth', async () => {
    reset();
    const c = client();
    for (let i = 0; i < 3; i++) await c.get('lab', '/internal/v1/content');
    assert.equal(auth.calls, 1);
});

test('одновременные вызовы делят один запрос токена', async () => {
    reset();
    const c = client();
    await Promise.all(Array.from({ length: 8 }, () => c.get('lab', '/internal/v1/content')));
    assert.equal(auth.calls, 1);
});

test('токен обновляется заранее, за refreshAheadSec до истечения', async () => {
    reset();
    let t = 1_000_000;
    const c = client({ now: () => t, refreshAheadSec: 60 });
    await c.get('lab', '/internal/v1/content');
    t += 830 * 1000;                                   // до истечения 70 с — ещё рано
    await c.get('lab', '/internal/v1/content');
    assert.equal(auth.calls, 1);
    t += 20 * 1000;                                    // до истечения 50 с — пора
    await c.get('lab', '/internal/v1/content');
    assert.equal(auth.calls, 2);
});

test('401 от владельца (ключ перевыпущен) — новый токен и один повтор', async () => {
    reset();
    const c = client();
    await c.get('lab', '/internal/v1/content');        // токен закеширован
    await new Promise((r) => setTimeout(r, 1100));     // iat — в секундах
    // iat в токене — целые секунды (округление вниз), метка тоже на границе секунды:
    // старый токен выдан не меньше секунды назад, новый — в эту секунду или позже
    owner.rejectBefore = Math.floor(Date.now() / 1000) * 1000;
    const r = await c.get('lab', '/internal/v1/content');
    assert.equal(r.service, 'client-api');
    assert.equal(auth.calls, 2);
});

test('постоянный 401 — ровно один повтор, потом ошибка', async () => {
    reset();
    owner.mode = 'always401';
    await assert.rejects(client().get('lab', '/internal/v1/content'), (e) => e instanceof InternalCallError && e.status === 401);
    assert.equal(owner.hits, 2);
});

test('прочие ошибки владельца не повторяются и приходят со статусом', async () => {
    reset();
    owner.mode = 'forbidden';
    await assert.rejects(client().get('lab', '/internal/v1/content'), (e) => e.status === 403 && e.service === 'lab');
    assert.equal(owner.hits, 1);
});

test('неверный секрет — ошибка от auth, без секрета в тексте', async () => {
    reset();
    const err = await client({ clientSecret: 'wrong-secret-value' }).get('lab', '/internal/v1/content').catch((e) => e);
    assert.ok(err instanceof InternalCallError);
    assert.equal(err.service, 'auth');
    assert.equal(err.status, 401);
    assert.ok(!JSON.stringify({ m: err.message, b: err.body }).includes('wrong-secret-value'));
});

test('владелец не отвечает — ошибка по таймауту, status 0', async () => {
    reset();
    const c = client({ timeoutMs: 200 });
    await c.get('lab', '/internal/v1/usage').catch(() => {});      // прогреть токен (403 — не важно)
    owner.mode = 'hang';
    const t0 = Date.now();
    const err = await c.get('lab', '/internal/v1/content').catch((e) => e);
    assert.equal(err.status, 0);
    assert.ok(Date.now() - t0 < 2000);
});

test('массив в query раскладывается в повторяющийся параметр', async () => {
    reset();
    const r = await client().get('lab', '/internal/v1/content', { uids: ['a', 'b'], skip: undefined });
    assert.equal(r.query, 'uids=a&uids=b');
});

test('неизвестный сервис — понятная ошибка', async () => {
    await assert.rejects(client().get('nope', '/x'), /неизвестный сервис "nope"/);
});

test('fromEnv: без обязательных переменных падает сразу, со списком', () => {
    assert.throws(() => createInternalClient.fromEnv({}), /INTERNAL_AUTH_URL, INTERNAL_CLIENT_ID, INTERNAL_CLIENT_SECRET/);
    assert.throws(() => createInternalClient.fromEnv({ INTERNAL_AUTH_URL: 'x', INTERNAL_CLIENT_ID: 'y', INTERNAL_CLIENT_SECRET: 'z' }),
        /ни один INTERNAL_URL_/);
    const c = createInternalClient.fromEnv({
        INTERNAL_AUTH_URL: auth.url, INTERNAL_CLIENT_ID: 'client-api', INTERNAL_CLIENT_SECRET: 's3cret',
        INTERNAL_URL_LAB: owner.url,
    });
    return c.get('lab', '/internal/v1/content');
});

// ── сторона владельца ───────────────────────────────────────────────────────

async function raw(path, headers = {}) {
    const res = await fetch(owner.url + path, { headers });
    return { status: res.status, body: await res.json() };
}

function serviceToken(over = {}) {
    return jwt.sign({ scope: over.scope ?? ['lab:content:read'] }, privateKey, {
        algorithm: 'RS256', audience: over.aud ?? 'internal', issuer: over.iss ?? ISSUER,
        subject: 'client-api', expiresIn: over.exp ?? 60,
    });
}

test('нет нужного права — 403', async () => {
    reset();
    const err = await client().get('lab', '/internal/v1/usage').catch((e) => e);
    assert.equal(err.status, 403);
});

test('без токена — 401', async () => {
    reset();
    assert.equal((await raw('/internal/v1/content')).status, 401);
});

test('пользовательский токен (aud=staff) — 401', async () => {
    reset();
    const r = await raw('/internal/v1/content', { Authorization: `Bearer ${serviceToken({ aud: 'staff' })}` });
    assert.equal(r.status, 401);
});

test('чужой issuer и истёкший токен — 401', async () => {
    reset();
    assert.equal((await raw('/internal/v1/content', { Authorization: `Bearer ${serviceToken({ iss: 'evil' })}` })).status, 401);
    assert.equal((await raw('/internal/v1/content', { Authorization: `Bearer ${serviceToken({ exp: -10 })}` })).status, 401);
});

test('токен, подписанный чужим ключом, — 401', async () => {
    reset();
    const { privateKey: other } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    const forged = jwt.sign({ scope: ['lab:content:read'] }, other, { algorithm: 'RS256', audience: 'internal', issuer: ISSUER, subject: 'client-api', expiresIn: 60 });
    assert.equal((await raw('/internal/v1/content', { Authorization: `Bearer ${forged}` })).status, 401);
});

test('запрос через nginx (X-Real-IP / X-Forwarded-For) — 404 даже с верным токеном', async () => {
    reset();
    const auth_ = { Authorization: `Bearer ${serviceToken()}` };
    assert.equal((await raw('/internal/v1/content', { ...auth_, 'X-Real-IP': '8.8.8.8' })).status, 404);
    assert.equal((await raw('/internal/v1/content', { ...auth_, 'X-Forwarded-For': '8.8.8.8' })).status, 404);
    assert.equal((await raw('/internal/v1/content', auth_)).status, 200);
});

test('маршрут без права — ошибка уже при подключении', () => {
    assert.throws(() => internal(), /должно быть указано право/);
    assert.throws(() => requireInternal({ issuer: ISSUER }), /без publicKey/);
});
