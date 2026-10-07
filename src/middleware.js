// Проверка внутренних вызовов на стороне сервиса-владельца эндпоинта.
//
//   const { requireInternal } = require('@totaling/internal');
//   const internal = requireInternal({ publicKey, issuer });   // ключ auth уже есть в API
//   router.get('/internal/v1/content', internal('lab:content:read'), handler);
//
// По порядку:
//   1. запрос пришёл через nginx (X-Real-IP / X-Forwarded-For) → 404;
//   2. нет токена или он не проходит (подпись RS256, issuer, aud='internal',
//      срок) → 401;
//   3. у сервиса нет нужного права в scope → 403;
//   4. иначе req.service = { id, scope } и дальше.
//
// Право указывается у КАЖДОГО маршрута обязательно: внутренний маршрут без
// права — ошибка конфигурации, и падает она при старте, а не молча пропускает.
// Внутренние маршруты монтируются под /internal/v1/…, вне /api/: на api-хостах
// nginx отдаёт наружу только /api/…, так что снаружи их не видно по построению.

function requireDirect(req, res, next) {
    // Сервисы зовут друг друга на 127.0.0.1 мимо nginx, а nginx на публичных
    // хостах всегда ставит эти заголовки. Подделать их ОТСУТСТВИЕ через nginx
    // нельзя. Отвечаем как на несуществующий маршрут.
    if (req.headers['x-real-ip'] || req.headers['x-forwarded-for']) {
        return res.status(404).json({ message: ['Not found'] });
    }
    next();
}

function bearer(req) {
    const h = req.headers.authorization;
    if (h && h.split(' ')[0] === 'Bearer') return h.split(' ')[1];
    return null;
}

function requireInternal({ publicKey, issuer, audience = 'internal', jwt = require('jsonwebtoken'), log = console.log } = {}) {
    if (!publicKey) throw new Error('@totaling/internal: requireInternal без publicKey');
    if (!issuer) throw new Error('@totaling/internal: requireInternal без issuer');

    return function internal(scope) {
        if (typeof scope !== 'string' || !scope) {
            throw new Error('@totaling/internal: у внутреннего маршрута должно быть указано право, например internal("lab:content:read")');
        }

        return function internalGuard(req, res, next) {
            return requireDirect(req, res, () => {
                const token = bearer(req);
                if (!token) return res.status(401).json({ message: ['Token is missing'] });

                let decoded;
                try {
                    decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'], audience, issuer });
                } catch (err) {
                    return res.status(401).json({ message: ['Invalid token'] });
                }

                const granted = Array.isArray(decoded.scope) ? decoded.scope : [];
                if (!granted.includes(scope)) {
                    log(`[internal] сервису "${decoded.sub}" не выдано право ${scope} (${req.method} ${req.originalUrl || req.url})`);
                    return res.status(403).json({ message: ['Forbidden'] });
                }

                req.service = { id: decoded.sub, scope: granted };
                next();
            });
        };
    };
}

module.exports = { requireInternal, requireDirect };
