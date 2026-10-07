// @totaling/internal — внутренние вызовы между сервисами Totaling.
// Подробно: README.md; решение — DECISIONS.md, ADR-0002/0003/0009.
const { createInternalClient, InternalCallError } = require('./src/client');
const { requireInternal, requireDirect } = require('./src/middleware');

module.exports = { createInternalClient, InternalCallError, requireInternal, requireDirect };
