/**
 * DUEL database layer (Turso / libSQL)
 * Exposes the same callback style as sqlite3 (db.run / db.get / db.all / db.serialize)
 * so the rest of server.js works unchanged.
 *
 * - On Render: set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN -> data persists.
 * - Locally: if those are not set, it uses a local file (duel.db).
 */
require('dotenv').config();
const { createClient } = require('@libsql/client');

const url = process.env.TURSO_DATABASE_URL || 'file:duel.db';
const client = createClient({
  url,
  authToken: process.env.TURSO_AUTH_TOKEN || undefined
});

// Run queries one at a time, in the order they were issued
let queue = Promise.resolve();

function normalize(params, cb) {
  if (typeof params === 'function') return { params: [], cb: params };
  return { params: params || [], cb };
}

function toPlain(result) {
  return result.rows.map((row) => {
    const obj = {};
    result.columns.forEach((col, i) => {
      obj[col] = row[i];
    });
    return obj;
  });
}

function execute(sql, params, cb, mode) {
  const args = params.map((p) => (p === undefined ? null : p));
  queue = queue.then(async () => {
    let err = null;
    let out;
    try {
      const result = await client.execute({ sql, args });
      const rows = toPlain(result);
      out = mode === 'get' ? rows[0] : mode === 'all' ? rows : undefined;
    } catch (e) {
      err = e;
      if (!cb) console.error('DB error:', e.message);
    }
    if (cb) {
      try {
        cb(err, out);
      } catch (e) {
        console.error('Callback error:', e);
      }
    }
  });
}

const db = {
  run(sql, params, cb) {
    const n = normalize(params, cb);
    execute(sql, n.params, n.cb, 'run');
  },
  get(sql, params, cb) {
    const n = normalize(params, cb);
    execute(sql, n.params, n.cb, 'get');
  },
  all(sql, params, cb) {
    const n = normalize(params, cb);
    execute(sql, n.params, n.cb, 'all');
  },
  serialize(fn) {
    fn(); // queries already run in order
  }
};

console.log(`✅ Database: ${url.startsWith('file:') ? 'local file (data resets on Render free!)' : 'Turso (persistent)'}`);

module.exports = db;
