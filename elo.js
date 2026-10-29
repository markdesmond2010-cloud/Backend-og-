/**
 * DUEL Elo ranking (Facemash style)
 *
 * - Every photo starts at 1000.
 * - expected = 1 / (1 + 10 ^ ((opponent - me) / 400))
 * - winner gains K * (1 - expected), loser loses K * expected, with K = 32.
 * - Wins, losses and matchesPlayed are updated together with the ratings.
 *
 * This uses DUEL's own database layer (db.js, Turso/SQLite), so it plugs
 * straight into the existing voting route. The maths is the same as it would be
 * on Firebase or Supabase; only the three small query helpers below would change.
 */
const db = require('./db');

const START_ELO = 1000;
const K_FACTOR = 32;

// ---- tiny promise helpers around db.js ----
const run = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, (e) => (e ? reject(e) : resolve())));
const get = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => (e ? reject(e) : resolve(r))));
const all = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => (e ? reject(e) : resolve(r || []))));

// ---- pure maths (easy to test) ----

// Chance that a photo rated ratingA beats a photo rated ratingB
function expectedScore(ratingA, ratingB) {
  return 1 / (1 + Math.pow(10, (ratingB - ratingA) / 400));
}

function calculateNewRatings(winnerRating, loserRating, k = K_FACTOR) {
  const expectedWinner = expectedScore(winnerRating, loserRating);
  const expectedLoser = 1 - expectedWinner;

  const winnerDelta = k * (1 - expectedWinner); // winner: actual score 1
  const loserDelta = k * (0 - expectedLoser); // loser: actual score 0

  return {
    expectedWinner,
    winnerDelta,
    loserDelta,
    winnerAfter: winnerRating + winnerDelta,
    loserAfter: loserRating + loserDelta
  };
}

// Only one rating update runs at a time, so two quick votes can never overwrite each other
let lock = Promise.resolve();
function withLock(fn) {
  const next = lock.then(fn);
  lock = next.catch(() => {});
  return next;
}

// Reads both ratings, calculates, saves the new ratings and updates wins/losses
function updateElo(winnerId, loserId) {
  return withLock(async () => {
    if (!winnerId || !loserId || winnerId === loserId) throw new Error('Need two different photos');

    const winner = await get(`SELECT id, rating FROM photos WHERE id = ?`, [winnerId]);
    const loser = await get(`SELECT id, rating FROM photos WHERE id = ?`, [loserId]);
    if (!winner || !loser) throw new Error('Photo not found');

    const winnerBefore = winner.rating ?? START_ELO;
    const loserBefore = loser.rating ?? START_ELO;
    const calc = calculateNewRatings(winnerBefore, loserBefore);
    const now = Date.now();

    await run(
      `UPDATE photos SET rating = ?, wins = COALESCE(wins, 0) + 1, matchesPlayed = COALESCE(matchesPlayed, 0) + 1, updatedAt = ? WHERE id = ?`,
      [calc.winnerAfter, now, winnerId]
    );
    await run(
      `UPDATE photos SET rating = ?, losses = COALESCE(losses, 0) + 1, matchesPlayed = COALESCE(matchesPlayed, 0) + 1, updatedAt = ? WHERE id = ?`,
      [calc.loserAfter, now, loserId]
    );

    return {
      expectedWinner: calc.expectedWinner,
      winner: { id: winnerId, before: winnerBefore, after: calc.winnerAfter, delta: calc.winnerDelta },
      loser: { id: loserId, before: loserBefore, after: calc.loserAfter, delta: calc.loserDelta }
    };
  });
}

// Puts every photo back to 1000 and replays all past votes in order with the Facemash rules.
// With { onlyOnce: true } it runs a single time (the first deploy after this update).
function recalculateAllRatings({ onlyOnce = false } = {}) {
  return withLock(async () => {
    await run(`CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT)`);
    if (onlyOnce) {
      const done = await get(`SELECT value FROM app_meta WHERE key = 'elo_v2'`);
      if (done) return null;
    }

    const photos = await all(`SELECT id FROM photos`);
    const state = new Map(photos.map((p) => [p.id, { rating: START_ELO, wins: 0, losses: 0, played: 0 }]));
    const matches = await all(`SELECT id, photoAId, photoBId, winnerId FROM matches ORDER BY timestamp ASC, id ASC`);

    const matchUpdates = [];
    let replayed = 0;

    for (const m of matches) {
      const loserId = m.winnerId === m.photoAId ? m.photoBId : m.photoAId;
      const w = state.get(m.winnerId);
      const l = state.get(loserId);
      if (!w || !l) continue;

      const calc = calculateNewRatings(w.rating, l.rating);
      const aIsWinner = m.winnerId === m.photoAId;
      matchUpdates.push([
        aIsWinner ? w.rating : l.rating,
        aIsWinner ? l.rating : w.rating,
        aIsWinner ? calc.winnerAfter : calc.loserAfter,
        aIsWinner ? calc.loserAfter : calc.winnerAfter,
        aIsWinner ? calc.winnerDelta : calc.loserDelta,
        aIsWinner ? calc.loserDelta : calc.winnerDelta,
        m.id
      ]);

      w.rating = calc.winnerAfter;
      w.wins += 1;
      w.played += 1;
      l.rating = calc.loserAfter;
      l.losses += 1;
      l.played += 1;
      replayed += 1;
    }

    for (const [id, s] of state) {
      await run(`UPDATE photos SET rating = ?, wins = ?, losses = ?, matchesPlayed = ? WHERE id = ?`, [
        s.rating,
        s.wins,
        s.losses,
        s.played,
        id
      ]);
    }
    for (const u of matchUpdates) {
      await run(
        `UPDATE matches SET ratingABefore = ?, ratingBBefore = ?, ratingAAfter = ?, ratingBAfter = ?, deltaA = ?, deltaB = ? WHERE id = ?`,
        u
      );
    }
    await run(`INSERT OR REPLACE INTO app_meta (key, value) VALUES ('elo_v2', ?)`, [String(Date.now())]);

    return { photos: photos.length, matches: replayed };
  });
}

module.exports = { START_ELO, K_FACTOR, expectedScore, calculateNewRatings, updateElo, recalculateAllRatings };
