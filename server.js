/**
 * DUEL - Photo Voting App Backend
 * Real-user authentication, Cloudinary storage, Elo ratings
 * 
 * Run: npm install && npm start
 * API: http://localhost:5000
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const CLOUDINARY_API = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_NAME = process.env.CLOUDINARY_NAME;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// Initialize database tables
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE,
        googleId TEXT UNIQUE,
        username TEXT UNIQUE NOT NULL,
        displayName TEXT NOT NULL,
        bio TEXT,
        passwordHash TEXT,
        profileImage TEXT,
        createdAt INTEGER,
        updatedAt INTEGER
      )
    `);

    // Photos table
    db.run(`
      CREATE TABLE IF NOT EXISTS photos (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        title TEXT NOT NULL,
        imageUrl TEXT NOT NULL,
        cloudinaryId TEXT,
        rating REAL DEFAULT 1600,
        matchesPlayed INTEGER DEFAULT 0,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        createdAt INTEGER,
        updatedAt INTEGER,
        FOREIGN KEY(userId) REFERENCES users(id)
      )
    `);

    // Matches/Votes table
    db.run(`
      CREATE TABLE IF NOT EXISTS matches (
        id TEXT PRIMARY KEY,
        photoAId TEXT NOT NULL,
        photoBId TEXT NOT NULL,
        winnerId TEXT NOT NULL,
        userId TEXT NOT NULL,
        ratingABefore REAL,
        ratingBBefore REAL,
        ratingAAfter REAL,
        ratingBAfter REAL,
        deltaA REAL,
        deltaB REAL,
        timestamp INTEGER,
        FOREIGN KEY(photoAId) REFERENCES photos(id),
        FOREIGN KEY(photoBId) REFERENCES photos(id),
        FOREIGN KEY(winnerId) REFERENCES photos(id),
        FOREIGN KEY(userId) REFERENCES users(id)
      )
    `);

    // Reports table (users flag photos; admin reviews them)
    db.run(`
      CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        photoId TEXT NOT NULL,
        reporterId TEXT NOT NULL,
        reason TEXT,
        status TEXT DEFAULT 'open',
        createdAt INTEGER,
        UNIQUE(photoId, reporterId)
      )
    `);

    // Invite tracking (adds the column to existing databases; error ignored if it already exists)
    db.run(`ALTER TABLE users ADD COLUMN invitedBy TEXT`, [], () => {});
    db.run(`ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0`, [], () => {});
    db.run(`ALTER TABLE photos ADD COLUMN category TEXT DEFAULT 'selfies'`, [], () => {});

    // Challenges: a direct duel between two specific photos
    db.run(`
      CREATE TABLE IF NOT EXISTS challenges (
        id TEXT PRIMARY KEY,
        fromUserId TEXT NOT NULL,
        toUserId TEXT NOT NULL,
        fromPhotoId TEXT NOT NULL,
        toPhotoId TEXT,
        status TEXT DEFAULT 'pending',
        createdAt INTEGER,
        acceptedAt INTEGER,
        endsAt INTEGER
      )
    `);

    // Engagement: Clout points, activity tracking, notifications, push subscriptions
    db.run(`ALTER TABLE users ADD COLUMN clout INTEGER DEFAULT 0`, [], () => {});
    db.run(`ALTER TABLE users ADD COLUMN welcomed INTEGER DEFAULT 0`, [], () => {});
    db.run(`ALTER TABLE users ADD COLUMN lastActiveAt INTEGER`, [], () => {});
    db.run(`ALTER TABLE users ADD COLUMN lastReminderAt INTEGER`, [], () => {});
    db.run(`ALTER TABLE users ADD COLUMN reminderStreak INTEGER DEFAULT 0`, [], () => {});
    db.run(`ALTER TABLE users ADD COLUMN achievementsSeen TEXT`, [], () => {});
    db.run(`ALTER TABLE users ADD COLUMN tierSeen TEXT`, [], () => {});

    db.run(`
      CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        type TEXT,
        text TEXT,
        link TEXT,
        ref TEXT,
        count INTEGER DEFAULT 1,
        createdAt INTEGER,
        readAt INTEGER
      )
    `);
    db.run(`CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(userId, createdAt)`, [], () => {});
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_welcome ON notifications(userId) WHERE type = 'welcome'`, [], () => {});

    db.run(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        endpoint TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        p256dh TEXT,
        auth TEXT,
        createdAt INTEGER
      )
    `);

    console.log('✅ Database tables initialized');
  });
}

initializeDatabase();

// ==================== AUTHENTICATION ====================

// JWT token generation
function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
}

// Verify JWT middleware
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  req.userId = decoded.userId;
  db.get(`SELECT banned, lastActiveAt FROM users WHERE id = ?`, [req.userId], (err, row) => {
    if (row && row.banned) return res.status(403).json({ error: 'This account has been suspended' });
    // Remember when someone was last active (at most once every 10 minutes)
    if (row && (!row.lastActiveAt || Date.now() - row.lastActiveAt > 10 * 60 * 1000)) {
      db.run(`UPDATE users SET lastActiveAt = ?, reminderStreak = 0 WHERE id = ?`, [Date.now(), req.userId]);
    }
    next();
  });
}

// Admin emails (comma separated in ADMIN_EMAILS env variable)
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',')
  .map((e) => e.trim().toLowerCase())
  .filter(Boolean);

function isAdminEmail(email) {
  return !!email && ADMIN_EMAILS.includes(String(email).toLowerCase());
}

// Admin-only middleware (use after verifyToken)
function requireAdmin(req, res, next) {
  db.get(`SELECT email FROM users WHERE id = ?`, [req.userId], (err, user) => {
    if (err || !user || !isAdminEmail(user.email)) {
      return res.status(403).json({ error: 'Admins only' });
    }
    next();
  });
}

// Remove a photo and everything attached to it
function deletePhotoCompletely(photoId, cb) {
  db.run(`DELETE FROM matches WHERE photoAId = ? OR photoBId = ? OR winnerId = ?`, [photoId, photoId, photoId]);
  db.run(`DELETE FROM reports WHERE photoId = ?`, [photoId]);
  db.run(`UPDATE challenges SET status = 'cancelled' WHERE fromPhotoId = ? OR toPhotoId = ?`, [photoId, photoId]);
  db.run(`DELETE FROM photos WHERE id = ?`, [photoId], cb);
}

// Find the user who invited someone (ref = their username)
function resolveReferrer(ref, cb) {
  if (!ref || typeof ref !== 'string') return cb(null);
  db.get(`SELECT id FROM users WHERE LOWER(username) = LOWER(?)`, [ref.trim()], (err, row) => {
    cb(!err && row ? row.id : null);
  });
}

// ---- Usernames (used in share links like /u/majormark) ----
const USERNAME_RE = /^[a-z0-9_]{3,20}$/i;
const RESERVED_USERNAMES = ['u', 'api', 'auth', 'admin', 'www', 'duel', 'login', 'signup', 'support', 'help', 'privacy', 'terms', 'about', 'root', 'null'];

// Find a free short username from a base (e.g. the part of an email before @)
function pickUsername(base, cb) {
  let clean = String(base || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 15);
  if (clean.length < 3) clean = (clean + 'user').slice(0, 15);
  if (RESERVED_USERNAMES.includes(clean)) clean += '1';

  const attempt = (i) => {
    const candidate = i === 0 ? clean : clean + Math.floor(Math.random() * (i < 4 ? 100 : 100000));
    db.get(`SELECT id FROM users WHERE LOWER(username) = LOWER(?)`, [candidate], (err, row) => {
      if (!err && !row) return cb(candidate);
      if (i >= 8) return cb(clean + Date.now().toString(36).slice(-5));
      attempt(i + 1);
    });
  };
  attempt(0);
}

// Simple vote rate limit: at most 15 votes per 30 seconds per account
const voteLog = new Map();
function tooManyVotes(userId) {
  const now = Date.now();
  const recent = (voteLog.get(userId) || []).filter((t) => now - t < 30000);
  if (recent.length >= 15) {
    voteLog.set(userId, recent);
    return true;
  }
  recent.push(now);
  voteLog.set(userId, recent);
  return false;
}

// ---- Tiers, achievements and card labels ----
// Tiers are based on a user's total wins (votes received on their photos)
const TIERS = [
  { name: 'Beginner', emoji: '🌱', min: 0 },
  { name: 'Contender', emoji: '⚔️', min: 5 },
  { name: 'Challenger', emoji: '🥈', min: 25 },
  { name: 'Elite', emoji: '💎', min: 100 },
  { name: 'Champion', emoji: '👑', min: 300 }
];

function tierFor(wins) {
  let idx = 0;
  TIERS.forEach((t, i) => {
    if (wins >= t.min) idx = i;
  });
  const cur = TIERS[idx];
  const next = TIERS[idx + 1] || null;
  return {
    name: cur.name,
    emoji: cur.emoji,
    min: cur.min,
    nextName: next ? next.name : null,
    nextMin: next ? next.min : null,
    wins
  };
}

// Everything achievements and tiers need to know about a user
function userStats(userId, cb) {
  db.all(`SELECT id, wins, matchesPlayed FROM photos WHERE userId = ?`, [userId], (e1, photos) => {
    const list = photos || [];
    const wins = list.reduce((sum, p) => sum + (p.wins || 0), 0);
    const battles = list.reduce((sum, p) => sum + (p.matchesPlayed || 0), 0);

    db.get(`SELECT COUNT(*) AS n FROM matches WHERE userId = ?`, [userId], (e2, v) => {
      db.all(
        `SELECT m.winnerId AS winnerId, p.id AS pid
         FROM matches m JOIN photos p ON (p.id = m.photoAId OR p.id = m.photoBId)
         WHERE p.userId = ? ORDER BY m.timestamp ASC`,
        [userId],
        (e3, rows) => {
          let run = 0;
          let best = 0;
          (rows || []).forEach((r) => {
            if (r.winnerId === r.pid) {
              run += 1;
              if (run > best) best = run;
            } else {
              run = 0;
            }
          });

          db.all(
            `SELECT (SELECT COUNT(*) + 1 FROM photos p2
                     WHERE p2.matchesPlayed >= 1
                       AND (p2.rating > p.rating OR (p2.rating = p.rating AND p2.matchesPlayed > p.matchesPlayed))) AS rank
             FROM photos p WHERE p.userId = ? AND p.matchesPlayed >= 10`,
            [userId],
            (e4, ranked) => {
              const ranks = (ranked || []).map((r) => r.rank);
              cb({
                wins,
                battles,
                votesCast: v?.n || 0,
                bestStreak: best,
                topRank: ranks.length ? Math.min(...ranks) : null
              });
            }
          );
        }
      );
    });
  });
}

function buildAchievements(st) {
  const defs = [
    { id: 'first_victory', name: 'First Victory', description: 'Win your first duel', current: st.wins, target: 1 },
    { id: 'rising_star', name: 'Rising Star', description: 'Win 10 duels', current: st.wins, target: 10 },
    { id: 'crowd_favourite', name: 'Crowd Favourite', description: 'Receive 100 votes', current: st.wins, target: 100 },
    { id: 'unstoppable', name: 'Unstoppable', description: 'Win 5 duels in a row', current: st.bestStreak, target: 5 },
    {
      id: 'peoples_champion',
      name: "People's Champion",
      description: 'Get a photo into the top 3 (needs 10+ battles)',
      current: st.topRank && st.topRank <= 3 ? 1 : 0,
      target: 1
    },
    { id: 'familiar_face', name: 'Familiar Face', description: 'Vote in 100 duels', current: st.votesCast, target: 100 }
  ];
  return defs.map((d) => ({ ...d, current: Math.min(d.current, d.target), earned: d.current >= d.target }));
}

// Precise label for the share card. "Champion" is only used when the ranking really supports it.
function cardLabel({ rank, total, matchesPlayed, wins, userWins }) {
  if (rank === 1 && total >= 10 && matchesPlayed >= 10) return 'DUEL CHAMPION';
  if (rank && rank <= 3 && total >= 3 && matchesPlayed >= 3) return 'TOP-RATED PHOTO';
  if (wins >= 10) return 'COMMUNITY FAVOURITE';
  if (userWins >= 10) return 'RISING STAR';
  if (userWins === 1) return 'FIRST VICTORY';
  if (rank) return 'ON THE BOARD';
  return 'NEW CHALLENGER';
}

// ---- Categories ----
const CATEGORIES = {
  fashion: 'Fashion & Outfits',
  selfies: 'Selfies & Personal Style',
  photography: 'Photography & Creativity'
};

// ---- Rate limits (in memory; resets when the server restarts) ----
function makeLimiter(windowMs, max, message, keyFn) {
  const hits = new Map();
  return (req, res, next) => {
    const key = keyFn ? keyFn(req) : req.ip;
    const now = Date.now();
    const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
    if (recent.length >= max) {
      hits.set(key, recent);
      return res.status(429).json({ error: message });
    }
    recent.push(now);
    hits.set(key, recent);
    next();
  };
}
const authLimiter = makeLimiter(15 * 60 * 1000, 30, 'Too many attempts. Try again in a few minutes.');
const signupLimiter = makeLimiter(60 * 60 * 1000, 8, 'Too many sign-ups from this network. Try again later.');
const uploadLimiter = makeLimiter(10 * 60 * 1000, 6, 'You are uploading too fast. Try again in a few minutes.', (req) => req.userId);
const challengeLimiter = makeLimiter(60 * 60 * 1000, 10, 'Too many challenges. Try again later.', (req) => req.userId);
const MAX_PHOTOS_PER_USER = 20;

// ---- Battle tokens: a vote is only accepted for a battle the server actually served ----
function signMatchToken(userId, a, b) {
  return jwt.sign({ k: 'match', u: userId, a, b }, JWT_SECRET, { expiresIn: '15m' });
}

// ---- Small promise wrappers for the analytics queries ----
const dbGet = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => (e ? reject(e) : resolve(r))));
const dbAll = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => (e ? reject(e) : resolve(r || []))));

// ---- Challenges ----
function challengeRows(whereSql, params, cb) {
  db.all(
    `SELECT c.*, fu.username AS fromUsername, fu.displayName AS fromName,
            tu.username AS toUsername, tu.displayName AS toName,
            fp.imageUrl AS fromImage, fp.title AS fromTitle,
            tp.imageUrl AS toImage, tp.title AS toTitle
     FROM challenges c
     JOIN users fu ON fu.id = c.fromUserId
     JOIN users tu ON tu.id = c.toUserId
     JOIN photos fp ON fp.id = c.fromPhotoId
     LEFT JOIN photos tp ON tp.id = c.toPhotoId
     WHERE ${whereSql}
     ORDER BY c.createdAt DESC LIMIT 30`,
    params,
    cb
  );
}

function shapeChallenge(r, counts) {
  const base = {
    id: r.id,
    status: r.status,
    createdAt: r.createdAt,
    acceptedAt: r.acceptedAt,
    endsAt: r.endsAt,
    from: { userId: r.fromUserId, username: r.fromUsername, displayName: r.fromName, photoId: r.fromPhotoId, imageUrl: r.fromImage, title: r.fromTitle },
    to: { userId: r.toUserId, username: r.toUsername, displayName: r.toName, photoId: r.toPhotoId, imageUrl: r.toImage, title: r.toTitle }
  };
  if (!counts) return base;
  const votesFrom = (counts.find((c) => c.winnerId === r.fromPhotoId) || {}).n || 0;
  const votesTo = (counts.find((c) => c.winnerId === r.toPhotoId) || {}).n || 0;
  const ended = Date.now() > r.endsAt;
  let winner = null;
  if (ended) winner = votesFrom > votesTo ? 'from' : votesTo > votesFrom ? 'to' : 'tie';
  return { ...base, votesFrom, votesTo, total: votesFrom + votesTo, ended, winner };
}

function addBattleCounts(rows, cb) {
  if (!rows.length) return cb([]);
  const out = [];
  let left = rows.length;
  rows.forEach((r, i) => {
    if (r.status !== 'accepted') {
      out[i] = shapeChallenge(r, null);
      if (--left === 0) cb(out);
      return;
    }
    db.all(
      `SELECT winnerId, COUNT(*) AS n FROM matches
       WHERE (photoAId = ? AND photoBId = ?) OR (photoAId = ? AND photoBId = ?)
       GROUP BY winnerId`,
      [r.fromPhotoId, r.toPhotoId, r.toPhotoId, r.fromPhotoId],
      (e, counts) => {
        out[i] = shapeChallenge(r, counts || []);
        if (--left === 0) cb(out);
      }
    );
  });
}

// ---- Web push (optional: needs the web-push package and VAPID keys in the environment) ----
let webpush = null;
try {
  webpush = require('web-push');
} catch (e) {
  console.log('ℹ️ web-push is not installed, push notifications are off');
}
const VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;
if (webpush && VAPID_PUBLIC && VAPID_PRIVATE) {
  try {
    webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@example.com', VAPID_PUBLIC, VAPID_PRIVATE);
  } catch (e) {
    console.error('Push setup failed:', e.message);
    webpush = null;
  }
}
const pushEnabled = () => !!(webpush && VAPID_PUBLIC && VAPID_PRIVATE);

function sendPush(userId, payload) {
  if (!pushEnabled()) return;
  db.all(`SELECT * FROM push_subscriptions WHERE userId = ?`, [userId], (err, subs) => {
    (subs || []).forEach((sub) => {
      webpush
        .sendNotification(
          { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
          JSON.stringify(payload)
        )
        .catch((e) => {
          // The phone removed this subscription
          if (e && (e.statusCode === 404 || e.statusCode === 410)) {
            db.run(`DELETE FROM push_subscriptions WHERE endpoint = ?`, [sub.endpoint]);
          }
        });
    });
  });
}

const dbRun = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, (e) => (e ? reject(e) : resolve())));

// ---- Clout points ----
const WELCOME_CLOUT = 500;
function awardClout(userId, amount) {
  db.run(`UPDATE users SET clout = COALESCE(clout, 0) + ? WHERE id = ?`, [amount, userId]);
}

// ---- Notifications (the red dots) ----
function notifyUser(userId, { type, text, link, push }, cb) {
  db.run(
    `INSERT INTO notifications (id, userId, type, text, link, createdAt) VALUES (?, ?, ?, ?, ?, ?)`,
    [uuidv4(), userId, type, text, link || null, Date.now()],
    () => {
      if (push) sendPush(userId, { title: 'DUEL', body: text, url: link || '/' });
      if (cb) cb();
    }
  );
}

// Votes on the same photo are grouped into one notification
function notifyVote(ownerId, photoId, title) {
  db.get(
    `SELECT id, count FROM notifications WHERE userId = ? AND type = 'votes' AND ref = ? AND readAt IS NULL`,
    [ownerId, photoId],
    (e, row) => {
      const t = String(title || 'your photo').slice(0, 40);
      if (row) {
        const n = (row.count || 1) + 1;
        db.run(`UPDATE notifications SET count = ?, text = ?, createdAt = ? WHERE id = ?`, [
          n,
          `🗳️ "${t}" got ${n} new votes`,
          Date.now(),
          row.id
        ]);
      } else {
        db.run(
          `INSERT INTO notifications (id, userId, type, text, link, ref, count, createdAt) VALUES (?, ?, 'votes', ?, ?, ?, 1, ?)`,
          [uuidv4(), ownerId, `🗳️ "${t}" got a new vote`, '/?go=profile', photoId, Date.now()]
        );
      }
    }
  );
}

// First-time welcome: Clout bonus + a notification, and seed the "already earned" lists
function giveWelcome(userId, cb) {
  userStats(userId, (st) => {
    const earnedIds = buildAchievements(st).filter((a) => a.earned).map((a) => a.id);
    db.run(
      `UPDATE users SET welcomed = 1, clout = COALESCE(clout, 0) + ?, achievementsSeen = ?, tierSeen = ?
       WHERE id = ? AND COALESCE(welcomed, 0) = 0`,
      [WELCOME_CLOUT, JSON.stringify(earnedIds), tierFor(st.wins).name, userId],
      () => {
        db.run(
          `INSERT OR IGNORE INTO notifications (id, userId, type, text, link, createdAt) VALUES (?, ?, 'welcome', ?, ?, ?)`,
          [uuidv4(), userId, `🎉 Welcome, Contender! You start with ${WELCOME_CLOUT} Clout. Vote, upload and duel to earn more.`, '/?go=vote', Date.now()],
          () => cb && cb()
        );
      }
    );
  });
}

// Announce new achievements and tier-ups (and pay Clout for achievements)
function checkProgress(userId) {
  userStats(userId, (st) => {
    db.get(`SELECT achievementsSeen, tierSeen FROM users WHERE id = ?`, [userId], (e, row) => {
      if (!row) return;
      const earned = buildAchievements(st).filter((a) => a.earned);
      const tier = tierFor(st.wins);
      let seen = null;
      try {
        seen = row.achievementsSeen ? JSON.parse(row.achievementsSeen) : null;
      } catch (err) {}

      if (seen) {
        earned
          .filter((a) => !seen.includes(a.id))
          .forEach((a) => {
            awardClout(userId, 25);
            notifyUser(userId, { type: 'achievement', text: `🏅 Achievement unlocked: ${a.name}! +25 Clout`, link: '/?go=profile', push: true });
          });
        const oldIdx = TIERS.findIndex((t) => t.name === row.tierSeen);
        const newIdx = TIERS.findIndex((t) => t.name === tier.name);
        if (oldIdx >= 0 && newIdx > oldIdx) {
          notifyUser(userId, { type: 'tier', text: `${tier.emoji} You reached ${tier.name} tier!`, link: '/?go=profile', push: true });
        }
      }
      db.run(`UPDATE users SET achievementsSeen = ?, tierSeen = ? WHERE id = ?`, [
        JSON.stringify(earned.map((a) => a.id)),
        tier.name,
        userId
      ]);
    });
  });
}

// A photo with this many open reports is hidden until an admin reviews it
const HIDE_AFTER_REPORTS = 3;

// ==================== AUTH ENDPOINTS ====================

// Sign up with email/password
app.post('/api/auth/signup', authLimiter, signupLimiter, async (req, res) => {
  const { email, password, username, displayName, ref } = req.body;

  if (!email || !password || !username || !displayName) {
    return res.status(400).json({ error: 'All fields required' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const now = Date.now();

    db.run(
      `INSERT INTO users (id, email, username, displayName, passwordHash, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [userId, email, username, displayName, passwordHash, now, now],
      (err) => {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Email or username already taken' });
          }
          return res.status(500).json({ error: 'Signup failed' });
        }

        resolveReferrer(ref, (referrerId) => {
          if (referrerId && referrerId !== userId) {
            db.run(`UPDATE users SET invitedBy = ? WHERE id = ?`, [referrerId, userId]);
            awardClout(referrerId, 100);
            notifyUser(referrerId, { type: 'invite', text: `👋 @${username} joined with your link! +100 Clout`, link: '/?go=profile', push: true });
          }
        });

        const token = generateToken(userId);
        res.json({
          token,
          user: {
            id: userId,
            email,
            username,
            displayName,
            bio: '',
            profileImage: null
          }
        });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login with email/password
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      if (user.banned) {
        return res.status(403).json({ error: 'This account has been suspended' });
      }

      try {
        const passwordMatch = await bcrypt.compare(password, user.passwordHash);
        if (!passwordMatch) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = generateToken(user.id);
        res.json({
          token,
          user: {
            id: user.id,
            email: user.email,
            username: user.username,
            displayName: user.displayName,
            bio: user.bio,
            profileImage: user.profileImage
          }
        });
      } catch (err) {
        res.status(500).json({ error: 'Server error' });
      }
    }
  );
});

// Google OAuth - Get auth URL
app.get('/api/auth/google-url', (req, res) => {
  const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?${new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth/google/callback`,
    response_type: 'code',
    scope: 'openid email profile'
  })}`;

  res.json({ url: googleAuthUrl });
});

// Google OAuth - Handle callback
app.post('/api/auth/google-callback', async (req, res) => {
  const { code, ref } = req.body;

  try {
    // Exchange code for token
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth/google/callback`,
      grant_type: 'authorization_code'
    });

    const { id_token } = tokenResponse.data;
    
    // Decode ID token (in production, verify signature)
    const decoded = jwt.decode(id_token);
    const { email, name, picture, sub: googleId } = decoded;

    // Check if user exists
    db.get(
      `SELECT * FROM users WHERE googleId = ?`,
      [googleId],
      (err, existingUser) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (existingUser) {
          // User exists, log them in
          const token = generateToken(existingUser.id);
          return res.json({
            token,
            user: {
              id: existingUser.id,
              email: existingUser.email,
              username: existingUser.username,
              displayName: existingUser.displayName,
              bio: existingUser.bio,
              profileImage: existingUser.profileImage
            }
          });
        }

        // Create new user from Google info
        const userId = uuidv4();
        const now = Date.now();

        pickUsername(email.split('@')[0], (username) => {
        db.run(
          `INSERT INTO users (id, googleId, email, username, displayName, profileImage, createdAt, updatedAt)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [userId, googleId, email, username, name, picture, now, now],
          (err) => {
            if (err) return res.status(500).json({ error: 'Failed to create user' });

            resolveReferrer(ref, (referrerId) => {
              if (referrerId && referrerId !== userId) {
                db.run(`UPDATE users SET invitedBy = ? WHERE id = ?`, [referrerId, userId]);
            awardClout(referrerId, 100);
            notifyUser(referrerId, { type: 'invite', text: `👋 @${username} joined with your link! +100 Clout`, link: '/?go=profile', push: true });
              }
            });

            const token = generateToken(userId);
            res.json({
              token,
              user: {
                id: userId,
                email,
                username,
                displayName: name,
                bio: '',
                profileImage: picture
              }
            });
          }
        );
        });
      }
    );
  } catch (err) {
    console.error('Google auth error:', err.message);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

// Get current user
app.get('/api/auth/me', verifyToken, (req, res) => {
  db.get(
    `SELECT id, email, username, displayName, bio, profileImage FROM users WHERE id = ?`,
    [req.userId],
    (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found' });
      db.get(`SELECT COUNT(*) AS n FROM users WHERE invitedBy = ?`, [req.userId], (err2, row) => {
        db.get(`SELECT COUNT(*) AS n FROM challenges WHERE toUserId = ? AND status = 'pending'`, [req.userId], (err3, ch) => {
          db.get(`SELECT COALESCE(clout, 0) AS clout, COALESCE(welcomed, 0) AS welcomed FROM users WHERE id = ?`, [req.userId], (err4, x) => {
            const finish = (clout, welcomeBonus) => {
              db.get(`SELECT COUNT(*) AS n FROM notifications WHERE userId = ? AND readAt IS NULL`, [req.userId], (err5, un) => {
                res.json({
                  ...user,
                  isAdmin: isAdminEmail(user.email),
                  invitedCount: row?.n || 0,
                  pendingChallenges: ch?.n || 0,
                  clout,
                  unreadNotifications: un?.n || 0,
                  welcomeBonus
                });
              });
            };
            if (x && !x.welcomed) giveWelcome(req.userId, () => finish(x.clout + WELCOME_CLOUT, WELCOME_CLOUT));
            else finish(x ? x.clout : 0, 0);
          });
        });
      });
    }
  );
});

// ==================== PHOTO ENDPOINTS ====================

// Upload photo (to Cloudinary - handled by frontend)
app.post('/api/photos/upload', verifyToken, uploadLimiter, (req, res) => {
  const { title, imageUrl, cloudinaryId } = req.body;
  const category = req.body.category;

  if (!title || !imageUrl) {
    return res.status(400).json({ error: 'Title and image required' });
  }
  if (!CATEGORIES[category]) {
    return res.status(400).json({ error: 'Please choose a category' });
  }

  db.get(`SELECT COUNT(*) AS n FROM photos WHERE userId = ?`, [req.userId], (e, row) => {
    if (row && row.n >= MAX_PHOTOS_PER_USER) {
      return res.status(400).json({ error: `You can have up to ${MAX_PHOTOS_PER_USER} photos. Delete one to add another.` });
    }

    const photoId = uuidv4();
    const now = Date.now();

    db.run(
      `INSERT INTO photos (id, userId, title, imageUrl, cloudinaryId, category, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [photoId, req.userId, String(title).slice(0, 100), imageUrl, cloudinaryId, category, now, now],
      (err) => {
        if (err) return res.status(500).json({ error: 'Upload failed' });

        const first = !!row && row.n === 0;
        if (first) awardClout(req.userId, 100); // first upload bonus

        res.json({
          cloutEarned: first ? 100 : 0,
          id: photoId,
          userId: req.userId,
          title,
          imageUrl,
          category,
          rating: 1600,
          matchesPlayed: 0,
          wins: 0,
          losses: 0
        });
      }
    );
  });
});

// Get user's photos
app.get('/api/users/:userId/photos', (req, res) => {
  db.all(
    `SELECT id, userId, title, imageUrl, category, rating, matchesPlayed, wins, losses, createdAt
     FROM photos WHERE userId = ? ORDER BY createdAt DESC`,
    [req.params.userId],
    (err, photos) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(photos || []);
    }
  );
});

app.get('/api/matchup/next', verifyToken, (req, res) => {
  const category = CATEGORIES[req.query.category] ? req.query.category : null;
  // Photos from other people, not hidden by reports, not reported by this user
  db.all(
    `SELECT p.*, u.displayName AS uploaderName, u.username AS uploaderUsername, u.profileImage AS uploaderImage
     FROM photos p
     JOIN users u ON u.id = p.userId
     WHERE p.userId != ?
       AND (SELECT COUNT(*) FROM reports r WHERE r.photoId = p.id AND r.status = 'open') < ?
       AND NOT EXISTS (SELECT 1 FROM reports r2 WHERE r2.photoId = p.id AND r2.reporterId = ?)
       AND (? IS NULL OR COALESCE(p.category, 'selfies') = ?)
     ORDER BY RANDOM()
     LIMIT 60`,
    [req.userId, HIDE_AFTER_REPORTS, req.userId, category, category],
    (err, photos) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!photos || photos.length < 2 || new Set(photos.map((p) => p.userId)).size < 2) {
        return res.status(404).json({ error: 'Not enough photos', code: 'NOT_ENOUGH_PHOTOS' });
      }

      // Pairs this user has already voted on
      db.all(`SELECT photoAId, photoBId FROM matches WHERE userId = ?`, [req.userId], (err2, seenRows) => {
        if (err2) return res.status(500).json({ error: 'Database error' });

        const seen = new Set((seenRows || []).map((m) => [m.photoAId, m.photoBId].sort().join('|')));
        const pairs = [];
        for (let i = 0; i < photos.length; i++) {
          for (let j = i + 1; j < photos.length; j++) {
            const key = [photos[i].id, photos[j].id].sort().join('|');
            const sameCategory = (photos[i].category || 'selfies') === (photos[j].category || 'selfies');
            const differentOwners = photos[i].userId !== photos[j].userId; // never pit someone against themselves
            if (sameCategory && differentOwners && !seen.has(key)) pairs.push([photos[i], photos[j]]);
          }
        }

        if (pairs.length === 0) {
          return res.status(404).json({ error: 'No new pairs', code: 'ALL_VOTED' });
        }

        // New photos get more exposure: pairs with fewer battles are more likely
        const weights = pairs.map(([x, y]) => 1 / (1 + ((x.matchesPlayed || 0) + (y.matchesPlayed || 0)) / 2));
        let roll = Math.random() * weights.reduce((sum, w) => sum + w, 0);
        let pick = 0;
        for (; pick < weights.length; pick++) {
          roll -= weights[pick];
          if (roll <= 0) break;
        }
        const [a, b] = pairs[Math.min(pick, pairs.length - 1)];
        const shape = (p) => {
          const { uploaderName, uploaderUsername, uploaderImage, ...photo } = p;
          return {
            ...photo,
            uploader: { displayName: uploaderName, username: uploaderUsername, profileImage: uploaderImage }
          };
        };
        res.json({ photoA: shape(a), photoB: shape(b), matchToken: signMatchToken(req.userId, a.id, b.id) });
      });
    }
  );
});

// Vote on matchup
app.post('/api/matchup/vote', verifyToken, (req, res) => {
  const { photoAId, photoBId, winnerId, matchToken } = req.body;

  if (tooManyVotes(req.userId)) {
    return res.status(429).json({ error: 'You are voting too fast. Slow down a little.' });
  }

  // The battle must be one the server served to this user, and not answered instantly
  try {
    const t = jwt.verify(matchToken || '', JWT_SECRET);
    const sameUser = t.k === 'match' && t.u === req.userId;
    const samePair = (t.a === photoAId && t.b === photoBId) || (t.a === photoBId && t.b === photoAId);
    if (!sameUser || !samePair) throw new Error('bad token');
    if (Date.now() / 1000 - t.iat < 1) {
      return res.status(429).json({ error: 'That was too quick. Take a look at both photos first!' });
    }
  } catch (e) {
    return res.status(400).json({ error: 'This battle expired. Refresh and try again.' });
  }

  if (!photoAId || !photoBId || !winnerId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (winnerId !== photoAId && winnerId !== photoBId) {
    return res.status(400).json({ error: 'Winner must be one of the two photos' });
  }

  db.get(`SELECT * FROM photos WHERE id = ?`, [photoAId], (err, photoA) => {
    db.get(`SELECT * FROM photos WHERE id = ?`, [photoBId], (err2, photoB) => {
      if (!photoA || !photoB) {
        return res.status(400).json({ error: 'Photos not found' });
      }
      if (photoA.userId === req.userId || photoB.userId === req.userId) {
        return res.status(403).json({ error: 'You cannot vote on your own photos' });
      }
      if (photoA.userId === photoB.userId) {
        return res.status(400).json({ error: 'Those photos belong to the same person' });
      }

      db.get(
        `SELECT id FROM matches WHERE userId = ?
           AND ((photoAId = ? AND photoBId = ?) OR (photoAId = ? AND photoBId = ?))`,
        [req.userId, photoAId, photoBId, photoBId, photoAId],
        (err3, already) => {
          if (already) {
            return res.status(409).json({ error: 'You already voted on this pair' });
          }

          // Calculate Elo changes
          const ea = 1 / (1 + Math.pow(10, (photoB.rating - photoA.rating) / 400));
          const eb = 1 - ea;
          // New photos move faster so they find their level quickly (fairness for newcomers)
          const kA = (photoA.matchesPlayed || 0) < 10 ? 40 : 20;
          const kB = (photoB.matchesPlayed || 0) < 10 ? 40 : 20;
          const resultA = winnerId === photoAId ? 1 : 0;
          const deltaA = kA * (resultA - ea);
          const deltaB = kB * ((1 - resultA) - eb);

          const newRatingA = photoA.rating + deltaA;
          const newRatingB = photoB.rating + deltaB;
          const now = Date.now();
          const matchId = uuidv4();

          // Update ratings
          db.run(`UPDATE photos SET rating = ?, matchesPlayed = matchesPlayed + 1, wins = wins + ?, losses = losses + ?, updatedAt = ? WHERE id = ?`,
            [newRatingA, resultA ? 1 : 0, resultA ? 0 : 1, now, photoAId]);

          db.run(`UPDATE photos SET rating = ?, matchesPlayed = matchesPlayed + 1, wins = wins + ?, losses = losses + ?, updatedAt = ? WHERE id = ?`,
            [newRatingB, resultA ? 0 : 1, resultA ? 1 : 0, now, photoBId]);

          // Record match
          db.run(
            `INSERT INTO matches (id, photoAId, photoBId, winnerId, userId, ratingABefore, ratingBBefore, ratingAAfter, ratingBAfter, deltaA, deltaB, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [matchId, photoAId, photoBId, winnerId, req.userId, photoA.rating, photoB.rating, newRatingA, newRatingB, deltaA, deltaB, now],
            (err4) => {
              if (err4) return res.status(500).json({ error: 'Vote failed' });

              // How the crowd voted on this exact pair (all users)
              db.get(
                `SELECT COUNT(*) AS total, SUM(CASE WHEN winnerId = ? THEN 1 ELSE 0 END) AS winnerVotes
                 FROM matches
                 WHERE (photoAId = ? AND photoBId = ?) OR (photoAId = ? AND photoBId = ?)`,
                [winnerId, photoAId, photoBId, photoBId, photoAId],
                (err5, pair) => {
                  const winnerPhoto = winnerId === photoAId ? photoA : photoB;
                  let cloutEarned = 5;
                  awardClout(req.userId, 5); // for voting
                  awardClout(winnerPhoto.userId, 2); // for receiving a vote
                  notifyVote(winnerPhoto.userId, winnerPhoto.id, winnerPhoto.title);
                  checkProgress(winnerPhoto.userId);

                  const respond = (dailyComplete) => {
                    res.json({
                      matchId,
                      winner: winnerId,
                      photoARating: Math.round(newRatingA),
                      photoBRating: Math.round(newRatingB),
                      pairVotes: { total: pair?.total || 1, winnerVotes: pair?.winnerVotes || 1 },
                      cloutEarned,
                      dailyComplete
                    });
                  };

                  // Daily challenge: 10 votes in today's featured category
                  const day = Math.floor(Date.now() / 86400000);
                  const keys = Object.keys(CATEGORIES);
                  const featured = keys[day % keys.length];
                  if ((winnerPhoto.category || 'selfies') !== featured) return respond(false);

                  db.get(
                    `SELECT COUNT(*) AS n FROM matches m JOIN photos p ON p.id = m.winnerId
                     WHERE m.userId = ? AND m.timestamp >= ? AND COALESCE(p.category, 'selfies') = ?`,
                    [req.userId, day * 86400000, featured],
                    (err6, d) => {
                      if (d && d.n === 10) {
                        awardClout(req.userId, 50);
                        cloutEarned += 50;
                        notifyUser(req.userId, { type: 'daily', text: '✅ Daily challenge complete! +50 Clout', link: '/?go=vote' });
                        return respond(true);
                      }
                      respond(false);
                    }
                  );
                }
              );
            }
          );
        }
      );
    });
  });
});

// Rank info for the shareable ranking card
app.get('/api/photos/:photoId/rank', (req, res) => {
  db.get(
    `SELECT p.id, p.userId, p.title, p.imageUrl, p.category, p.rating, p.matchesPlayed, p.wins, p.losses,
            u.username AS ownerUsername, u.displayName AS ownerName
     FROM photos p JOIN users u ON u.id = p.userId WHERE p.id = ?`,
    [req.params.photoId],
    (err, photo) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!photo) return res.status(404).json({ error: 'Photo not found' });

      const visible = `(SELECT COUNT(*) FROM reports r WHERE r.photoId = photos.id AND r.status = 'open') < ${HIDE_AFTER_REPORTS}`;

      const finish = (rank, total) => {
        userStats(photo.userId, (st) => {
          const { userId, ...pub } = photo;
          res.json({
            ...pub,
            rank,
            total,
            tier: tierFor(st.wins),
            userWins: st.wins,
            label: cardLabel({
              rank,
              total,
              matchesPlayed: photo.matchesPlayed,
              wins: photo.wins,
              userWins: st.wins
            })
          });
        });
      };

      db.get(`SELECT COUNT(*) AS total FROM photos WHERE matchesPlayed >= 1 AND ${visible}`, (err2, t) => {
        const total = t?.total || 0;
        if (photo.matchesPlayed < 1) return finish(null, total);
        db.get(
          `SELECT COUNT(*) AS better FROM photos
           WHERE matchesPlayed >= 1 AND ${visible}
             AND (rating > ? OR (rating = ? AND matchesPlayed > ?))`,
          [photo.rating, photo.rating, photo.matchesPlayed],
          (err3, b) => finish((b?.better || 0) + 1, total)
        );
      });
    }
  );
});

// My achievements and tier
app.get('/api/achievements', verifyToken, (req, res) => {
  userStats(req.userId, (st) => {
    res.json({ tier: tierFor(st.wins), tiers: TIERS, stats: st, achievements: buildAchievements(st) });
  });
});

// Choose one of your own uploaded photos as your profile picture (or clear it)
app.put('/api/profile/picture', verifyToken, (req, res) => {
  const { photoId, imageUrl } = req.body;
  const now = Date.now();

  const save = (url) => {
    db.run(`UPDATE users SET profileImage = ?, updatedAt = ? WHERE id = ?`, [url, now, req.userId], (err) => {
      if (err) {
        console.error('Profile picture error:', err.message);
        return res.status(500).json({ error: 'Update failed', detail: String(err.message).slice(0, 120) });
      }
      res.json({ success: true, profileImage: url });
    });
  };

  // Direct upload from the phone (stored on Cloudinary)
  if (imageUrl) {
    if (typeof imageUrl !== 'string' || !imageUrl.startsWith('https://res.cloudinary.com/')) {
      return res.status(400).json({ error: 'That image link is not allowed' });
    }
    return save(imageUrl);
  }

  // Clear the picture (letter avatar)
  if (!photoId) return save(null);

  // One of your own uploaded photos
  db.get(`SELECT imageUrl FROM photos WHERE id = ? AND userId = ?`, [photoId, req.userId], (err, photo) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!photo) return res.status(404).json({ error: 'Choose one of your own photos' });
    save(photo.imageUrl);
  });
});

// Public profile (brief) for sharing: /u/<username>
app.get('/api/public/profile/:username', (req, res) => {
  db.get(
    `SELECT id, username, displayName, profileImage, bio FROM users WHERE LOWER(username) = LOWER(?)`,
    [req.params.username],
    (err, u) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!u) return res.status(404).json({ error: 'Profile not found' });

      db.all(
        `SELECT p.id, p.title, p.imageUrl, p.rating, p.matchesPlayed, p.wins, p.losses,
           CASE WHEN p.matchesPlayed >= 1 THEN
             (SELECT COUNT(*) + 1 FROM photos p2
              WHERE p2.matchesPlayed >= 1
                AND (SELECT COUNT(*) FROM reports r2 WHERE r2.photoId = p2.id AND r2.status = 'open') < ${HIDE_AFTER_REPORTS}
                AND (p2.rating > p.rating OR (p2.rating = p.rating AND p2.matchesPlayed > p.matchesPlayed)))
           ELSE NULL END AS rank
         FROM photos p
         WHERE p.userId = ?
           AND (SELECT COUNT(*) FROM reports r WHERE r.photoId = p.id AND r.status = 'open') < ${HIDE_AFTER_REPORTS}
         ORDER BY (p.matchesPlayed > 0) DESC, p.rating DESC, p.matchesPlayed DESC`,
        [u.id],
        (err2, photos) => {
          if (err2) return res.status(500).json({ error: 'Database error' });
          const list = photos || [];
          const ranks = list.map((p) => p.rank).filter((r) => r != null);

          userStats(u.id, (st) => {
            res.json({
              username: u.username,
              displayName: u.displayName,
              profileImage: u.profileImage,
              bio: u.bio,
              photoCount: list.length,
              totalVotes: list.reduce((sum, p) => sum + (p.matchesPlayed || 0), 0),
              totalWins: st.wins,
              totalBattles: st.battles,
              winRate: st.battles ? Math.round((st.wins / st.battles) * 100) : 0,
              tier: tierFor(st.wins),
              achievements: buildAchievements(st).filter((a) => a.earned).map((a) => a.name),
              bestRank: ranks.length ? Math.min(...ranks) : null,
              photos: list.slice(0, 3)
            });
          });
        }
      );
    }
  );
});

// Public battle preview for the landing page (no login needed)
app.get('/api/public/battle', (req, res) => {
  db.all(
    `SELECT p.id, p.imageUrl, p.userId, u.username AS uploaderUsername
     FROM photos p JOIN users u ON u.id = p.userId
     WHERE (SELECT COUNT(*) FROM reports r WHERE r.photoId = p.id AND r.status = 'open') < ${HIDE_AFTER_REPORTS}
     ORDER BY RANDOM() LIMIT 30`,
    (err, photos) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!photos || photos.length < 2) return res.status(404).json({ code: 'NOT_ENOUGH_PHOTOS' });

      let pair = null;
      for (let i = 0; i < photos.length && !pair; i++) {
        for (let j = i + 1; j < photos.length; j++) {
          if (photos[i].userId !== photos[j].userId) {
            pair = [photos[i], photos[j]];
            break;
          }
        }
      }
      if (!pair) return res.status(404).json({ code: 'NOT_ENOUGH_PHOTOS' });

      const shape = (p) => ({ id: p.id, imageUrl: p.imageUrl, uploader: { username: p.uploaderUsername } });
      res.json({ photoA: shape(pair[0]), photoB: shape(pair[1]) });
    }
  );
});

// Trending duels: most-voted pairs in the last 14 days
app.get('/api/public/trending', (req, res) => {
  const since = Date.now() - 14 * 24 * 60 * 60 * 1000;
  db.all(
    `SELECT MIN(photoAId, photoBId) AS a, MAX(photoAId, photoBId) AS b, COUNT(*) AS votes
     FROM matches WHERE timestamp > ?
     GROUP BY MIN(photoAId, photoBId), MAX(photoAId, photoBId)
     ORDER BY votes DESC LIMIT 3`,
    [since],
    (err, pairs) => {
      if (err || !pairs || pairs.length === 0) return res.json([]);

      const ids = [...new Set(pairs.flatMap((p) => [p.a, p.b]))];
      const marks = ids.map(() => '?').join(',');
      db.all(
        `SELECT p.id, p.imageUrl, p.userId, u.username
         FROM photos p JOIN users u ON u.id = p.userId
         WHERE p.id IN (${marks})
           AND (SELECT COUNT(*) FROM reports r WHERE r.photoId = p.id AND r.status = 'open') < ${HIDE_AFTER_REPORTS}`,
        ids,
        (err2, rows) => {
          const byId = {};
          (rows || []).forEach((r) => {
            byId[r.id] = { id: r.id, userId: r.userId, imageUrl: r.imageUrl, uploader: { username: r.username } };
          });
          const out = pairs
            .filter((p) => byId[p.a] && byId[p.b] && byId[p.a].userId !== byId[p.b].userId)
            .map((p) => ({
              votes: p.votes,
              photoA: { id: byId[p.a].id, imageUrl: byId[p.a].imageUrl, uploader: byId[p.a].uploader },
              photoB: { id: byId[p.b].id, imageUrl: byId[p.b].imageUrl, uploader: byId[p.b].uploader }
            }));
          res.json(out);
        }
      );
    }
  );
});

// Daily challenge: vote on 10 duels in today's featured category
app.get('/api/daily', verifyToken, (req, res) => {
  const day = Math.floor(Date.now() / 86400000);
  const keys = Object.keys(CATEGORIES);
  const category = keys[day % keys.length];
  const goal = 10;

  db.get(
    `SELECT COUNT(*) AS n FROM matches m JOIN photos p ON p.id = m.winnerId
     WHERE m.userId = ? AND m.timestamp >= ? AND COALESCE(p.category, 'selfies') = ?`,
    [req.userId, day * 86400000, category],
    (err, row) => {
      db.all(
        `SELECT DISTINCT CAST(timestamp / 86400000 AS INTEGER) AS d FROM matches
         WHERE userId = ? AND timestamp >= ? ORDER BY d DESC`,
        [req.userId, Date.now() - 60 * 86400000],
        (err2, rows) => {
          const days = new Set((rows || []).map((r) => r.d));
          let cursor = days.has(day) ? day : day - 1;
          let streak = 0;
          while (days.has(cursor)) {
            streak += 1;
            cursor -= 1;
          }
          const votes = row?.n || 0;
          res.json({ category, categoryLabel: CATEGORIES[category], goal, votes, done: votes >= goal, streak });
        }
      );
    }
  );
});

// ---- Challenges ----
app.post('/api/challenges', verifyToken, challengeLimiter, (req, res) => {
  const { toUsername, photoId } = req.body;
  if (!toUsername || !photoId) return res.status(400).json({ error: 'Choose a person and one of your photos' });

  db.get(`SELECT id FROM photos WHERE id = ? AND userId = ?`, [photoId, req.userId], (e1, photo) => {
    if (!photo) return res.status(400).json({ error: 'Choose one of your own photos' });

    db.get(`SELECT id FROM users WHERE LOWER(username) = LOWER(?)`, [String(toUsername).replace(/^@/, '')], (e2, target) => {
      if (!target) return res.status(404).json({ error: 'We could not find that user' });
      if (target.id === req.userId) return res.status(400).json({ error: 'You cannot challenge yourself' });

      db.get(
        `SELECT id FROM challenges WHERE fromUserId = ? AND toUserId = ? AND status = 'pending'`,
        [req.userId, target.id],
        (e3, existing) => {
          if (existing) return res.status(409).json({ error: 'You already sent them a challenge' });

          const id = uuidv4();
          db.run(
            `INSERT INTO challenges (id, fromUserId, toUserId, fromPhotoId, status, createdAt) VALUES (?, ?, ?, ?, 'pending', ?)`,
            [id, req.userId, target.id, photoId, Date.now()],
            (e4) => {
              if (e4) return res.status(500).json({ error: 'Could not send the challenge' });
              db.get(`SELECT username FROM users WHERE id = ?`, [req.userId], (e5, me) => {
                notifyUser(target.id, {
                  type: 'challenge',
                  text: `⚔️ @${me?.username || 'Someone'} challenged you to a duel`,
                  link: '/?go=profile',
                  push: true
                });
              });
              res.json({ success: true, id });
            }
          );
        }
      );
    });
  });
});

app.get('/api/challenges', verifyToken, (req, res) => {
  db.run(`UPDATE challenges SET status = 'expired' WHERE status = 'pending' AND createdAt < ?`, [Date.now() - 7 * 86400000]);
  challengeRows(
    `(c.fromUserId = ? OR c.toUserId = ?) AND c.status NOT IN ('cancelled', 'declined')`,
    [req.userId, req.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      addBattleCounts(rows || [], (out) => {
        res.json(out.map((c) => ({ ...c, role: c.from.userId === req.userId ? 'from' : 'to' })));
      });
    }
  );
});

app.post('/api/challenges/:id/accept', verifyToken, (req, res) => {
  const { photoId } = req.body;
  db.get(`SELECT * FROM challenges WHERE id = ?`, [req.params.id], (e1, c) => {
    if (!c) return res.status(404).json({ error: 'Challenge not found' });
    if (c.toUserId !== req.userId) return res.status(403).json({ error: 'This challenge is not for you' });
    if (c.status !== 'pending') return res.status(400).json({ error: 'This challenge is no longer open' });

    db.get(`SELECT id FROM photos WHERE id = ? AND userId = ?`, [photoId, req.userId], (e2, photo) => {
      if (!photo) return res.status(400).json({ error: 'Choose one of your own photos' });
      const now = Date.now();
      db.run(
        `UPDATE challenges SET toPhotoId = ?, status = 'accepted', acceptedAt = ?, endsAt = ? WHERE id = ?`,
        [photoId, now, now + 3 * 86400000, c.id],
        (e3) => {
          if (e3) return res.status(500).json({ error: 'Could not accept' });
          db.get(`SELECT username FROM users WHERE id = ?`, [req.userId], (e4, me) => {
            notifyUser(c.fromUserId, {
              type: 'challenge_accepted',
              text: `✅ @${me?.username || 'Someone'} accepted your challenge. The battle is live!`,
              link: `/b/${c.id}`,
              push: true
            });
          });
          res.json({ success: true, id: c.id });
        }
      );
    });
  });
});

app.post('/api/challenges/:id/decline', verifyToken, (req, res) => {
  db.run(
    `UPDATE challenges SET status = 'declined' WHERE id = ? AND toUserId = ? AND status = 'pending'`,
    [req.params.id, req.userId],
    () => res.json({ success: true })
  );
});

app.post('/api/challenges/:id/cancel', verifyToken, (req, res) => {
  db.run(
    `UPDATE challenges SET status = 'cancelled' WHERE id = ? AND fromUserId = ? AND status = 'pending'`,
    [req.params.id, req.userId],
    () => res.json({ success: true })
  );
});

// Public battle page data
app.get('/api/battle/:id', (req, res) => {
  challengeRows(`c.id = ? AND c.status = 'accepted'`, [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!rows || rows.length === 0) return res.status(404).json({ error: 'Battle not found' });
    addBattleCounts(rows, (out) => res.json(out[0]));
  });
});

// Permission + token to vote in a battle
app.get('/api/battle/:id/vote-token', verifyToken, (req, res) => {
  challengeRows(`c.id = ? AND c.status = 'accepted'`, [req.params.id], (err, rows) => {
    const c = rows && rows[0];
    if (!c) return res.status(404).json({ error: 'Battle not found' });
    if (Date.now() > c.endsAt) return res.json({ canVote: false, reason: 'ended' });
    if (c.fromUserId === req.userId || c.toUserId === req.userId) return res.json({ canVote: false, reason: 'own' });

    db.get(
      `SELECT id FROM matches WHERE userId = ?
         AND ((photoAId = ? AND photoBId = ?) OR (photoAId = ? AND photoBId = ?))`,
      [req.userId, c.fromPhotoId, c.toPhotoId, c.toPhotoId, c.fromPhotoId],
      (e2, seen) => {
        if (seen) return res.json({ canVote: false, reason: 'voted' });
        res.json({
          canVote: true,
          photoAId: c.fromPhotoId,
          photoBId: c.toPhotoId,
          matchToken: signMatchToken(req.userId, c.fromPhotoId, c.toPhotoId)
        });
      }
    );
  });
});

// ---- Admin analytics and moderation ----
app.get('/api/admin/analytics', verifyToken, requireAdmin, async (req, res) => {
  try {
    const now = Date.now();
    const day = 86400000;
    const week = now - 7 * day;

    const [users, users7, photos, photos7, votes, votes24, votes7, voters7, reports, referred, refTop, daily, boosting, newHeavy] =
      await Promise.all([
        dbGet(`SELECT COUNT(*) AS n FROM users`),
        dbGet(`SELECT COUNT(*) AS n FROM users WHERE createdAt >= ?`, [week]),
        dbGet(`SELECT COUNT(*) AS n FROM photos`),
        dbGet(`SELECT COUNT(*) AS n FROM photos WHERE createdAt >= ?`, [week]),
        dbGet(`SELECT COUNT(*) AS n FROM matches`),
        dbGet(`SELECT COUNT(*) AS n FROM matches WHERE timestamp >= ?`, [now - day]),
        dbGet(`SELECT COUNT(*) AS n FROM matches WHERE timestamp >= ?`, [week]),
        dbGet(`SELECT COUNT(DISTINCT userId) AS n FROM matches WHERE timestamp >= ?`, [week]),
        dbGet(`SELECT COUNT(DISTINCT photoId) AS n FROM reports WHERE status = 'open'`),
        dbGet(`SELECT COUNT(*) AS n FROM users WHERE invitedBy IS NOT NULL`),
        dbAll(`SELECT u.username AS username, COUNT(*) AS n FROM users i JOIN users u ON u.id = i.invitedBy GROUP BY u.id ORDER BY n DESC LIMIT 5`),
        dbAll(`SELECT CAST(timestamp / 86400000 AS INTEGER) AS d, COUNT(*) AS n FROM matches WHERE timestamp >= ? GROUP BY d ORDER BY d`, [now - 7 * day]),
        dbAll(
          `SELECT vu.username AS voter, ou.username AS owner, COUNT(*) AS n
           FROM matches m
           JOIN photos p ON p.id = m.winnerId
           JOIN users ou ON ou.id = p.userId
           JOIN users vu ON vu.id = m.userId
           WHERE m.timestamp >= ?
           GROUP BY m.userId, p.userId HAVING COUNT(*) >= 15 ORDER BY n DESC LIMIT 10`,
          [week]
        ),
        dbAll(
          `SELECT u.username AS username, COUNT(*) AS n
           FROM matches m JOIN users u ON u.id = m.userId
           WHERE u.createdAt >= ? AND m.timestamp >= ?
           GROUP BY u.id HAVING COUNT(*) >= 40 ORDER BY n DESC LIMIT 10`,
          [now - day, now - day]
        )
      ]);

    const today = Math.floor(now / day);
    const byDay = {};
    daily.forEach((r) => {
      byDay[r.d] = r.n;
    });
    const dailyVotes = [];
    for (let i = 6; i >= 0; i--) {
      const d = today - i;
      dailyVotes.push({ day: new Date(d * day).toUTCString().slice(0, 3), votes: byDay[d] || 0 });
    }

    res.json({
      users: users.n,
      newUsers7d: users7.n,
      photos: photos.n,
      newPhotos7d: photos7.n,
      votes: votes.n,
      votes24h: votes24.n,
      votes7d: votes7.n,
      activeVoters7d: voters7.n,
      openReports: reports.n,
      referredSignups: referred.n,
      topReferrers: refTop,
      dailyVotes,
      possibleBoosting: boosting,
      newAccountHeavyVoting: newHeavy
    });
  } catch (err) {
    console.error('Analytics error:', err);
    res.status(500).json({ error: 'Could not load analytics' });
  }
});

app.post('/api/admin/users/:username/ban', verifyToken, requireAdmin, (req, res) => {
  db.get(`SELECT id, email FROM users WHERE LOWER(username) = LOWER(?)`, [req.params.username], (err, u) => {
    if (err || !u) return res.status(404).json({ error: 'User not found' });
    if (isAdminEmail(u.email)) return res.status(400).json({ error: 'You cannot ban an admin' });

    db.run(`UPDATE users SET banned = 1 WHERE id = ?`, [u.id], () => {
      db.all(`SELECT id FROM photos WHERE userId = ?`, [u.id], (e2, list) => {
        (list || []).forEach((p) => deletePhotoCompletely(p.id));
        res.json({ success: true });
      });
    });
  });
});

// ==================== DELETE / REPORT / ADMIN ====================

// Delete my own photo
app.delete('/api/photos/:photoId', verifyToken, (req, res) => {
  db.get(`SELECT id, userId FROM photos WHERE id = ?`, [req.params.photoId], (err, photo) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!photo) return res.status(404).json({ error: 'Photo not found' });
    if (photo.userId !== req.userId) return res.status(403).json({ error: 'Not your photo' });

    deletePhotoCompletely(photo.id, (err2) => {
      if (err2) return res.status(500).json({ error: 'Delete failed' });
      res.json({ success: true });
    });
  });
});

// Report a photo
app.post('/api/photos/:photoId/report', verifyToken, (req, res) => {
  const reason = String(req.body.reason || 'Other').slice(0, 200);

  db.get(`SELECT id, userId FROM photos WHERE id = ?`, [req.params.photoId], (err, photo) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!photo) return res.status(404).json({ error: 'Photo not found' });
    if (photo.userId === req.userId) return res.status(400).json({ error: 'You cannot report your own photo' });

    db.run(
      `INSERT INTO reports (id, photoId, reporterId, reason, status, createdAt) VALUES (?, ?, ?, ?, 'open', ?)`,
      [uuidv4(), photo.id, req.userId, reason, Date.now()],
      (err2) => {
        if (err2 && !String(err2.message).includes('UNIQUE')) {
          return res.status(500).json({ error: 'Report failed' });
        }
        res.json({ success: true });
      }
    );
  });
});

// Admin: list photos with open reports
app.get('/api/admin/reports', verifyToken, requireAdmin, (req, res) => {
  db.all(
    `SELECT p.id AS photoId, p.title, p.imageUrl, u.displayName AS uploaderName, u.username AS uploaderUsername, u.email AS uploaderEmail,
            COUNT(r.id) AS reportCount
     FROM reports r
     JOIN photos p ON p.id = r.photoId
     JOIN users u ON u.id = p.userId
     WHERE r.status = 'open'
     GROUP BY p.id
     ORDER BY reportCount DESC`,
    (err, items) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      db.all(`SELECT photoId, reason FROM reports WHERE status = 'open'`, (err2, reasons) => {
        if (err2) return res.status(500).json({ error: 'Database error' });
        const out = (items || []).map((it) => ({
          ...it,
          reasons: (reasons || []).filter((r) => r.photoId === it.photoId).map((r) => r.reason)
        }));
        res.json(out);
      });
    }
  );
});

// Admin: dismiss reports on a photo (keeps the photo)
app.post('/api/admin/reports/:photoId/dismiss', verifyToken, requireAdmin, (req, res) => {
  db.run(`UPDATE reports SET status = 'dismissed' WHERE photoId = ? AND status = 'open'`, [req.params.photoId], (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true });
  });
});

// Admin: remove any photo
app.delete('/api/admin/photos/:photoId', verifyToken, requireAdmin, (req, res) => {
  deletePhotoCompletely(req.params.photoId, (err) => {
    if (err) return res.status(500).json({ error: 'Delete failed' });
    res.json({ success: true });
  });
});

// ==================== LEADERBOARD ====================

app.get('/api/leaderboard', (req, res) => {
  const category = CATEGORIES[req.query.category] ? req.query.category : null;
  const scope = req.query.scope;
  const hidden = `(SELECT COUNT(*) FROM reports r WHERE r.photoId = p.id AND r.status = 'open') < ${HIDE_AFTER_REPORTS}`;
  const catCond = category ? `AND COALESCE(p.category, 'selfies') = ?` : '';

  // Recent winners: ranked by votes received in a time window (this week / this month)
  if (scope === 'week' || scope === 'season') {
    const now = new Date();
    const since = scope === 'week'
      ? Date.now() - 7 * 24 * 60 * 60 * 1000
      : Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1);
    const params = [since];
    if (category) params.push(category);

    return db.all(
      `SELECT p.id, p.title, p.imageUrl, p.rating, p.category, u.displayName, u.username, u.profileImage,
              SUM(CASE WHEN m.winnerId = p.id THEN 1 ELSE 0 END) AS wins, COUNT(*) AS battles
       FROM matches m
       JOIN photos p ON (p.id = m.photoAId OR p.id = m.photoBId)
       JOIN users u ON u.id = p.userId
       WHERE m.timestamp >= ? AND ${hidden} ${catCond}
       GROUP BY p.id
       ORDER BY wins DESC, (SUM(CASE WHEN m.winnerId = p.id THEN 1 ELSE 0 END) * 1.0 / COUNT(*)) DESC
       LIMIT 100`,
      params,
      (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json((rows || []).map((p, idx) => ({
          ...p,
          rank: idx + 1,
          matchesPlayed: p.battles,
          losses: p.battles - p.wins,
          winRate: ((p.wins / p.battles * 100) || 0).toFixed(1),
          provisional: false
        })));
      }
    );
  }

  // All-time: ranked by rating
  db.all(
    `SELECT p.*, u.displayName, u.profileImage, u.username
     FROM photos p
     JOIN users u ON p.userId = u.id
     WHERE p.matchesPlayed >= 1 AND ${hidden} ${catCond}
     ORDER BY p.rating DESC, p.matchesPlayed DESC
     LIMIT 100`,
    category ? [category] : [],
    (err, photos) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json((photos || []).map((p, idx) => ({
        rank: idx + 1,
        ...p,
        provisional: p.matchesPlayed < 5,
        winRate: ((p.wins / p.matchesPlayed * 100) || 0).toFixed(1)
      })));
    }
  );
});

// ==================== PHOTO + USER PROFILE ====================

app.get('/api/photos/:photoId', (req, res) => {
  db.get(
    `SELECT p.*, u.displayName, u.profileImage, u.username, u.bio 
     FROM photos p 
     JOIN users u ON p.userId = u.id 
     WHERE p.id = ?`,
    [req.params.photoId],
    (err, photo) => {
      if (err || !photo) return res.status(404).json({ error: 'Photo not found' });

      const winRate = photo.matchesPlayed > 0 
        ? ((photo.wins / photo.matchesPlayed * 100).toFixed(1))
        : 0;

      res.json({ ...photo, winRate });
    }
  );
});

app.get('/api/users/:userId', (req, res) => {
  db.get(
    `SELECT id, username, displayName, bio, profileImage, createdAt FROM users WHERE id = ?`,
    [req.params.userId],
    (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found' });

      db.all(
        `SELECT COUNT(*) as totalPhotos, AVG(rating) as avgRating, SUM(wins) as totalWins 
         FROM photos WHERE userId = ?`,
        [req.params.userId],
        (err2, stats) => {
          res.json({
            ...user,
            totalPhotos: stats?.[0]?.totalPhotos || 0,
            avgRating: stats?.[0]?.avgRating ? Math.round(stats[0].avgRating) : 0,
            totalWins: stats?.[0]?.totalWins || 0
          });
        }
      );
    }
  );
});

// Update profile (display name, bio, username)
app.put('/api/profile', verifyToken, (req, res) => {
  const { displayName, bio, username } = req.body;
  const now = Date.now();

  const saveProfile = (newUsername) => {
    const fields = ['displayName = ?', 'bio = ?', 'updatedAt = ?'];
    const values = [displayName || '', bio || '', now];
    if (newUsername) {
      fields.push('username = ?');
      values.push(newUsername);
    }
    values.push(req.userId);

    db.run(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, values, (err) => {
      if (err) {
        if (String(err.message).includes('UNIQUE')) {
          return res.status(409).json({ error: 'That username is already taken' });
        }
        console.error('Profile update error:', err.message);
        return res.status(500).json({ error: 'Update failed', detail: String(err.message).slice(0, 120) });
      }
      res.json({ success: true, username: newUsername || undefined });
    });
  };

  if (!username) return saveProfile(null);

  const wanted = String(username).trim().replace(/^@/, '');
  if (!USERNAME_RE.test(wanted)) {
    return res.status(400).json({ error: 'Username must be 3-20 letters, numbers or underscores' });
  }
  if (RESERVED_USERNAMES.includes(wanted.toLowerCase())) {
    return res.status(400).json({ error: 'That username is not available' });
  }

  db.get(
    `SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?`,
    [wanted, req.userId],
    (err, taken) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (taken) return res.status(409).json({ error: 'That username is already taken' });
      saveProfile(wanted);
    }
  );
});

// ==================== NOTIFICATIONS + PUSH ====================

app.get('/api/notifications', verifyToken, (req, res) => {
  db.all(
    `SELECT id, type, text, link, count, createdAt, readAt FROM notifications
     WHERE userId = ? ORDER BY createdAt DESC LIMIT 30`,
    [req.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows || []);
    }
  );
});

app.post('/api/notifications/read', verifyToken, (req, res) => {
  db.run(`UPDATE notifications SET readAt = ? WHERE userId = ? AND readAt IS NULL`, [Date.now(), req.userId], () =>
    res.json({ success: true })
  );
});

app.get('/api/push/key', (req, res) => {
  res.json({ publicKey: pushEnabled() ? VAPID_PUBLIC : null });
});

app.post('/api/push/subscribe', verifyToken, (req, res) => {
  const sub = req.body.subscription;
  if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
    return res.status(400).json({ error: 'Invalid subscription' });
  }
  db.run(
    `INSERT OR REPLACE INTO push_subscriptions (endpoint, userId, p256dh, auth, createdAt) VALUES (?, ?, ?, ?, ?)`,
    [sub.endpoint, req.userId, sub.keys.p256dh, sub.keys.auth, Date.now()],
    (err) => {
      if (err) return res.status(500).json({ error: 'Could not save subscription' });
      res.json({ success: true });
    }
  );
});

app.post('/api/push/unsubscribe', verifyToken, (req, res) => {
  db.run(`DELETE FROM push_subscriptions WHERE endpoint = ? AND userId = ?`, [req.body.endpoint || '', req.userId], () =>
    res.json({ success: true })
  );
});

// A polite reminder for people who have been away (called on a schedule by cron-job.org)
app.get('/api/cron/reminders', async (req, res) => {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.query.key !== secret) return res.status(403).json({ error: 'Forbidden' });
  if (!pushEnabled()) return res.json({ sent: 0, note: 'push is not configured' });

  // Only between 9am and 9pm local time (Lagos is UTC+1 by default)
  const offset = Number(process.env.REMINDER_UTC_OFFSET ?? 1);
  const localHour = (new Date().getUTCHours() + offset + 24) % 24;
  if (localHour < 9 || localHour >= 21) return res.json({ sent: 0, note: 'quiet hours' });

  try {
    const now = Date.now();
    const gap = 20 * 60 * 60 * 1000;
    const users = await dbAll(
      `SELECT u.id, COALESCE(u.reminderStreak, 0) AS streak, u.lastReminderAt,
              (SELECT COUNT(*) FROM notifications n WHERE n.userId = u.id AND n.readAt IS NULL) AS unread
       FROM users u
       WHERE COALESCE(u.banned, 0) = 0
         AND EXISTS (SELECT 1 FROM push_subscriptions s WHERE s.userId = u.id)
         AND (u.lastActiveAt IS NULL OR u.lastActiveAt < ?)
         AND (u.lastReminderAt IS NULL OR u.lastReminderAt < ?)
       LIMIT 200`,
      [now - gap, now - gap]
    );

    const day = Math.floor(now / 86400000);
    const keys = Object.keys(CATEGORIES);
    const featuredLabel = CATEGORIES[keys[day % keys.length]];
    let sent = 0;

    for (const u of users) {
      // Stop nagging after 3 reminders in a row that were ignored (pause for a week)
      if (u.streak >= 3 && u.lastReminderAt && now - u.lastReminderAt < 7 * 86400000) continue;

      let body;
      if (u.unread > 0) body = `👀 You have ${u.unread} new update${u.unread === 1 ? '' : 's'} on DUEL`;
      else if (u.streak % 2 === 0) body = `🔥 Today's challenge: 10 quick ${featuredLabel} duels. Ready when you are!`;
      else body = '📸 Your photos are waiting for votes. Come see how they are ranking!';

      sendPush(u.id, { title: 'DUEL', body, url: '/?go=vote' });
      await dbRun(`UPDATE users SET lastReminderAt = ?, reminderStreak = ? WHERE id = ?`, [
        now,
        u.streak >= 3 ? 1 : u.streak + 1,
        u.id
      ]);
      sent += 1;
    }
    res.json({ sent });
  } catch (err) {
    console.error('Reminder error:', err);
    res.status(500).json({ error: 'Reminder job failed' });
  }
});

// Tiny health check (used by an uptime pinger to keep the free server awake)
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ==================== STATS ====================

app.get('/api/stats', (req, res) => {
  db.get(`SELECT COUNT(*) as totalPhotos FROM photos`, (err1, photo) => {
    db.get(`SELECT COUNT(*) as totalMatches FROM matches`, (err2, match) => {
      db.get(`SELECT COUNT(*) as totalUsers FROM users`, (err3, user) => {
        res.json({
          totalPhotos: photo?.totalPhotos || 0,
          totalMatches: match?.totalMatches || 0,
          totalUsers: user?.totalUsers || 0
        });
      });
    });
  });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
  console.log(`\n🎯 DUEL API running on http://localhost:${PORT}`);
  console.log(`📸 Upload photo: POST /api/photos/upload`);
  console.log(`🗳️  Vote: POST /api/matchup/vote`);
  console.log(`🏆 Leaderboard: GET /api/leaderboard\n`);
});
