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

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
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

// A photo with this many open reports is hidden until an admin reviews it
const HIDE_AFTER_REPORTS = 3;

// ==================== AUTH ENDPOINTS ====================

// Sign up with email/password
app.post('/api/auth/signup', async (req, res) => {
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
app.post('/api/auth/login', async (req, res) => {
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
        res.json({
          ...user,
          isAdmin: isAdminEmail(user.email),
          invitedCount: row?.n || 0
        });
      });
    }
  );
});

// ==================== PHOTO ENDPOINTS ====================

// Upload photo (to Cloudinary - handled by frontend)
app.post('/api/photos/upload', verifyToken, (req, res) => {
  const { title, imageUrl, cloudinaryId } = req.body;

  if (!title || !imageUrl) {
    return res.status(400).json({ error: 'Title and image required' });
  }

  const photoId = uuidv4();
  const now = Date.now();

  db.run(
    `INSERT INTO photos (id, userId, title, imageUrl, cloudinaryId, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [photoId, req.userId, title, imageUrl, cloudinaryId, now, now],
    (err) => {
      if (err) return res.status(500).json({ error: 'Upload failed' });

      res.json({
        id: photoId,
        userId: req.userId,
        title,
        imageUrl,
        rating: 1600,
        matchesPlayed: 0,
        wins: 0,
        losses: 0
      });
    }
  );
});

// Get user's photos
app.get('/api/users/:userId/photos', (req, res) => {
  db.all(
    `SELECT id, userId, title, imageUrl, rating, matchesPlayed, wins, losses, createdAt
     FROM photos WHERE userId = ? ORDER BY createdAt DESC`,
    [req.params.userId],
    (err, photos) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(photos || []);
    }
  );
});

app.get('/api/matchup/next', verifyToken, (req, res) => {
  // Photos from other people, not hidden by reports, not reported by this user
  db.all(
    `SELECT p.*, u.displayName AS uploaderName, u.username AS uploaderUsername, u.profileImage AS uploaderImage
     FROM photos p
     JOIN users u ON u.id = p.userId
     WHERE p.userId != ?
       AND (SELECT COUNT(*) FROM reports r WHERE r.photoId = p.id AND r.status = 'open') < ?
       AND NOT EXISTS (SELECT 1 FROM reports r2 WHERE r2.photoId = p.id AND r2.reporterId = ?)
     ORDER BY RANDOM()
     LIMIT 60`,
    [req.userId, HIDE_AFTER_REPORTS, req.userId],
    (err, photos) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!photos || photos.length < 2) {
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
            if (!seen.has(key)) pairs.push([photos[i], photos[j]]);
          }
        }

        if (pairs.length === 0) {
          return res.status(404).json({ error: 'No new pairs', code: 'ALL_VOTED' });
        }

        const [a, b] = pairs[Math.floor(Math.random() * pairs.length)];
        const shape = (p) => {
          const { uploaderName, uploaderUsername, uploaderImage, ...photo } = p;
          return {
            ...photo,
            uploader: { displayName: uploaderName, username: uploaderUsername, profileImage: uploaderImage }
          };
        };
        res.json({ photoA: shape(a), photoB: shape(b) });
      });
    }
  );
});

// Vote on matchup
app.post('/api/matchup/vote', verifyToken, (req, res) => {
  const { photoAId, photoBId, winnerId } = req.body;

  if (tooManyVotes(req.userId)) {
    return res.status(429).json({ error: 'You are voting too fast. Slow down a little.' });
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
          const k = 20;
          const resultA = winnerId === photoAId ? 1 : 0;
          const deltaA = k * (resultA - ea);
          const deltaB = k * ((1 - resultA) - eb);

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
                  res.json({
                    matchId,
                    winner: winnerId,
                    photoARating: Math.round(newRatingA),
                    photoBRating: Math.round(newRatingB),
                    pairVotes: { total: pair?.total || 1, winnerVotes: pair?.winnerVotes || 1 }
                  });
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
    `SELECT id, userId, title, rating, matchesPlayed, wins, losses FROM photos WHERE id = ?`,
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
  const { photoId } = req.body;
  const now = Date.now();

  if (!photoId) {
    return db.run(`UPDATE users SET profileImage = NULL, updatedAt = ? WHERE id = ?`, [now, req.userId], (err) => {
      if (err) return res.status(500).json({ error: 'Update failed' });
      res.json({ success: true, profileImage: null });
    });
  }

  db.get(`SELECT imageUrl FROM photos WHERE id = ? AND userId = ?`, [photoId, req.userId], (err, photo) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!photo) return res.status(404).json({ error: 'Choose one of your own photos' });

    db.run(`UPDATE users SET profileImage = ?, updatedAt = ? WHERE id = ?`, [photo.imageUrl, now, req.userId], (err2) => {
      if (err2) return res.status(500).json({ error: 'Update failed' });
      res.json({ success: true, profileImage: photo.imageUrl });
    });
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
      if (!pair) pair = [photos[0], photos[1]];

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
        `SELECT p.id, p.imageUrl, u.username
         FROM photos p JOIN users u ON u.id = p.userId
         WHERE p.id IN (${marks})
           AND (SELECT COUNT(*) FROM reports r WHERE r.photoId = p.id AND r.status = 'open') < ${HIDE_AFTER_REPORTS}`,
        ids,
        (err2, rows) => {
          const byId = {};
          (rows || []).forEach((r) => {
            byId[r.id] = { id: r.id, imageUrl: r.imageUrl, uploader: { username: r.username } };
          });
          const out = pairs
            .filter((p) => byId[p.a] && byId[p.b])
            .map((p) => ({ votes: p.votes, photoA: byId[p.a], photoB: byId[p.b] }));
          res.json(out);
        }
      );
    }
  );
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
    `SELECT p.id AS photoId, p.title, p.imageUrl, u.displayName AS uploaderName, u.email AS uploaderEmail,
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
  db.all(
    `SELECT p.*, u.displayName, u.profileImage, u.username 
     FROM photos p 
     JOIN users u ON p.userId = u.id 
     WHERE p.matchesPlayed >= 1 
       AND (SELECT COUNT(*) FROM reports r WHERE r.photoId = p.id AND r.status = 'open') < ${HIDE_AFTER_REPORTS} 
     ORDER BY p.rating DESC, p.matchesPlayed DESC 
     LIMIT 100`,
    (err, photos) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      const leaderboard = photos.map((p, idx) => ({
        rank: idx + 1,
        ...p,
        winRate: ((p.wins / p.matchesPlayed * 100) || 0).toFixed(1)
      }));

      res.json(leaderboard);
    }
  );
});

// Get photo with user details
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

// ==================== USER PROFILE ====================

app.get('/api/users/:userId', (req, res) => {
  db.get(
    `SELECT id, username, displayName, bio, profileImage, createdAt FROM users WHERE id = ?`,
    [req.params.userId],
    (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found' });

      // Get user's photos stats
      db.all(
        `SELECT COUNT(*) as totalPhotos, AVG(rating) as avgRating, SUM(wins) as totalWins 
         FROM photos WHERE userId = ?`,
        [req.params.userId],
        (err, stats) => {
          res.json({
            ...user,
            totalPhotos: stats[0]?.totalPhotos || 0,
            avgRating: stats[0]?.avgRating ? Math.round(stats[0].avgRating) : 0,
            totalWins: stats[0]?.totalWins || 0
          });
        }
      );
    }
  );
});

// Update profile (bio, display name)
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
        return res.status(500).json({ error: 'Update failed' });
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
