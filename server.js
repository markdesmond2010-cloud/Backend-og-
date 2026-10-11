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
        const username = email.split('@')[0] + Math.random().toString(36).slice(7);
        const now = Date.now();

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
    `SELECT p.*, u.displayName AS uploaderName, u.profileImage AS uploaderImage
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
          const { uploaderName, uploaderImage, ...photo } = p;
          return { ...photo, uploader: { displayName: uploaderName, profileImage: uploaderImage } };
        };
        res.json({ photoA: shape(a), photoB: shape(b) });
      });
    }
  );
});

// Vote on matchup
app.post('/api/matchup/vote', verifyToken, (req, res) => {
  const { photoAId, photoBId, winnerId } = req.body;

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

              res.json({
                matchId,
                winner: winnerId,
                photoARating: Math.round(newRatingA),
                photoBRating: Math.round(newRatingB)
              });
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
    `SELECT id, title, rating, matchesPlayed, wins, losses FROM photos WHERE id = ?`,
    [req.params.photoId],
    (err, photo) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!photo) return res.status(404).json({ error: 'Photo not found' });

      const visible = `(SELECT COUNT(*) FROM reports r WHERE r.photoId = photos.id AND r.status = 'open') < ${HIDE_AFTER_REPORTS}`;

      db.get(`SELECT COUNT(*) AS total FROM photos WHERE matchesPlayed >= 1 AND ${visible}`, (err2, t) => {
        if (photo.matchesPlayed < 1) {
          return res.json({ ...photo, rank: null, total: t?.total || 0 });
        }
        db.get(
          `SELECT COUNT(*) AS better FROM photos
           WHERE matchesPlayed >= 1 AND ${visible}
             AND (rating > ? OR (rating = ? AND matchesPlayed > ?))`,
          [photo.rating, photo.rating, photo.matchesPlayed],
          (err3, b) => {
            res.json({ ...photo, rank: (b?.better || 0) + 1, total: t?.total || 0 });
          }
        );
      });
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
    `SELECT p.*, u.displayName, u.profileImage 
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
  const { displayName, bio } = req.body;
  const now = Date.now();

  db.run(
    `UPDATE users SET displayName = ?, bio = ?, updatedAt = ? WHERE id = ?`,
    [displayName || '', bio || '', now, req.userId],
    (err) => {
      if (err) return res.status(500).json({ error: 'Update failed' });
      res.json({ success: true });
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
