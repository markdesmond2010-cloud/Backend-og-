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
const sqlite3 = require('sqlite3').verbose();
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

// Database setup
const db = new sqlite3.Database(process.env.DATABASE_PATH || 'duel.db', (err) => {
  if (err) console.error(err);
  else console.log('✅ Connected to database');
});

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

// ==================== AUTH ENDPOINTS ====================

// Sign up with email/password
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, username, displayName } = req.body;

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
  const { code } = req.body;

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
      res.json(user);
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

// Get next matchup
app.get('/api/matchup/next', verifyToken, (req, res) => {
  db.all(
    `SELECT * FROM photos WHERE matchesPlayed >= 0 ORDER BY RANDOM() LIMIT 2`,
    (err, photos) => {
      if (err || photos.length < 2) {
        return res.status(400).json({ error: 'Not enough photos' });
      }

      db.get(
        `SELECT displayName, profileImage FROM users WHERE id = ?`,
        [photos[0].userId],
        (err1, user1) => {
          db.get(
            `SELECT displayName, profileImage FROM users WHERE id = ?`,
            [photos[1].userId],
            (err2, user2) => {
              res.json({
                photoA: { ...photos[0], uploader: user1 },
                photoB: { ...photos[1], uploader: user2 }
              });
            }
          );
        }
      );
    }
  );
});

// Vote on matchup
app.post('/api/matchup/vote', verifyToken, (req, res) => {
  const { photoAId, photoBId, winnerId } = req.body;

  if (!photoAId || !photoBId || !winnerId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  db.get(`SELECT * FROM photos WHERE id = ?`, [photoAId], (err, photoA) => {
    db.get(`SELECT * FROM photos WHERE id = ?`, [photoBId], (err, photoB) => {
      if (!photoA || !photoB) {
        return res.status(400).json({ error: 'Photos not found' });
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
        (err) => {
          if (err) return res.status(500).json({ error: 'Vote failed' });

          res.json({
            matchId,
            winner: winnerId,
            photoARating: Math.round(newRatingA),
            photoBRating: Math.round(newRatingB)
          });
        }
      );
    });
  });
});

// ==================== LEADERBOARD ====================

app.get('/api/leaderboard', (req, res) => {
  db.all(
    `SELECT p.*, u.displayName, u.profileImage 
     FROM photos p 
     JOIN users u ON p.userId = u.id 
     WHERE p.matchesPlayed >= 1 
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
