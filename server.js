const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);
const multer = require('multer');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 3000);
const renderExternalUrl = (process.env.RENDER_EXTERNAL_URL || '').replace(/\/$/, '');
const renderHostname = process.env.RENDER_EXTERNAL_HOSTNAME ? `https://${process.env.RENDER_EXTERNAL_HOSTNAME}` : '';
const appUrl = (process.env.APP_URL || renderExternalUrl || renderHostname || `http://localhost:${port}`).replace(/\/$/, '');
const callbackUrl = (process.env.GOOGLE_CALLBACK_URL || `${appUrl}/auth/google/callback`).replace(/\/$/, '');
const uploadsDir = path.join(__dirname, 'uploads');
const databaseUrl = process.env.DATABASE_URL;
const pool = new Pool({
  connectionString: databaseUrl,
  ssl: databaseUrl && !/^localhost|127\.0\.0\.1/.test(databaseUrl) ? { rejectUnauthorized: false } : false
});

app.set('trust proxy', 1);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (_req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${uniqueSuffix}-${safeName}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024, files: 10 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype && file.mimetype.startsWith('image/')) {
      cb(null, true);
      return;
    }
    cb(new Error('Solo se permiten imágenes.'));
  }
});

const fs = require('fs');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const allowedEmails = (process.env.ALLOWED_GOOGLE_EMAILS || '')
  .split(',')
  .map((email) => email.trim().toLowerCase())
  .filter(Boolean);

const googleConfigured = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

if (!googleConfigured) {
  console.warn('Faltan GOOGLE_CLIENT_ID o GOOGLE_CLIENT_SECRET. La autenticación con Google no funcionará hasta configurarlos.');
}

if (!allowedEmails.length) {
  console.warn('No hay emails en ALLOWED_GOOGLE_EMAILS. Ningún usuario de Google podrá publicar novedades.');
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isAllowedEmail(email) {
  return allowedEmails.includes(normalizeEmail(email));
}

async function initializeDatabase() {
  if (!databaseUrl) {
    throw new Error('Falta DATABASE_URL. Configurala en .env o en las variables de entorno de Render.');
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS news (
    id BIGSERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    content TEXT NOT NULL,
    date TEXT NOT NULL,
    author_email TEXT NOT NULL,
    images JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    google_id TEXT UNIQUE,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    picture TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

passport.serializeUser((user, done) => {
  done(null, user.email);
});

passport.deserializeUser(async (email, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    done(null, result.rows[0] || null);
  } catch (error) {
    done(error);
  }
});

if (googleConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: callbackUrl,
        scope: ['profile', 'email']
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
        const email = normalizeEmail(profile.emails && profile.emails[0] ? profile.emails[0].value : '');

        if (!email) {
          return done(new Error('No se pudo obtener el email de Google.'));
        }

        if (!isAllowedEmail(email)) {
          return done(null, false, { message: 'Este usuario no está autorizado para publicar.' });
        }

        let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        let user = result.rows[0];

        if (!user) {
          await pool.query(
            'INSERT INTO users (google_id, email, name, picture) VALUES ($1, $2, $3, $4)',
            [profile.id, email, profile.displayName || '', profile.photos && profile.photos[0] ? profile.photos[0].value : '']
          );
          result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
          user = result.rows[0];
        }

        return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
}

app.use(express.json({ limit: '1mb' }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'lista-roja-secret',
    store: new PgSession({ pool, createTableIfMissing: true }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: Boolean(process.env.APP_URL && /^https:/i.test(process.env.APP_URL)) || Boolean(process.env.RENDER_EXTERNAL_URL) || Boolean(process.env.RENDER_EXTERNAL_HOSTNAME)
    }
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(__dirname));
app.use('/uploads', express.static(uploadsDir));

function ensureAuthorized(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: 'Debes iniciar sesión con Google.' });
  }

  if (!isAllowedEmail(req.user.email)) {
    return res.status(403).json({ message: 'Tu cuenta de Google no está autorizada para publicar.' });
  }

  return next();
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/novedades', (req, res) => {
  res.sendFile(path.join(__dirname, 'novedades.html'));
});

app.get('/api/me', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.json({ authenticated: false });
  }

  const email = normalizeEmail(req.user.email);
  return res.json({
    authenticated: true,
    email,
    allowed: isAllowedEmail(email),
    name: req.user.name || email
  });
});

app.get('/auth/google', (req, res, next) => {
  if (!googleConfigured) {
    return res.status(503).send(`
      <html><body style="font-family: Arial, sans-serif; background:#120d0d; color:#fdf4f4; padding:40px;">
        <h2>Google no configurado</h2>
        <p>Falta configurar GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET y ALLOWED_GOOGLE_EMAILS.</p>
        <p><a href="/novedades" style="color:#f7d57c;">Volver a novedades</a></p>
      </body></html>
    `);
  }

  return passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

app.get('/auth/google/callback', (req, res, next) => {
  if (!googleConfigured) {
    return res.status(503).send('Google no está configurado.');
  }

  return passport.authenticate('google', {
    failureRedirect: '/auth/google/failure',
    failureMessage: true
  })(req, res, next);
}, (req, res) => {
  res.redirect('/novedades');
});

app.get('/auth/google/failure', (req, res) => {
  res.status(403).send(`
    <html><body style="font-family: Arial, sans-serif; background:#120d0d; color:#fdf4f4; padding:40px;">
      <h2>No autorizado</h2>
      <p>Tu cuenta de Google no está autorizada para publicar novedades.</p>
      <p><a href="/novedades" style="color:#f7d57c;">Volver a novedades</a></p>
    </body></html>
  `);
});

app.get('/logout', (req, res, next) => {
  req.logout((error) => {
    if (error) {
      return next(error);
    }
    res.redirect('/novedades');
  });
});

function parseImages(rawImages) {
  if (!rawImages) return [];

  const list = typeof rawImages === 'string'
    ? rawImages.split(/\r?\n|,/) 
    : Array.isArray(rawImages)
      ? rawImages
      : [];

  return list
    .map((item) => String(item || '').trim())
    .filter(Boolean)
    .slice(0, 10);
}

function normalizeStoredImages(rawImages) {
  if (Array.isArray(rawImages)) return rawImages;

  try {
    const parsed = JSON.parse(rawImages || '[]');
    return Array.isArray(parsed) ? parsed : parseImages(rawImages || '');
  } catch (error) {
    return parseImages(rawImages || '');
  }
}

app.get('/api/news', async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT id, title, category, summary, content, date, author_email, images FROM news ORDER BY id DESC'
    );

    const normalizedRows = result.rows.map((row) => ({
      ...row,
      images: normalizeStoredImages(row.images)
    }));

    res.json(normalizedRows);
  } catch (error) {
    next(error);
  }
});

app.post('/api/news', ensureAuthorized, upload.array('images', 10), async (req, res, next) => {
  const { title, category, summary, content, date } = req.body || {};

  if (!title || !category || !summary || !content) {
    return res.status(400).json({ message: 'Faltan campos obligatorios.' });
  }

  const publicationDate = date || new Date().toISOString().slice(0, 10);
  const authorEmail = normalizeEmail(req.user.email);
  const uploadedImages = (req.files || []).map((file) => `/uploads/${file.filename}`);
  const parsedImages = JSON.stringify(uploadedImages);

  try {
    const result = await pool.query(
      `INSERT INTO news (title, category, summary, content, date, author_email, images)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       RETURNING id, title, category, summary, content, date, author_email, images`,
      [String(title).trim(), String(category).trim(), String(summary).trim(), String(content).trim(), publicationDate, authorEmail, parsedImages]
    );
    const created = result.rows[0];

    return res.status(201).json({
      message: 'Novedad publicada.',
      news: { ...created, images: normalizeStoredImages(created.images) }
    });
  } catch (error) {
    return next(error);
  }
});

app.delete('/api/news/:id', ensureAuthorized, async (req, res, next) => {
  const newsId = Number(req.params.id);

  if (!Number.isInteger(newsId) || newsId <= 0) {
    return res.status(400).json({ message: 'ID inválido.' });
  }

  try {
    const result = await pool.query('SELECT id, author_email FROM news WHERE id = $1', [newsId]);
    const existing = result.rows[0];

    if (!existing) {
      return res.status(404).json({ message: 'La novedad no existe.' });
    }

    if (normalizeEmail(existing.author_email) !== normalizeEmail(req.user.email)) {
      return res.status(403).json({ message: 'Solo el autor o un integrante de la lista puede eliminar esta novedad.' });
    }

    await pool.query('DELETE FROM news WHERE id = $1', [newsId]);
    return res.json({ message: 'Novedad eliminada.' });
  } catch (error) {
    return next(error);
  }
});

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ message: 'Error interno del servidor.' });
});

initializeDatabase()
  .then(() => {
    app.listen(port, () => {
      console.log(`Servidor corriendo en http://localhost:${port}`);
      console.log(`Emails permitidos: ${allowedEmails.length ? allowedEmails.join(', ') : 'ninguno'}`);
    });
  })
  .catch((error) => {
    console.error(`No se pudo inicializar PostgreSQL: ${error.message}`);
    process.exit(1);
  });
