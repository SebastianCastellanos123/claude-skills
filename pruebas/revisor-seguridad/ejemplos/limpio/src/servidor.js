const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { iniciarSesion } = require('./sesiones');
const pagos = require('./pagos');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const ORIGENES = ['https://tienda-segura.example'];

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: ORIGENES, credentials: true }));

function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify(req.cookies.session, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Inicia sesión' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/api/login', async (req, res) => {
  const { email, clave } = req.body;
  const token = await iniciarSesion(email, clave);
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 60 * 60 * 1000 });
  res.json({ ok: true });
});

app.get('/api/pedidos/:id', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM pedidos WHERE id = $1 AND usuario_id = $2',
    [req.params.id, req.user.id]
  );
  res.json(rows);
});

app.get('/api/admin/usuarios', requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, email FROM usuarios');
  res.json(rows);
});

app.post('/api/pagos', requireAuth, pagos.cobrar);

app.listen(3000);
