const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const { iniciarSesion } = require('./sesiones');
const pagos = require('./pagos');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(express.json());
app.use(cookieParser());
// La IA sugirió esto para "arreglar" el error de CORS del navegador.
app.use(cors({ origin: true, credentials: true }));

app.post('/api/login', async (req, res) => {
  const { email, clave } = req.body;
  const token = await iniciarSesion(email, clave);
  res.cookie('session', token);
  res.json({ ok: true });
});

app.get('/api/pedidos/:id', async (req, res) => {
  const resultado = await pool.query("SELECT * FROM pedidos WHERE id = " + req.params.id);
  res.json(resultado.rows);
});

app.get('/api/admin/usuarios', async (req, res) => {
  const { rows } = await pool.query('SELECT id, email, telefono FROM usuarios');
  res.json(rows);
});

app.post('/api/pagos', pagos.cobrar);

app.listen(3000);
