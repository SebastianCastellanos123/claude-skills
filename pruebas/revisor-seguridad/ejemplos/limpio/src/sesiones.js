const jwt = require('jsonwebtoken');

async function iniciarSesion(email, clave) {
  // (de ejemplo) aquí se validaría la clave contra la base de datos
  return jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

module.exports = { iniciarSesion };
