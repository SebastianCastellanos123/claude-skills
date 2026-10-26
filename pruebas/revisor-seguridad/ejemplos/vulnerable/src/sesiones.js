const crypto = require('crypto');

async function iniciarSesion(email, clave) {
  // (de ejemplo) aquí se validaría la clave contra la base de datos
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { iniciarSesion };
