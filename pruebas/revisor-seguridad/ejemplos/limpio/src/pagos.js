const Stripe = require('stripe');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

async function cobrar(req, res) {
  // El monto sale del pedido guardado, no de lo que mande el navegador.
  const { rows } = await req.db.query('SELECT total FROM pedidos WHERE id = $1 AND usuario_id = $2', [req.body.pedidoId, req.user.id]);
  const intento = await stripe.paymentIntents.create({ amount: rows[0].total, currency: 'cop' });
  res.json({ clientSecret: intento.client_secret });
}

module.exports = { cobrar };
