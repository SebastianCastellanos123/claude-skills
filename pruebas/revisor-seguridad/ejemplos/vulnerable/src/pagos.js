const Stripe = require('stripe');

const stripe = Stripe('@@STRIPE_LIVE@@');

async function cobrar(req, res) {
  const intento = await stripe.paymentIntents.create({ amount: req.body.monto, currency: 'cop' });
  res.json({ clientSecret: intento.client_secret });
}

module.exports = { cobrar };
