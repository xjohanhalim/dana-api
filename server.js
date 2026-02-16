const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'SUPER_SECRET_DANAKILAT_KEY';

const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'dana_kilat'
});

/* ======================
   AUTH MIDDLEWARE
====================== */
function verifyToken(req, res, next) {

  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: 'Unauthorized' });

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ error: 'Token expired / invalid' });
  }
}

/* ======================
   REGISTER
====================== */
app.post('/register', async (req, res) => {

  const { name, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await db.query(
      'INSERT INTO users (name, email, password, saldo) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, 0]
    );

    res.json({ success: true });

  } catch (err) {
    res.status(400).json({ error: 'Email sudah digunakan' });
  }
});

/* ======================
   LOGIN
====================== */
app.post('/login', async (req, res) => {

  const { email, password } = req.body;

  const [rows] = await db.query(
    'SELECT * FROM users WHERE email = ?',
    [email]
  );

  if (rows.length === 0)
    return res.status(400).json({ error: 'Email tidak ditemukan' });

  const user = rows[0];

  const valid = await bcrypt.compare(password, user.password);
  if (!valid)
    return res.status(400).json({ error: 'Password salah' });

  const token = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '2h' }
  );

  res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      saldo: user.saldo
    }
  });
});

/* ======================
   GET USER
====================== */
app.get('/user', verifyToken, async (req, res) => {

  const [rows] = await db.query(
    'SELECT id, name, email, saldo FROM users WHERE id = ?',
    [req.user.id]
  );

  res.json(rows[0]);
});

/* ======================
   GET TRANSACTIONS
====================== */
app.get('/transactions', verifyToken, async (req, res) => {

  const [rows] = await db.query(
    'SELECT merchant, nominal, created_at as waktu FROM transactions WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.id]
  );

  res.json(rows);
});

/* ======================
   PAYMENT
====================== */
app.post('/payment', verifyToken, async (req, res) => {

  const { merchant, amount } = req.body;
  const userId = req.user.id;

  const conn = await db.getConnection();
  await conn.beginTransaction();

  try {

    const [user] = await conn.query(
      'SELECT saldo FROM users WHERE id = ? FOR UPDATE',
      [userId]
    );

    if (user[0].saldo < amount)
      throw new Error('Saldo tidak cukup');

    await conn.query(
      'UPDATE users SET saldo = saldo - ? WHERE id = ?',
      [amount, userId]
    );

    await conn.query(
      'INSERT INTO transactions (user_id, merchant, nominal) VALUES (?, ?, ?)',
      [userId, merchant, amount]
    );

    await conn.commit();
    res.json({ success: true });

  } catch (err) {
    await conn.rollback();
    res.status(400).json({ error: err.message });
  }

  conn.release();
});

/* ======================
   TOP UP
====================== */
app.post('/topup', verifyToken, async (req, res) => {

  const { amount } = req.body;
  const userId = req.user.id;

  await db.query(
    'UPDATE users SET saldo = saldo + ? WHERE id = ?',
    [amount, userId]
  );

  await db.query(
    'INSERT INTO transactions (user_id, merchant, nominal) VALUES (?, ?, ?)',
    [userId, 'Top Up Saldo', amount]
  );

  res.json({ success: true });
});

app.listen(3000, () =>
  console.log('🚀 DanaKilat API running with FULL JWT on port 3000')
);
