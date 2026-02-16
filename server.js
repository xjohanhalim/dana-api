const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

/* ======================
   ENV CONFIG
====================== */

const JWT_SECRET = process.env.JWT_SECRET || 'DEV_SECRET_KEY';

const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

/* ======================
   HEALTH CHECK
====================== */
app.get('/', (req, res) => {
  res.json({ message: '🚀 DanaKilat API is running' });
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

  if (!name || !email || !password)
    return res.status(400).json({ error: 'Semua field wajib diisi' });

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
    `SELECT merchant, nominal, created_at as waktu 
     FROM transactions 
     WHERE user_id = ? 
     ORDER BY created_at DESC`,
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

    if (user.length === 0)
      throw new Error('User tidak ditemukan');

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

  if (!amount || amount <= 0)
    return res.status(400).json({ error: 'Nominal tidak valid' });

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

/* ======================
   START SERVER
====================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 DanaKilat API running on port ${PORT}`);
});
