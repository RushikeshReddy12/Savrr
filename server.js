// Hi
import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import pkg from 'pg';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';

const { Pool } = pkg;
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const pool = new Pool({
  host: process.env.PGHOST,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  port: process.env.PGPORT
});

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'styles')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  res.render('index', { title: 'Savrr' });
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'Register - Savrr' });
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.send('Email already registered.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
      [username, email, hashedPassword]
    );

    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error registering user.');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'Login - Savrr' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.send('No user found with this email.');
    }

    const user = userResult.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.send('Incorrect password.');
    }

    res.send(`Welcome, ${user.username}!`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in.');
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Savrr running on port ${PORT}`));
