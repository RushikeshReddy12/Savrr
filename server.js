import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import pkg from 'pg';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';
import session from 'express-session'; // ✅ Add sessions

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

// ✅ Setup session middleware
app.use(session({
  secret: 'savrr-secret-key', // change this to something strong in production
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // true if using HTTPS
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'styles')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware to protect routes
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

app.get('/', (req, res) => {
  res.render('index', { title: 'Savrr' });
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'Register - Savrr' });
});

app.post('/register', async (req, res) => {
  const { username, email, password, phone } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, email, password, phone) VALUES ($1, $2, $3, $4)',
      [username, email, hashedPassword, phone]
    );
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'Login - Savrr' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (result.rows.length === 0) {
      return res.status(401).send('Invalid username or password');
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).send('Invalid username or password');
    }

    req.session.userId = user.id;
    res.render('dashboard', { 
      title: 'Dashboard', 
      username 
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard', { title: 'Dashboard - Savrr', username: req.session.username });
});

// Show Create Account form
app.get('/create-account', requireLogin, (req, res) => {
  res.render('create-account', { title: 'Create Account' });
});

// Handle Create Account form submission
app.post('/create-account', requireLogin, async (req, res) => {
  const { account_number, bank_name, ifsc_code, shortcut_name, income_per_month, initial_balance } = req.body;
  const userId = req.session.userId; // ✅ Now will work

  try {
    await pool.query(
      `INSERT INTO accounts (user_id, account_number, bank_name, ifsc_code, shortcut_name, income_per_month, initial_balance)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId, account_number, bank_name, ifsc_code, shortcut_name, income_per_month, initial_balance]
    );

    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error creating account');
  }
});

// 1. Show list of accounts to edit
app.get('/edit-account', requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const result = await pool.query('SELECT * FROM accounts WHERE user_id = $1', [userId]);
  res.render('edit-account-list', { title: 'Select Account to Edit', accounts: result.rows });
});

// 2. Show form to edit a specific account
app.get('/edit-account/:id', requireLogin, async (req, res) => {
  const { id } = req.params;
  const userId = req.session.userId;
  const result = await pool.query('SELECT * FROM accounts WHERE id = $1 AND user_id = $2', [id, userId]);
  if (result.rows.length === 0) return res.send('Account not found.');
  res.render('edit-account-form', { title: 'Edit Account', account: result.rows[0] });
});

// 3. Handle edit form submission
app.post('/edit-account/:id', requireLogin, async (req, res) => {
  const { id } = req.params;
  const userId = req.session.userId;
  const { bank_name, shortcut_name, income_per_month } = req.body;
  await pool.query(
    `UPDATE accounts
     SET bank_name = $1,
         shortcut_name = $2,
         income_per_month = $3
     WHERE id = $4 AND user_id = $5`,
    [bank_name, shortcut_name, income_per_month, id, userId]
  );
  res.redirect('/dashboard');
});

app.get('/make-payments', (req, res) => {
    res.render('make-payments', { title: 'Make Payments - Savrr' });
});

app.get("/send-money", (req, res) => {
    res.render("send-money-search", { message: null });
});

app.post("/send-money/search", async (req, res) => {
    const { phone } = req.body;
    try {
        const result = await pool.query(
            "SELECT id, username, phone FROM users WHERE phone = $1",
            [phone]
        );
        if (result.rows.length === 0) {
            return res.render("send-money-search", { message: "This number is not registered" });
        }
        res.render("send-money-form", { recipient: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

app.post("/send-money/:id", async (req, res) => {
    const senderId = req.session.userId;
    const receiverId = req.params.id;
    const { amount, note } = req.body;

    try {
        await pool.query("BEGIN");

        // Deduct from sender
        await pool.query(
            "UPDATE accounts SET balance = balance - $1 WHERE user_id = $2",
            [amount, senderId]
        );

        // Add to receiver
        await pool.query(
            "UPDATE accounts SET balance = balance + $1 WHERE user_id = $2",
            [amount, receiverId]
        );

        // Record transaction
        await pool.query(
            "INSERT INTO transactions (sender_id, receiver_id, amount, note, date) VALUES ($1, $2, $3, $4, NOW())",
            [senderId, receiverId, amount, note]
        );

        await pool.query("COMMIT");

        res.redirect("/dashboard");
    } catch (err) {
        await pool.query("ROLLBACK");
        console.error(err);
        res.status(500).send("Transaction failed");
    }
});

app.get('/check-balance', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');

  try {
    const result = await pool.query(
      'SELECT id, shortcut_name, bank_name FROM accounts WHERE user_id = $1',
      [req.session.userId]
    );

    res.render('check-balance-list', {
      title: 'Check Balance',
      accounts: result.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.get('/check-balance/:id', async (req, res) => {
  try {
    const accountResult = await pool.query(
      'SELECT account_number, bank_name, shortcut_name, initial_balance FROM accounts WHERE id = $1 AND user_id = $2',
      [req.params.id, req.session.userId]
    );

    if (accountResult.rows.length === 0) {
      return res.status(404).send('Account not found');
    }

    const account = accountResult.rows[0];
    res.render('check-balance-view', {
      title: 'Check Balance',
      account
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Savrr running on port ${PORT}`));
