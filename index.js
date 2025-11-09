const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
const port = process.env.PORT || 3000;
require("dotenv").config();
console.log("DB Password:", process.env.PGPASSWORD); // just to verify

const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});

app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'styles')));
app.use(express.urlencoded({ extended: true }));

function checkAuth(req, res, next) {
  if (!req.session.username) {
    return res.redirect('/');
  }
  next();
}

const crypto = require('crypto');

const algorithm = 'aes-256-cbc';
const key = crypto.scryptSync('your_secret_key_for_encryption', 'salt', 32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(data) {
  const parts = data.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = parts.join(':');
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

app.get('/', (req, res) => {
  res.render('index', { title: 'Savrr Home' });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT password FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      const isValid = await bcrypt.compare(password, result.rows[0].password);
      if (isValid) {
        req.session.username = username;
        return res.redirect('/dashboard');
      }
    }
    res.send('Invalid credentials');
  } catch (err) {
    res.status(500).send('Error logging in');
  }
});

app.post('/register', async (req, res) => {
  const { name, username, phone, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await pool.query(
      'INSERT INTO users (name, username, phone, email, password) VALUES ($1, $2, $3, $4, $5)',
      [name, username, phone, email, hashedPassword]
    );
    await pool.query(
      'INSERT INTO usercreditscores (username, phone, creditscore) VALUES ($1, $2, 100)',
      [username, phone]
    );
    res.redirect('/login');
  } catch (err) {
    console.error("Error registering user:", err.message);
res.render("register", { error: "Error registering user: " + err.message });

  }
});

app.get('/dashboard', checkAuth, async (req, res) => {
  try {
    const scoreResult = await pool.query(
      'SELECT creditscore FROM usercreditscores WHERE username = $1',
      [req.session.username]
    );

    const creditScore = scoreResult.rows.length > 0 ? scoreResult.rows[0].creditscore : 'N/A';

    res.render('dashboard', {
      username: req.session.username,
      creditScore
    });
  } catch (err) {
    console.error('Error fetching credit score:', err);
    res.status(500).send('Error loading dashboard');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.redirect('/');
  });
});

app.get('/create-account', checkAuth, (req, res) => {
  res.render('create-account', { username: req.session.username });
});

app.post('/create-account', checkAuth, async (req, res) => {
  const { account_name, account_number, ifsc_code, shortcut_name, pincode, income } = req.body;
  try {
    const encryptedAccountNumber = encrypt(account_number);
    const encryptedIfscCode = encrypt(ifsc_code);
    const encryptedPincode = encrypt(pincode.toString());

    const userAccountInsertResult = await pool.query(
    `INSERT INTO useraccounts 
      (username, account_name, account_number, ifsc_code, shortcut_name, pincode, income, balance)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
    RETURNING id, shortcut_name`,
    [req.session.username, account_name, encryptedAccountNumber, encryptedIfscCode, shortcut_name, encryptedPincode, income]
  );

    res.send('Account created successfully!');
  } catch (err) {
    console.error('Error creating account:', err);
    res.status(500).send('Error creating account');
  }
});

app.get('/edit-account', checkAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, account_name, shortcut_name FROM useraccounts WHERE username = $1',
      [req.session.username]
    );
    res.render('edit-account-list', { accounts: result.rows });
  } catch (err) {
    console.error('Error fetching accounts:', err);
    res.status(500).send('Error retrieving user accounts');
  }
});

app.get('/edit-account/:id', checkAuth, async (req, res) => {
  const accountId = req.params.id;
  try {
    const result = await pool.query(
      'SELECT * FROM useraccounts WHERE id = $1 AND username = $2',
      [accountId, req.session.username]
    );

    if (result.rows.length === 0) {
      return res.status(404).send('Account not found');
    }

    const account = result.rows[0];

    account.account_number = decrypt(account.account_number);
    account.ifsc_code = decrypt(account.ifsc_code);
    account.pincode = decrypt(account.pincode);

    res.render('edit-account-form', { account });
  } catch (err) {
    console.error('Error fetching account:', err);
    res.status(500).send('Error retrieving account');
  }
});

app.post('/edit-account', checkAuth, async (req, res) => {
  const { id, account_name, account_number, ifsc_code, shortcut_name, pincode, income } = req.body;

  try {
    const encryptedAccountNumber = encrypt(account_number);
    const encryptedIfscCode = encrypt(ifsc_code);
    const encryptedPincode = encrypt(pincode.toString());

    await pool.query(
      `UPDATE useraccounts SET 
        account_name = $1,
        account_number = $2,
        ifsc_code = $3,
        shortcut_name = $4,
        pincode = $5,
        income = $6
       WHERE id = $7 AND username = $8`,
      [account_name, encryptedAccountNumber, encryptedIfscCode, shortcut_name, encryptedPincode, income, id, req.session.username]
    );

    res.redirect('/edit-account');
  } catch (err) {
    console.error('Error updating account:', err);
    res.status(500).send('Error updating account');
  }
});

app.get('/check-balance', checkAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, account_name, shortcut_name FROM useraccounts WHERE username = $1',
      [req.session.username]
    );
    res.render('check-balance-list', { accounts: result.rows });
  } catch (err) {
    console.error('Error fetching accounts:', err);
    res.status(500).send('Error retrieving user accounts');
  }
});

app.get('/check-balance/:id', checkAuth, async (req, res) => {
  const accountId = req.params.id;
  try {
    const result = await pool.query(
      'SELECT account_name, balance FROM useraccounts WHERE id = $1 AND username = $2',
      [accountId, req.session.username]
    );
    if (result.rows.length === 0) {
      return res.status(404).send('Account not found');
    }
    const account = result.rows[0];
    res.render('check-balance-detail', { account });
  } catch (err) {
    console.error('Error fetching account balance:', err);
    res.status(500).send('Error retrieving account balance');
  }
});

app.get('/make-payments', checkAuth, (req, res) => {
  res.render('make-payments', { username: req.session.username });
});

app.get('/send-money', checkAuth, (req, res) => {
  res.render('send-money-search', { message: null, username: req.session.username });
});

app.post('/send-money/search', checkAuth, async (req, res) => {
  const { phone } = req.body;
  try {
    const userResult = await pool.query('SELECT username FROM users WHERE phone = $1', [phone]);
    if (userResult.rows.length === 0) {
      return res.render('send-money-search', { message: null, username: req.session.username });
    }

    const receiverUsername = userResult.rows[0].username;
    res.redirect(`/send-money/form?receiver=${receiverUsername}`);
  } catch (err) {
    console.error('Error searching user by phone:', err);
    res.status(500).send('Server error');
  }
});

app.get('/send-money/form', checkAuth, async (req, res) => {
  const receiverUsername = req.query.receiver;
  const senderUsername = req.session.username;

  try {
    const senderAccounts = await pool.query(
      'SELECT id, shortcut_name FROM useraccounts WHERE username = $1',
      [senderUsername]
    );
    const receiverAccounts = await pool.query(
      'SELECT id, shortcut_name FROM useraccounts WHERE username = $1',
      [receiverUsername]
    );

    if (receiverAccounts.rows.length === 0) {
      return res.send('Receiver has no accounts.');
    }

    res.render('send-money-form', {
      senderUsername,
      receiverUsername,
      senderAccounts: senderAccounts.rows,
      receiverAccounts: receiverAccounts.rows,
      message: null,
      username: senderUsername
    });
  } catch (err) {
    console.error('Error loading send money form:', err);
    res.status(500).send('Server error');
  }
});

app.post('/send-money', checkAuth, async (req, res) => {
  const { senderAccountId, receiverAccountId, amount, note } = req.body;
  const senderUsername = req.session.username;
  const transferAmount = parseFloat(amount);

  if (isNaN(transferAmount) || transferAmount <= 0) {
    return res.send('Invalid amount specified.');
  }

  try {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const senderAccResult = await client.query(
        `SELECT useraccounts.balance, users.phone, useraccounts.account_name 
         FROM useraccounts 
         JOIN users ON useraccounts.username = users.username 
         WHERE useraccounts.id = $1 AND useraccounts.username = $2`,
        [senderAccountId, senderUsername]
      );

      if (senderAccResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.send('Sender account not found.');
      }

      const senderRow = senderAccResult.rows[0];
      const senderBalance = parseFloat(senderRow.balance);
      const senderPhone = senderRow.phone || 'N/A';
      const senderAccountName = senderRow.account_name;

      if (senderBalance < transferAmount) {
        await client.query('ROLLBACK');
        return res.send('Insufficient balance in sender\'s account.');
      }

      const receiverAccResult = await client.query(
        `SELECT useraccounts.username, users.phone, useraccounts.account_name 
         FROM useraccounts 
         JOIN users ON useraccounts.username = users.username 
         WHERE useraccounts.id = $1`,
        [receiverAccountId]
      );

      if (receiverAccResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.send('Receiver account not found.');
      }

      const receiverRow = receiverAccResult.rows[0];
      const receiverUsername = receiverRow.username;
      const receiverPhone = receiverRow.phone || 'N/A';
      const receiverAccountName = receiverRow.account_name;

      await client.query(
        'UPDATE useraccounts SET balance = balance - $1 WHERE id = $2 AND username = $3',
        [transferAmount, senderAccountId, senderUsername]
      );
      await client.query(
        'UPDATE useraccounts SET balance = balance + $1 WHERE id = $2',
        [transferAmount, receiverAccountId]
      );

      await client.query(
        `INSERT INTO usertransactions 
          (senderusername, senderaccount, senderphonenumber, receiverusername, receiveraccount, receiverphonenumber, narration, amount, timeoftransaction) 
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
        [
          senderUsername,
          senderAccountName,
          senderPhone,
          receiverUsername,
          receiverAccountName,
          receiverPhone,
          note || '',
          transferAmount
        ]
      );

      await client.query('COMMIT');
      res.send('Money sent successfully.');
    } catch (e) {
      await client.query('ROLLBACK');
      console.error('Transaction error:', e);
      res.status(500).send('Transaction failed.');
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Connection error:', err);
    res.status(500).send('Server error');
  }
});

app.get('/pay-bills', checkAuth, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT phone FROM users WHERE username = $1', [req.session.username]);
    if (userResult.rows.length === 0) return res.send('User record not found.');

    const userPhone = userResult.rows[0].phone;

    const billsResult = await pool.query(
      'SELECT id, billname, amount, lastdate FROM billgenerator WHERE phonenumber = $1',
      [userPhone]
    );

    res.render('pay-bills-list', {
      username: req.session.username,
      bills: billsResult.rows
    });
  } catch (err) {
    console.error('Error fetching bills:', err);
    res.status(500).send('Error loading bills');
  }
});

app.get('/pay-bills/pay/:billId', checkAuth, async (req, res) => {
  const billId = req.params.billId;
  try {
    const billResult = await pool.query('SELECT * FROM billgenerator WHERE id = $1', [billId]);
    if (billResult.rows.length === 0) return res.send('Bill not found.');

    const bill = billResult.rows[0];

    const accountsResult = await pool.query('SELECT id, shortcut_name FROM useraccounts WHERE username = $1', [req.session.username]);

    const divisionsResult = await pool.query(
      `SELECT amount, nameofthedivision, accountshortcutname FROM accountdivisions WHERE username = $1 AND LOWER(nameofthedivision) = LOWER($2)`,
      [req.session.username, bill.billname]
    );

    res.render('pay-single-bill-form', {
      bill,
      accounts: accountsResult.rows,
      divisions: divisionsResult.rows,
      username: req.session.username,
      warning: null
    });
  } catch (err) {
    console.error('Error loading bill payment form:', err);
    res.status(500).send('Error loading form');
  }
});

app.post('/pay-bills/pay/:billId', checkAuth, async (req, res) => {
  const billId = req.params.billId;
  const { senderAccountId, overrideWarning } = req.body; 
  try {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const billResult = await client.query('SELECT * FROM billgenerator WHERE id = $1', [billId]);
      if (billResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.send('Bill not found.');
      }
      const bill = billResult.rows[0];
      const billName = bill.billname;

      const userResult = await client.query('SELECT phone FROM users WHERE username = $1', [req.session.username]);
      if (userResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.send('User not found.');
      }
      const userPhone = userResult.rows[0].phone;

      const amount = parseFloat(bill.amount);

      const accountResult = await client.query(
        'SELECT account_name, balance, shortcut_name FROM useraccounts WHERE id = $1 AND username = $2',
        [senderAccountId, req.session.username]
      );
      if (accountResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.send('Account not found.');
      }
      const balance = parseFloat(accountResult.rows[0].balance);
      const senderAccountName = accountResult.rows[0].account_name;
      const shortcutName = accountResult.rows[0].shortcut_name;

      const divisionResult = await client.query(
        'SELECT amount FROM accountdivisions WHERE username = $1 AND accountshortcutname = $2 AND LOWER(nameofthedivision) = LOWER($3)',
        [req.session.username, shortcutName, billName]
      );

      const divisionAmount = divisionResult.rows.length > 0 ? parseFloat(divisionResult.rows[0].amount) : null;

      if (balance < amount) {
        await client.query('ROLLBACK');
        return res.send('Insufficient balance.');
      }

      if (divisionAmount !== null && amount > divisionAmount && !overrideWarning) {
        await client.query('ROLLBACK');

        const accountsResult = await client.query('SELECT id, shortcut_name FROM useraccounts WHERE username = $1', [req.session.username]);
        const divisionsResult = await client.query(
          `SELECT amount, nameofthedivision, accountshortcutname FROM accountdivisions WHERE username = $1 AND LOWER(nameofthedivision) = LOWER($2)`,
          [req.session.username, billName]
        );

        return res.render('pay-single-bill-form', {
          bill,
          accounts: accountsResult.rows,
          divisions: divisionsResult.rows,
          username: req.session.username,
          warning: 'This bill amount exceeds your division limit. To proceed, please confirm again.'
        });
      }

      await client.query(
        'UPDATE useraccounts SET balance = balance - $1 WHERE id = $2 AND username = $3',
        [amount, senderAccountId, req.session.username]
      );

      await client.query('DELETE FROM billgenerator WHERE id = $1', [billId]);

      await client.query(
        `INSERT INTO usertransactions 
          (senderusername, senderaccount, senderphonenumber, receiverusername, receiveraccount, receiverphonenumber, narration, amount, timeoftransaction) 
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
        [
          req.session.username,
          senderAccountName,
          userPhone,
          'Bill Payment',
          'Bill Payment',
          '',
          `Bill payment: ${billName}`,
          amount
        ]
      );

      if (divisionAmount !== null && amount > divisionAmount && overrideWarning) {
        const csResult = await client.query(
          'SELECT creditscore FROM usercreditscores WHERE username = $1',
          [req.session.username]
        );

        if (csResult.rows.length > 0) {
          const currentScore = parseFloat(csResult.rows[0].creditscore);
          const updatedScore = Math.max(0, currentScore * 0.93);

          await client.query(
            'UPDATE usercreditscores SET creditscore = $1 WHERE username = $2',
            [updatedScore, req.session.username]
          );
        }
      }

      await client.query('COMMIT');
      if (divisionAmount !== null && amount <= divisionAmount) {
        const today = new Date();
        const dueDate = new Date(bill.lastdate);
        if (today <= dueDate) {
          const csResult = await pool.query(
           'SELECT creditscore FROM usercreditscores WHERE username = $1',
        [req.session.username]
        );
        if (csResult.rows.length > 0) {
        const currentScore = parseFloat(csResult.rows[0].creditscore);
        const increasedScore = Math.min(100, currentScore * 1.02); 
        await pool.query(
         'UPDATE usercreditscores SET creditscore = $1 WHERE username = $2',
          [increasedScore, req.session.username]
        );
          }
        }
      }

      res.send('Bill paid successfully.');
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error paying bill:', err);
      res.status(500).send('Payment failed.');
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Connection error:', err);
    res.status(500).send('Server error');
  }
});

app.get('/reports', checkAuth, (req, res) => {
  res.render('reports', { username: req.session.username });
});

app.get('/reports/transactions', checkAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM usertransactions 
       WHERE senderusername = $1 
       ORDER BY timeoftransaction DESC 
       LIMIT 10`,
      [req.session.username]
    );
    res.render('reports-transactions', {
      username: req.session.username,
      transactions: result.rows
    });
  } catch (err) {
    console.error('Error fetching transactions:', err);
    res.status(500).send('Error loading transactions');
  }
});

app.get('/reports/profitandloss', checkAuth, async (req, res) => {
  try {
    const allTxResult = await pool.query(
      `SELECT amount FROM usertransactions WHERE senderusername = $1`,
      [req.session.username]
    );
    const incomeResult = await pool.query(
      `SELECT income FROM useraccounts WHERE username = $1`,
      [req.session.username]
    );

    const totalAccountIncome = incomeResult.rows.reduce((sum, row) => sum + parseFloat(row.income || 0), 0);

    const allTransactions = allTxResult.rows;
    let netIncome = totalAccountIncome; 
    let netExpense = 0;

    allTransactions.forEach(tx => {
      if (tx.amount > 0) {
        netExpense += tx.amount;
      } else {
        netIncome += Math.abs(tx.amount);
      }
    });

    const profitAndLoss = netIncome - netExpense;

    const recentTxResult = await pool.query(
      `SELECT * FROM usertransactions WHERE senderusername = $1 ORDER BY timeoftransaction DESC LIMIT 10`,
      [req.session.username]
    );

    res.render('reports-profitandloss', {
      username: req.session.username,
      transactions: recentTxResult.rows,
      netIncome,
      netExpense,
      profitAndLoss
    });

  } catch (err) {
    console.error('Error loading profit and loss report:', err);
    res.status(500).send('Error loading report');
  }
});

app.get('/reports/inspect', checkAuth, async (req, res) => {
  const username = req.session.username;

   try {
   const today = new Date();
   const fromDate = new Date(today.getFullYear(), today.getMonth() - 11, 1);

   const pieResult = await pool.query(`
     SELECT narration AS category, SUM(amount) AS total
     FROM usertransactions
     WHERE senderusername = $1
     AND amount > 0
     AND timeoftransaction >= $2
     GROUP BY narration
     `, [username, fromDate]);

   const lineResult = await pool.query(`
     SELECT TO_CHAR(timeoftransaction, 'Mon YYYY') AS month, SUM(ABS(amount)) AS total
     FROM usertransactions
     WHERE senderusername = $1
     AND amount < 0
     AND timeoftransaction >= $2
     GROUP BY month
     ORDER BY MIN(timeoftransaction)
     `, [username, fromDate]);

   const profitResult = await pool.query(`
     SELECT TO_CHAR(timeoftransaction, 'Mon YYYY') AS month,
     SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) AS income,
     SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) AS expense
     FROM usertransactions
     WHERE senderusername = $1
     AND timeoftransaction >= $2
     GROUP BY month
     ORDER BY MIN(timeoftransaction)
     `, [username, fromDate]);

   const pie = {
     labels: pieResult.rows.map(r => r.category || "Uncategorized"),
     data: pieResult.rows.map(r => parseFloat(r.total))
    };

   const line = {
     labels: lineResult.rows.map(r => r.month),
     data: lineResult.rows.map(r => parseFloat(r.total))
     };

  const bar = {
    labels: profitResult.rows.map(r => r.month),
     data: profitResult.rows.map(r => parseFloat(r.income) - parseFloat(r.expense)) };

  res.render('reports-inspect', {
     username,
     pie,
     line,
     bar
  });
  } catch (err) {
    console.error('Error loading inspect charts:', err);
    res.status(500).send('Error loading charts');
  }
});

app.get('/reports/custom', checkAuth, async (req, res) => {
  try {

    const categoriesResult = await pool.query(
      'SELECT DISTINCT narration FROM usertransactions WHERE senderusername = $1',
      [req.session.username]
    );
    
    const categories = categoriesResult.rows.map(r => r.narration).filter(c => c);

    res.render('reports-custom', { username: req.session.username, categories });
  } catch (err) {
    console.error('Error loading custom reports page:', err);
    res.status(500).send('Error loading custom reports page');
  }
});

app.post('/reports/custom/data', checkAuth, async (req, res) => {
  const { category, chartType } = req.body;
  const username = req.session.username;

  try {
    let labels = [];
    let data = [];

    const isAll = !category || category === 'all';

    if (chartType === 'pie') {
      if (isAll) {
        const pieResult = await pool.query(
          `SELECT narration AS label, SUM(amount) AS value
           FROM usertransactions
           WHERE senderusername = $1
           AND amount > 0
           GROUP BY narration`,
          [username]
        );
        labels = pieResult.rows.map(r => r.label || "Uncategorized");
        data = pieResult.rows.map(r => parseFloat(r.value));
      } else {
        const pieResult = await pool.query(
          `SELECT narration AS label, SUM(amount) AS value
           FROM usertransactions
           WHERE senderusername = $1
           AND narration ILIKE $2
           AND amount > 0
           GROUP BY narration`,
          [username, `%${category}%`]
        );
        labels = pieResult.rows.map(r => r.label || "Uncategorized");
        data = pieResult.rows.map(r => parseFloat(r.value));
      }
    } else if (chartType === 'bar') {
      const fromDate = new Date();
      fromDate.setMonth(fromDate.getMonth() - 11);
      const fromDateStr = fromDate.toISOString();

      if (isAll) {
        const barResult = await pool.query(
          `SELECT TO_CHAR(timeoftransaction, 'Mon YYYY') AS month, SUM(amount) AS total
           FROM usertransactions
           WHERE senderusername = $1
           AND amount > 0
           AND timeoftransaction >= $2
           GROUP BY month
           ORDER BY MIN(timeoftransaction)`,
          [username, fromDateStr]
        );
        labels = barResult.rows.map(r => r.month);
        data = barResult.rows.map(r => parseFloat(r.total));
      } else {
        const barResult = await pool.query(
          `SELECT TO_CHAR(timeoftransaction, 'Mon YYYY') AS month, SUM(amount) AS total
           FROM usertransactions
           WHERE senderusername = $1
           AND narration ILIKE $2
           AND amount > 0
           AND timeoftransaction >= $3
           GROUP BY month
           ORDER BY MIN(timeoftransaction)`,
          [username, `%${category}%`, fromDateStr]
        );
        labels = barResult.rows.map(r => r.month);
        data = barResult.rows.map(r => parseFloat(r.total));
      }
    } else if (chartType === 'line') {
      const fromDate = new Date();
      fromDate.setMonth(fromDate.getMonth() - 11);
      const fromDateStr = fromDate.toISOString();

      if (isAll) {
        const lineResult = await pool.query(
          `SELECT TO_CHAR(timeoftransaction, 'Mon YYYY') AS month, SUM(amount) AS total
          FROM usertransactions
          WHERE senderusername = $1
          AND amount > 0
          AND timeoftransaction >= $2
          GROUP BY month
          ORDER BY MIN(timeoftransaction)`,
          [username, fromDateStr]
        );
        labels = lineResult.rows.map(r => r.month);
        data = lineResult.rows.map(r => parseFloat(r.total));
      } else {
        const lineResult = await pool.query(
          `SELECT TO_CHAR(timeoftransaction, 'Mon YYYY') AS month, SUM(ABS(amount)) AS total
           FROM usertransactions
           WHERE senderusername = $1
           AND narration ILIKE $2
           AND amount > 0
           AND timeoftransaction >= $3
           GROUP BY month
           ORDER BY MIN(timeoftransaction)`,
          [username, `%${category}%`, fromDateStr]
        );
        labels = lineResult.rows.map(r => r.month);
        data = lineResult.rows.map(r => parseFloat(r.total));
      }
    } else {
      return res.status(400).json({ error: 'Invalid chart type or category' });
    }

    return res.json({ labels, data });

  } catch (err) {
    console.error('Error fetching custom chart data:', err);
    res.status(500).json({ error: 'Server error fetching data' });
  }
});

app.get('/manage-divisions', checkAuth, async (req, res) => {
  const username = req.session.username;
  try {
    const divisionsRes = await pool.query(
      'SELECT * FROM accountdivisions WHERE username = $1',
      [username]
    );
    const shortcutsRes = await pool.query(
      'SELECT shortcut_name FROM useraccounts WHERE username = $1',
      [username]
    );

    res.render('manage-divisions', {
      divisions: divisionsRes.rows,
      accountShortcuts: shortcutsRes.rows,
      error: null
    });
  } catch (err) {
    console.error('Error fetching divisions:', err);
    res.status(500).send('Server error');
  }
});

app.post('/manage-divisions/add', checkAuth, async (req, res) => {
  const username = req.session.username;
  const { accountshortcutname, amount, nameofthedivision } = req.body;
  const amt = parseFloat(amount);

  try {
    const accRes = await pool.query(
      'SELECT id, income FROM useraccounts WHERE username = $1 AND shortcut_name = $2',
      [username, accountshortcutname]
    );

    if (accRes.rows.length === 0) {
      const [divisionsRes, shortcutsRes] = await Promise.all([
        pool.query('SELECT * FROM accountdivisions WHERE username = $1', [username]),
        pool.query('SELECT shortcut_name FROM useraccounts WHERE username = $1', [username])
      ]);
      return res.render('manage-divisions', {
        divisions: divisionsRes.rows,
        accountShortcuts: shortcutsRes.rows,
        error: "Selected account not found."
      });
    }

    const accountId = accRes.rows[0].id;
    const income = parseFloat(accRes.rows[0].income);

    if (amt > income) {
      const [divisionsRes, shortcutsRes] = await Promise.all([
        pool.query('SELECT * FROM accountdivisions WHERE username = $1', [username]),
        pool.query('SELECT shortcut_name FROM useraccounts WHERE username = $1', [username])
      ]);
      return res.render('manage-divisions', {
        divisions: divisionsRes.rows,
        accountShortcuts: shortcutsRes.rows,
        error: "Entered amount exceeds account income."
      });
    }

    const sumRes = await pool.query(
      'SELECT COALESCE(SUM(amount), 0) AS total_divisions FROM accountdivisions WHERE username = $1 AND accountshortcutname = $2',
      [username, accountshortcutname]
    );
    const totalDivisionsAmount = parseFloat(sumRes.rows[0].total_divisions);

    if (amt > (income - totalDivisionsAmount)) {
      const [divisionsRes, shortcutsRes] = await Promise.all([
        pool.query('SELECT * FROM accountdivisions WHERE username = $1', [username]),
        pool.query('SELECT shortcut_name FROM useraccounts WHERE username = $1', [username])
      ]);
      return res.render('manage-divisions', {
        divisions: divisionsRes.rows,
        accountShortcuts: shortcutsRes.rows,
        error: "Total division amounts exceed account income."
      });
    }
    await pool.query(
      'INSERT INTO accountdivisions (username, accountshortcutname, amount, nameofthedivision, accountid) VALUES ($1, $2, $3, $4, $5)',
      [username, accountshortcutname, amt, nameofthedivision, accountId]
    );

    res.redirect('/manage-divisions');

  } catch (err) {
    console.error('Error adding division:', err);
    res.status(500).send('Server error while adding division');
  }
});

app.listen(port, () => {
  console.log(`Savrr app listening on port ${port}`);
});
