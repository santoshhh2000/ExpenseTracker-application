require('dotenv').config();
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const Razorpay = require('razorpay');
const { connection } = require('./db.js');

const { checkPremium, calculateTotalExpenses, updateTotalExpenses, setTokenCookie, authenticateToken } = require('./middleware.js');


const razorpay = new Razorpay({
  key_id: process.env.key_id,
  key_secret: process.env.key_secret
});


const JWT_SECRET = process.env.JWT_SECRET;

const app = express();
const port = process.env.port || 3001;


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/', async (req, res) => {
  const { name, email, password } = req.body;
  const emailCheck = 'SELECT * FROM users WHERE email=?';
  connection.query(emailCheck, [email], async (emailCheckErr, emailCheckResult) => {
    if (emailCheckErr) {
      res.status(500).send('Error checking email');
      return;
    }

    if (emailCheckResult.length > 0) {
      res.status(400).send('Email already exists');
      return;
    }

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const sql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
      connection.query(sql, [name, email, hashedPassword], (err, _result) => {
        if (err) {
          res.status(500).send('Error inserting data into database');
          return;
        }
        res.redirect('/signIn');
      });
    } catch (hashErr) {
      res.status(500).send('Error hashing password');
    }
  });
});

app.get('/signIn', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signIn.html'));
});

app.post('/signIn', async (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email=?';
  connection.query(sql, [email], async (err, result) => {
    if (err) {
      res.status(500).send('Error retrieving data from database');
      return;
    }

    if (result.length === 0) {
      res.status(401).send('Invalid email or password');
      return;
    }
    const user = result[0];
    const hashedPasswordFromDB = user.password;

    try {
      const isValid = await bcrypt.compare(password, hashedPasswordFromDB);
      if (isValid) {
        const userId = user.id;
        const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: process.env.expiresIn });
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/expenses');
      } else {
        res.status(401).send('Invalid email or password');
      }
    } catch (error) {
      res.status(500).send('Error comparing passwords');
    }
  });
});

app.get('/expenses', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'expenses.html'));
});

app.post('/expenses', authenticateToken, async (req, res) => {
  const { expenseType, description, amount } = req.body;
  const userId = req.user.userId;
  const sql = 'INSERT INTO expenses (user_id, expense_type, description, amount) VALUES (?, ?, ?, ?)';
  connection.query(sql, [userId, expenseType, description, amount], (err, result) => {
    if (err) {
      res.status(500).send('Error inserting data into database');
      return;
    }
    updateTotalExpenses(userId);
    res.redirect('/expenses');
  });
});

app.get('/expensesData', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const { page = process.env.page, pageSize = process.env.pageSize } = req.query;
  const offset = (page - 1) * pageSize;

  connection.query('SELECT COUNT(*) AS total FROM expenses WHERE user_id = ?', [userId], (err, countResult) => {
    if (err) {
      res.status(500).json({ error: 'Error fetching total count' });
      return;
    }
    const totalCount = countResult[0].total;
    const totalPages = Math.ceil(totalCount / pageSize);

    const sql = 'SELECT * FROM expenses WHERE user_id = ? LIMIT ? OFFSET ?';
    connection.query(sql, [userId, parseInt(pageSize), parseInt(offset)], (err, results) => {
      if (err) {
        res.status(500).json({ error: 'Error fetching expenses from database' });
        return;
      }
      res.json({ data: results, totalPages });
    });
  });
});

app.get('/forgotPassword', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'forgotPassword.html'));
});

app.post("/forgotPassword", (req, res) => {
  const { email } = req.body;
  const sql = 'SELECT * FROM users WHERE email=?';
  connection.query(sql, [email], async (err, result) => {
    if (err) {
      res.status(500).send('Error retrieving data from database');
      return;
    }

    if (result.length === 0) {
      res.status(401).send('Invalid email or password');
      return;
    }

    try {
      const oldUser = result[0];
      const secret = JWT_SECRET + oldUser.password;
      const token = jwt.sign({ email: oldUser.email, id: oldUser.id }, secret, {
        expiresIn: "500m",
      });
      const link = `http://localhost:${port}/reset-password/${oldUser.id}/${token}`;

      var transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.user1,
          pass: process.env.pass,
        },
      });

      var mailOptions = {
        from: process.env.user1,
        to: email,
        subject: "Password Reset",
        text: link,
      };

      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log(error);
        }
      });

      res.send("Password reset link sent successfully");
    } catch (error) {
      res.status(500).send('Error generating reset link');
    }
  });
});

app.get("/reset-password/:id/:token", (req, res) => {
  const { id, token } = req.params;
  const sql = 'SELECT * FROM users WHERE id=?';

  connection.query(sql, [id], (err, result) => {
    if (err) {
      return res.status(500).send('Error retrieving data from database');
    }

    if (result.length === 0) {
      return res.status(401).send('Invalid user');
    }

    const oldUser = result[0];
    const secret = JWT_SECRET + oldUser.password;

    try {
      const verify = jwt.verify(token, secret);
      res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
    } catch (error) {
      res.status(401).send('Token verification failed');
    }
  });
});

app.post("/reset-password/:id/:token", (req, res) => {
  const { id, token } = req.params;
  const password = req.body.password;
  const sql = 'SELECT * FROM users WHERE id=?';
  connection.query(sql, [id], async (err, result) => {
    if (err) {
      return res.status(500).send('Error retrieving data from database');
    }

    if (result.length === 0) {
      return res.status(401).send('Invalid user');
    }

    const oldUser = result[0];
    const secret = JWT_SECRET + oldUser.password;

    try {
      const verify = jwt.verify(token, secret);
      const hashedPassword = await bcrypt.hash(password, 10);
      const updateSql = 'UPDATE users SET password=? WHERE id=?';

      connection.query(updateSql, [hashedPassword, oldUser.id], (updateErr, _updateResult) => {
        if (updateErr) {
          return res.status(500).send('Error updating password');
        }
        res.redirect('/signIn');
      });
    } catch (error) {
      return res.status(500).send('Error resetting password');
    }
  });

});

app.get('/deleteExpense/:id', authenticateToken, (req, res) => {
  const expenseId = req.params.id;
  connection.query('DELETE FROM expenses WHERE id = ?', [expenseId], (err, _result) => {
    if (err) {
      res.status(500).send('Error deleting expense');
      return;
    }
    const userId = req.user.userId;
    updateTotalExpenses(userId);
    res.redirect('/expenses');
  });
});

app.get('/fetchExpense/:id', authenticateToken, (req, res) => {
  const expenseId = req.params.id;
  const sql = 'SELECT * FROM expenses WHERE id = ?';

  connection.query(sql, [expenseId], (err, result) => {
    if (err) {
      res.status(500).json({ error: 'Error fetching expense details' });
      return;
    }

    if (result.length === 0) {
      res.status(404).json({ error: 'Expense not found' });
      return;
    }

    const expense = result[0];
    res.json(expense);
  });
});

app.get('/usersByTotalExpenses', async (req, res) => {
  try {
    const sql = 'SELECT id, name, total_expenses FROM users ORDER BY total_expenses DESC';
    connection.query(sql, (err, results) => {
      if (err) {
        res.status(500).json({ error: 'Error fetching users' });
        return;
      }
      res.json(results);
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/updateExpense/:id', authenticateToken, (req, res) => {
  const expenseId = req.params.id;
  const { expenseType, description, amount } = req.body;
  const sql = `UPDATE expenses SET expense_type = ?, description = ?, amount = ? WHERE id = ?`;
  const values = [expenseType, description, amount, expenseId];
  connection.query(sql, values, (err, result) => {
    if (err) {
      res.status(500).json({ error: 'Failed to update expense' });
      return;
    }
    const userId = req.user.userId;
    updateTotalExpenses(userId);
    res.status(200).json({ message: 'Expense updated successfully' });
  });
});


app.get('/create_payment', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'premium.html'));
});

app.post('/create_payment', authenticateToken, async (req, res) => {
  const options = {
    amount: 500 * 100,
    currency: 'INR',
    receipt: 'receipt_id_1'
  };

  try {
    const response = await razorpay.orders.create(options);
    const orderId = response.id;
    const userId = req.user.userId;
    res.json({ order_id: orderId });
  } catch (error) {
    res.status(500).json({ error: 'Razorpay API error: ' + error.description });
  }
});

app.post('/verify_payment', authenticateToken, async (req, res) => {
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;

  try {
    const payment = await razorpay.payments.fetch(razorpay_payment_id);
    if (payment.status === 'authorized') {
      const captureResponse = await razorpay.payments.capture(razorpay_payment_id, payment.amount);
      if (captureResponse.status === 'captured') {
        const userId = req.user.userId;
        const updateSql = 'UPDATE users SET is_premium = ? WHERE id = ?';
        connection.query(updateSql, [true, userId], (updateErr, _updateResult) => {
          if (updateErr) {
            res.status(500).send('Error updating user premium status');
            return;
          }
          res.sendStatus(200);
        });
      } else {
        res.status(400).send('Payment capture failed');
      }
    } else {
      res.status(400).send('Payment not authorized');
    }
  } catch (error) {
    res.status(500).json({ error: 'Error verifying payment: ' + error.message });
  }
});

app.get('/daily-report', authenticateToken, checkPremium, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'daily_report.html'));
});

app.post('/daily-report', authenticateToken, (req, res) => {
  const { reportDate } = req.body;
  const userId = req.user.userId;
  const sql = 'SELECT * FROM expenses WHERE DATE(created_at) = ? AND user_id = ?';

  connection.query(sql, [reportDate, userId], (err, results) => {
    if (err) {
      res.status(500).json({ error: 'Error fetching expenses from database' });
      return;
    }
    res.json(results);
  });
});

app.get('/monthly-report', authenticateToken, checkPremium, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'monthly-report.html'));
});

app.post('/monthly-report', authenticateToken, (req, res) => {
  const { year, month } = req.body;
  const userId = req.user.userId;
  const startDate = new Date(year, month - 1, 1);
  const endDate = new Date(year, month, 0);
  try {
    const sql = `
        SELECT *
        FROM expenses
        WHERE created_at >= ? AND created_at <= ? AND user_id = ?
    `;
    connection.query(sql, [startDate, endDate, userId], (err, results) => {
      if (err) {
        res.status(500).json({ error: 'Error fetching expenses' });
        return;
      }

      res.json(results);
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/leaderboard', authenticateToken, checkPremium, (req, res) => {
  try {
    const sql = 'SELECT id, name, total_expenses FROM users ORDER BY total_expenses DESC';
    connection.query(sql, (err, results) => {
      if (err) {
        res.status(500).send('Error fetching users');
        return;
      }

      res.sendFile(path.join(__dirname, 'public', 'usersByTotalExpenses.html'));
    });
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/signIn');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
