const jwt = require("jsonwebtoken");
const { connection } = require('./db.js');
const JWT_SECRET = process.env.JWT_SECRET;

function checkPremium(req, res, next) {
  const userId = req.user.userId;

  const sql = 'SELECT is_premium FROM users WHERE id = ?';
  connection.query(sql, [userId], (err, result) => {
    if (err) {
      return res.status(500).send('Error checking premium status');
    }

    if (result.length === 0) {
      return res.status(404).send('User not found');
    }

    const isPremium = result[0].is_premium;

    if (isPremium) {
      next();
    } else {
      return res.status(401).send('Unauthorized: Premium feature requires premium status');
    }
  });
}

async function calculateTotalExpenses(userId) {
  return new Promise((resolve, reject) => {
    const sql = 'SELECT SUM(amount) AS total FROM expenses WHERE user_id = ?';
    connection.query(sql, [userId], (err, result) => {
      if (err) {
        reject(err);
        return;
      }
      const totalExpenses = result[0].total || 0;
      resolve(totalExpenses);
    });
  });
}

async function updateTotalExpenses(userId) {
  try {
    const totalExpenses = await calculateTotalExpenses(userId);
    const updateSql = 'UPDATE users SET total_expenses = ? WHERE id = ?';
    connection.query(updateSql, [totalExpenses, userId], (updateErr, _updateResult) => {
      if (updateErr) {
        console.error('Error updating total expenses:', updateErr);
      } else {
        console.log('Total expenses updated successfully');
      }
    });
  } catch (error) {
    console.error('Error calculating total expenses:', error);
  }
}

function setTokenCookie(res, token) {
  res.cookie('token', token, { httpOnly: true });
}

function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

module.exports = {
  checkPremium,
  calculateTotalExpenses,
  updateTotalExpenses,
  setTokenCookie,
  authenticateToken
};
