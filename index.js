require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const SECRET = process.env.SECRET;
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).send('Server error');
    if (results.length === 0) return res.status(401).send('Invalid credentials');
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send('Invalid credentials');
    const token = jwt.sign({ id: user.id, role: user.role }, SECRET);
    res.json({ token, userId: user.id, role: user.role });
  });
});

app.get('/api/admin/users', (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).send("No token provided");
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err || decoded.role !== "admin") return res.status(403).send("Access denied");
    db.query("SELECT id, name, email, role FROM users", (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results);
    });
  });
});

app.delete('/api/admin/users/:id', (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).send("No token provided");
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err || decoded.role !== "admin") return res.status(403).send("Access denied");
    db.query("DELETE FROM users WHERE id = ?", [req.params.id], (err) => {
      if (err) return res.status(500).send(err);
      res.sendStatus(200);
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
