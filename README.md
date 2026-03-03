const express = require('express');
const winston = require('winston');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');

const app = express();
app.use(express.json());
app.use(helmet()); // Fix 3: Secure HTTP headers

const users = [];
const SECRET_KEY = 'your-secret-key';

// REGISTER ROUTE
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!validator.isEmail(email)) {
    return res.status(400).send('Invalid email format');
  }
  if (validator.isEmpty(password) || password.length < 6) {
    return res.status(400).send('Password must be at least 6 characters');
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ email, password: hashedPassword });
  res.status(201).send('User registered successfully');
});

// LOGIN ROUTE
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!validator.isEmail(email)) return res.status(400).send('Invalid email format');
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).send('User not found');
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).send('Invalid password');
  const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
  res.send({ message: 'Login successful', token });
});

// PROTECTED PROFILE ROUTE
app.get('/profile', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).send('Access denied. No token provided.');
  try {
    const verified = jwt.verify(token, SECRET_KEY);
    res.send({ message: 'Welcome to your profile!', user: verified.email });
  } catch (err) {
    res.status(400).send('Invalid token');
  }
});

app.listen(3000, () => console.log('Secure app running on http://localhost:3000'));
