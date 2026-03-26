require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { initializeDatabase } = require('./database');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 5000;

// ─── CORS: Sabse pehle, kisi bhi route se pehle ──────────────────────────────
// Step 1: Every request pe CORS headers manually set karo
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Allow karne wale origins
  const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://127.0.0.1:3000',
  ];

  // .env me set FRONTEND_URL add karo (comma-separated support)
  if (process.env.FRONTEND_URL) {
    process.env.FRONTEND_URL.split(',').forEach(u => allowedOrigins.push(u.trim()));
  }

  const isAllowed =
    !origin ||                                          // no origin = same origin / mobile / postman
    process.env.ALLOW_ALL_ORIGINS === 'true' ||         // env me true hai
    allowedOrigins.includes(origin) ||                  // exact match
    /\.vercel\.app$/.test(origin) ||                    // koi bhi vercel subdomain
    /\.netlify\.app$/.test(origin) ||                   // koi bhi netlify subdomain
    /\.railway\.app$/.test(origin) ||                   // railway
    /\.onrender\.com$/.test(origin);                    // render

  if (isAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With');
  res.setHeader('Access-Control-Max-Age', '86400');  // 24h preflight cache

  // OPTIONS preflight — seedha 200 return karo
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

// Step 2: cors() package bhi lagao double safety ke liye
app.use(cors({
  origin: true,       // reflect request origin
  credentials: true,
  optionsSuccessStatus: 200,
}));
// ─────────────────────────────────────────────────────────────────────────────

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Socket.IO
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  try {
    socket.user = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    next();
  } catch { next(new Error('Invalid token')); }
});

io.on('connection', (socket) => {
  console.log(`⚡ Socket connected: ${socket.user.name} (${socket.user.role})`);
  socket.join(`user_${socket.user.id}`);
  if (socket.user.role === 'admin') socket.join('admins');
  if (socket.user.role === 'field_worker') socket.join('field_workers');

  socket.on('location_ping', (data) => {
    io.to('admins').emit('worker_location', {
      worker_id: socket.user.id,
      worker_name: socket.user.name,
      ...data,
      timestamp: new Date().toISOString(),
    });
  });

  socket.on('visit_started', (data) => {
    io.to('admins').emit('worker_visit', {
      worker_id: socket.user.id,
      worker_name: socket.user.name,
      event: 'arrived',
      ...data,
    });
  });

  socket.on('disconnect', () => {
    if (socket.user.role === 'field_worker') {
      io.to('admins').emit('worker_offline', { worker_id: socket.user.id });
    }
  });
});

app.set('io', io);

// Auth route
const bcrypt = require('bcryptjs');
const { getPool } = require('./database');

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const db = await getPool();
  try {
    const [[user]] = await db.query('SELECT * FROM users WHERE username=? AND is_active=1', [username]);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign(
      { id: user.id, name: user.name, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '24h' }
    );
    let extra = {};
    if (user.role === 'worker') {
      const [depts] = await db.query(
        `SELECT d.* FROM departments d JOIN worker_departments wd ON wd.department_id=d.id WHERE wd.worker_id=?`,
        [user.id]
      );
      extra.departments = depts;
    }
    if (user.role === 'field_worker') {
      const [areas] = await db.query(
        `SELECT a.* FROM areas a JOIN field_worker_areas fwa ON fwa.area_id=a.id WHERE fwa.worker_id=?`,
        [user.id]
      );
      extra.areas = areas;
    }
    res.json({ token, user: { id: user.id, name: user.name, username: user.username, role: user.role, ...extra } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// API routes
const apiRoutes = require('./routes');
app.use('/api', apiRoutes);

// Serve uploaded photos
const path = require('path');
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

app.get('/health', (req, res) => res.json({ status: 'OK', time: new Date() }));
app.get('*', (req, res) => res.status(404).json({ message: 'Not found' }));

initializeDatabase().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🏥 Medical Manager API running on port ${PORT}`);
  });
}).catch(err => {
  console.error('❌ DB Error:', err.message);
  process.exit(1);
});
