const http = require('http');
const path = require('path');
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { Server: SocketServer } = require('socket.io');
const { configureRealtimeAdapter } = require('./services/realtimeAdapter');

// Fail fast for mongoose if database is offline
mongoose.set('bufferCommands', false);

// Load environment variables safely (do not fail if .env is missing in production on Render)
if (process.env.NODE_ENV !== 'production') {
  dotenv.config();
} else {
  dotenv.config({ silent: true });
}

const { notFound, errorHandler } = require('./middleware/errorMiddleware');
const { pool, initializeDatabase } = require('./config/postgres');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const settingsRoutes = require('./routes/settingsRoutes');
const auditRoutes = require('./routes/auditRoutes');
const studentApplicationRoutes = require('./routes/studentApplicationRoutes');
const studentRoutes = require('./routes/studentRoutes');
const insightRoutes = require('./routes/insightRoutes');
const reportRoutes = require('./routes/reportRoutes');
const compatRoutes = require('./routes/compatRoutes');
const placementCrmRoutes = require('./routes/placementCrmRoutes');
const compression = require('compression');
const { protect } = require('./middleware/authMiddleware');

const app = express();
// Enable trust proxy for cloud environments / reverse proxies (Render, Vercel)
app.set('trust proxy', 1);

const httpServer = http.createServer(app);
const io = new SocketServer(httpServer, {
  path: process.env.VERCEL === '1' ? '/api/socket-io/socket.io' : '/socket.io',
  cors: {
    origin: process.env.CORS_ORIGIN || process.env.CLIENT_URL
      ? (process.env.CORS_ORIGIN || process.env.CLIENT_URL).split(',').map((origin) => origin.trim())
      : '*',
  },
});

app.set('io', io);

let initializationPromise;
const initializeServices = () => {
  if (initializationPromise) return initializationPromise;
  initializationPromise = initializeServicesOnce().catch((error) => {
    initializationPromise = null;
    console.error('Service initialization failed:', error.message || error);
    throw error;
  });
  return initializationPromise;
};

const initializeServicesOnce = async () => {
  const isProduction = process.env.NODE_ENV === 'production' || process.env.VERCEL === '1';
  const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URI || process.env.MONGODB_URL;

  if (isProduction && (!process.env.JWT_SECRET || Buffer.byteLength(process.env.JWT_SECRET, 'utf8') < 32)) {
    throw new Error('JWT_SECRET must be configured with at least 32 characters in production.');
  }
  if (isProduction && !mongoUri) {
    throw new Error('MONGODB_URI is required in production for placement and application data.');
  }

  // Safely attempt PostgreSQL database initialization
  try {
    if (typeof initializeDatabase === 'function') {
      await initializeDatabase();
      console.log('PostgreSQL database initialized.');
    }
  } catch (pgErr) {
    console.warn('PostgreSQL initialization warning:', pgErr.message);
  }

  // Connect to MongoDB Atlas
  if (mongoUri && mongoose.connection.readyState !== 1) {
    try {
      await mongoose.connect(mongoUri, {
        dbName: process.env.MONGODB_DB_NAME || 'studentProfilingSystem',
        serverSelectionTimeoutMS: 5000,
        connectTimeoutMS: 5000,
        maxPoolSize: process.env.VERCEL === '1' ? 5 : 10,
        minPoolSize: 0,
      });
      console.log('MongoDB connected successfully.');
    } catch (mongoErr) {
      console.error('MongoDB connection error:', mongoErr.message);
      if (isProduction) throw mongoErr;
    }
  }

  if (mongoose.connection.readyState === 1 && process.env.VERCEL === '1') {
    await configureRealtimeAdapter(io);
  }
};

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication required.'));
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await initializeServices();
    const { rows } = await pool.query(
      'SELECT id, name, email, role, department FROM users WHERE id = $1',
      [decoded.id]
    );
    if (!rows[0]) return next(new Error('Authentication required.'));
    socket.data.user = rows[0];
    next();
  } catch (error) {
    next(new Error('Authentication failed.'));
  }
});

io.on('connection', (socket) => {
  socket.on('disconnect', () => {});
});

const fallbackApplications = [];

app.locals = app.locals || {};
app.locals.fallbackApplications = fallbackApplications;

// Gzip/Brotli Compression
app.use(compression());

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// CORS configuration supporting CLIENT_URL from Render env
const allowedOrigins = (process.env.CLIENT_URL || process.env.CORS_ORIGIN || '*')
  .split(',')
  .map((origin) => origin.trim());

app.use(cors({
  origin: allowedOrigins.includes('*') ? '*' : allowedOrigins,
  credentials: true,
}));

// Set security headers with Helmet
app.use(
  helmet({
    frameguard: { action: 'sameorigin' },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        frameAncestors: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          'https://cdn.jsdelivr.net',
          'https://cdnjs.cloudflare.com',
        ],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://cdn.jsdelivr.net',
          'https://cdnjs.cloudflare.com',
          'https://fonts.googleapis.com',
        ],
        fontSrc: [
          "'self'",
          'https://cdn.jsdelivr.net',
          'https://cdnjs.cloudflare.com',
          'https://fonts.gstatic.com',
        ],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'", 'ws:', 'wss:', 'https:'],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// Dev logging middleware
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Rate limiting for API requests
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: {
    success: false,
    message: 'Too many requests from this IP address, please try again after 15 minutes.',
  },
});
app.use('/api', limiter);

app.get('/api/runtime-config', (req, res) => {
  const socketPath = process.env.VERCEL === '1'
    ? '/api/socket-io/socket.io'
    : '/socket.io';
  res.json({
    success: true,
    data: {
      socketPath,
      socketScriptPath: `${socketPath}/socket.io.js`,
      socketTransports: process.env.VERCEL === '1' ? ['websocket'] : ['websocket', 'polling'],
    },
  });
});

app.use('/api', async (req, res, next) => {
  try {
    await initializeServices();
    next();
  } catch (error) {
    next(error);
  }
});

// Serve static frontend assets
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  etag: true,
}));

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    await initializeServices();
    res.status(200).json({
      success: true,
      databases: {
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Database health check failed:', error.message);
    res.status(503).json({ success: false, message: error.message || 'Database connection failed.' });
  }
});

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/audit-logs', auditRoutes);
app.use('/api/student-applications', studentApplicationRoutes);
app.use('/api/students', studentRoutes);
app.use('/api/insights', insightRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/placement', placementCrmRoutes);
app.use('/api', placementCrmRoutes);
app.use('/api', compatRoutes);

app.use('/api', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found.',
  });
});

// Fallback for SPA routing
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) {
    return next();
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use(notFound);
app.use(errorHandler);

const startServer = async () => {
  try {
    await initializeServices();
    const port = Number(process.env.PORT) || 5000;
    const server = httpServer.listen(port, '0.0.0.0', () => {
      console.log(`\n======================================================`);
      console.log(`Student Academic Personal & Career Profiling System`);
      console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${port}`);
      console.log(`======================================================\n`);
    });

    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`Port ${port} is already in use.`);
      } else {
        console.error('Backend listener failed:', error.message);
      }
      process.exitCode = 1;
    });
  } catch (err) {
    console.error('Failed to start backend detailed error:', err.stack || err);
    process.exit(1);
  }
};

if (require.main === module) {
  startServer();
}

module.exports = app;
module.exports.httpServer = httpServer;
module.exports.initializeServices = initializeServices;
