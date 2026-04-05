import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { createServer as createViteServer } from 'vite';

dotenv.config();

// --- Environment Variable Validation ---
console.log('🔍 Validating environment variables...');

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;

if (!JWT_SECRET) {
  console.warn('⚠️ WARNING: JWT_SECRET is not defined in environment variables.');
  console.warn('💡 ACTION: Using a fallback secret key for development. For production, please set JWT_SECRET in Settings > Environment Variables.');
} else {
  console.log('✅ JWT_SECRET is defined.');
}

if (!MONGODB_URI) {
  console.warn('⚠️ WARNING: MONGODB_URI is not defined in environment variables.');
  console.warn('💡 ACTION: The application will start in "Offline Mode" (In-Memory storage). To enable persistent storage, please set MONGODB_URI in Settings > Environment Variables.');
} else {
  // Basic format check for MONGODB_URI
  if (MONGODB_URI.startsWith('mongodb+srv://') || MONGODB_URI.startsWith('mongodb://')) {
    console.log('✅ MONGODB_URI format looks valid.');
  } else {
    console.warn('⚠️ WARNING: MONGODB_URI format may be incorrect. It should start with "mongodb://" or "mongodb+srv://".');
  }
}

const FINAL_JWT_SECRET = JWT_SECRET || 'fallback_secret_key_for_dev_only';
// --- End Validation ---

const app = express();

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Global Error Handlers
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception thrown:', err);
});

// In-memory user storage for temporary testing
const tempUsers: any[] = [];

// Middleware
app.use(cors());
app.use(express.json());

// Logging Middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Health check (Top Level - Fast)
app.get('/api/health/ping', (req, res) => {
  res.json({ status: 'pong', timestamp: new Date().toISOString() });
});

// DB Connection Check Middleware
const checkDbConnection = (req: any, res: any, next: any) => {
  console.log(`Checking DB connection for ${req.url}... Status: ${mongoose.connection.readyState}`);
  if (mongoose.connection.readyState !== 1) {
    const tip = (app as any).dbErrorTip;
    return res.status(503).json({ 
      message: tip || 'Database connection is not established. Please wait a few seconds or check your configuration.' 
    });
  }
  next();
};

// Auth Middleware
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, FINAL_JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

console.log('🏁 server.ts loading...');

async function startServer() {
  console.log('🏁 Initializing SQLi Tool Backend...');
  
  // 1. Register API Routes IMMEDIATELY
  // These will be available as soon as the server starts listening
  
  // Health check (Requested)
  app.get('/api/health', (req, res) => {
    res.json({ 
      status: 'ok', 
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'connecting',
      tip: (app as any).dbErrorTip
    });
  });

  // Fast ping
  app.get('/api/health/ping', (req, res) => {
    res.json({ status: 'pong' });
  });

  // Auth Routes
  app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    const requestId = Math.random().toString(36).substring(7);
    console.log(`[${requestId}] 📝 Incoming Registration: ${email}`);
    console.log(`[${requestId}] 🔍 DB Status: ${mongoose.connection.readyState === 1 ? 'CONNECTED' : 'DISCONNECTED'}`);

    try {
      // 1. Basic Input Validation
      if (!name || !email || !password) {
        console.warn(`[${requestId}] ⚠️ Validation failed: Missing fields`);
        return res.status(400).json({ success: false, message: 'All fields (name, email, password) are required.' });
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        console.warn(`[${requestId}] ⚠️ Validation failed: Invalid email format`);
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
      }

      if (password.length < 6) {
        console.warn(`[${requestId}] ⚠️ Validation failed: Password too short`);
        return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });
      }

      // 2. Primary Path: MongoDB
      if (mongoose.connection.readyState === 1) {
        console.log(`[${requestId}] ⏳ Attempting DB registration...`);
        try {
          // Use a race to implement a timeout for the DB operation
          const existingUser = await Promise.race([
            User.findOne({ email }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Database timeout')), 2500))
          ]) as any;

          if (existingUser) {
            console.warn(`[${requestId}] ⚠️ DB Conflict: Email already exists`);
            return res.status(400).json({ success: false, message: 'Email is already registered.' });
          }

          const hashedPassword = await bcrypt.hash(password, 10);
          const newUser = new User({
            name,
            email,
            password: hashedPassword,
            role: 'user'
          });

          await newUser.save();
          console.log(`[${requestId}] ✅ User registered in MongoDB: ${email}`);
          return res.status(201).json({ 
            success: true, 
            message: 'User registered successfully in database.' 
          });
        } catch (dbErr: any) {
          console.error(`[${requestId}] ❌ MongoDB registration error:`, {
            message: dbErr.message,
            stack: dbErr.stack,
            code: dbErr.code
          });
          // Fall through to offline mode if DB fails or times out
        }
      }

      // 3. Fallback Path: In-Memory (Offline Mode)
      console.warn(`[${requestId}] ⚠️ Falling back to Offline Mode for registration: ${email}`);
      const existingTempUser = tempUsers.find(u => u.email === email);
      if (existingTempUser) {
        console.warn(`[${requestId}] ⚠️ Memory Conflict: Email already exists`);
        return res.status(400).json({ success: false, message: 'Email is already registered (Offline Mode).' });
      }

      const offlineUser = {
        id: `offline_${Date.now()}`,
        name,
        email,
        password, // Stored as-is in memory for simplicity in offline mode
        role: 'user',
        createdAt: new Date()
      };

      tempUsers.push(offlineUser);
      console.log(`[${requestId}] ✅ User registered in memory: ${email}`);
      
      return res.status(201).json({ 
        success: true, 
        message: 'User registered successfully (Running in Offline Mode).',
        isOffline: true
      });

    } catch (error: any) {
      console.error(`[${requestId}] 💥 Critical registration error:`, {
        message: error.message,
        stack: error.stack,
        details: error
      });
      res.status(500).json({ 
        success: false, 
        message: 'An unexpected server error occurred during registration.' 
      });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const requestId = Math.random().toString(36).substring(7);
    console.log(`[${requestId}] 🔑 Incoming Login: ${email}`);
    console.log(`[${requestId}] 🔍 DB Status: ${mongoose.connection.readyState === 1 ? 'CONNECTED' : 'DISCONNECTED'}`);

    try {
      // 1. Basic Input Validation
      if (!email || !password) {
        console.warn(`[${requestId}] ⚠️ Validation failed: Missing credentials`);
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
      }

      // 2. Primary Path: MongoDB
      if (mongoose.connection.readyState === 1) {
        console.log(`[${requestId}] ⏳ Attempting DB login...`);
        try {
          // Use a race to implement a timeout for the DB operation
          const user = await Promise.race([
            User.findOne({ email }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Database timeout')), 2500))
          ]) as any;

          if (user) {
            console.log(`[${requestId}] 👤 User found in DB, verifying password...`);
            if (await bcrypt.compare(password, user.password)) {
              const token = jwt.sign({ userId: user._id }, FINAL_JWT_SECRET, { expiresIn: '24h' });
              console.log(`[${requestId}] ✅ User logged in from MongoDB: ${email}`);
              return res.json({
                success: true,
                token,
                user: {
                  uid: user._id,
                  email: user.email,
                  displayName: user.name,
                  role: user.role
                }
              });
            } else {
              console.warn(`[${requestId}] ⚠️ Password mismatch for DB user`);
            }
          } else {
            console.warn(`[${requestId}] ⚠️ User not found in DB`);
          }
        } catch (dbErr: any) {
          console.error(`[${requestId}] ❌ MongoDB login error:`, {
            message: dbErr.message,
            stack: dbErr.stack,
            code: dbErr.code
          });
          // Fall through to offline mode if DB fails or times out
        }
      }

      // 3. Fallback Path: In-Memory (Offline Mode)
      console.warn(`[${requestId}] ⚠️ Checking Offline Mode for login: ${email}`);
      const tempUser = tempUsers.find(u => u.email === email);
      
      // Note: In offline mode we store password as-is for simplicity
      if (tempUser && tempUser.password === password) {
        console.log(`[${requestId}] ✅ User logged in from memory: ${email}`);
        return res.json({
          success: true,
          token: "offline-dummy-token",
          user: {
            uid: tempUser.id,
            email: tempUser.email,
            displayName: tempUser.name,
            role: 'user',
            isOffline: true
          }
        });
      }

      // 4. Invalid Credentials
      console.warn(`[${requestId}] ⚠️ Login failed: Invalid credentials`);
      res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password. Please check your credentials and try again.' 
      });

    } catch (error: any) {
      console.error(`[${requestId}] 💥 Critical login error:`, {
        message: error.message,
        stack: error.stack,
        details: error
      });
      res.status(500).json({ 
        success: false, 
        message: 'An unexpected server error occurred during login.' 
      });
    }
  });

  app.get('/api/auth/me', [authenticateToken, checkDbConnection], async (req: any, res) => {
    try {
      const user = await User.findById(req.user.userId).select('-password');
      if (!user) return res.status(404).json({ message: 'User not found' });
      res.json({ uid: user._id, email: user.email, displayName: user.name, role: user.role });
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  });

  // 2. Start Listening IMMEDIATELY (Non-blocking)
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 SERVER STARTED SUCCESSFULLY`);
    console.log(`📡 Port: ${PORT}`);
    console.log(`🔗 Health: http://localhost:${PORT}/api/health\n`);
  });

  // 3. Background Tasks (Non-blocking)
  
  // Initialize Vite
  const initVite = async () => {
    if (process.env.NODE_ENV !== 'production') {
      console.log('📦 Starting Vite initialization...');
      try {
        const vite = await createViteServer({
          server: { middlewareMode: true },
          appType: 'spa',
        });
        app.use(vite.middlewares);
        console.log('✅ Vite middleware ready.');
      } catch (err) {
        console.error('❌ Vite init failed:', err);
      }
    } else {
      const distPath = path.join(process.cwd(), 'dist');
      app.use(express.static(distPath));
      app.get('*', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
    }
  };
  initVite();

  // Initialize MongoDB
  const initMongo = async () => {
    if (!MONGODB_URI) {
      console.warn('⚠️ MongoDB initialization skipped: MONGODB_URI is not defined.');
      (app as any).dbErrorTip = 'MONGODB_URI is missing. Please add it in Settings > Environment Variables.';
      return;
    }
    
    console.log('⏳ Connecting to MongoDB...');
    try {
      await mongoose.connect(MONGODB_URI, {
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });
      console.log('✅ MongoDB connected successfully');
    } catch (err: any) {
      console.error('❌ MongoDB connection failed:', err.message);
      if (err.message.includes('SSL alert number 80') || err.message.includes('Could not connect')) {
        (app as any).dbErrorTip = 'IP Whitelist issue detected. Add 0.0.0.0/0 in MongoDB Atlas.';
      }
    }
  };
  initMongo();

  // API 404 Handler (Must be after API routes but before Vite/Static fallback if possible)
  // Actually, Vite middleware handles SPA fallback, so we only 404 on /api
  app.use('/api', (req, res) => {
    res.status(404).json({ message: `API route not found: ${req.method} ${req.url}` });
  });
}

console.log('📡 Calling startServer()...');
startServer().catch(err => {
  console.error('💥 CRITICAL: startServer failed to execute:', err);
  process.exit(1);
});
