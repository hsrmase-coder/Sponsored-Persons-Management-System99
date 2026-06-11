require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const path = require('path');
const { initDB } = require('./config/db');
const { apiLimiter, securityHeaders, sanitizeMiddleware, validateSecurityConfig } = require('./middleware/security');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const logger = require('./config/logger');
const { initScheduler } = require('./config/scheduler');

const authRoutes = require('./routes/auth');
const sponsoredRoutes = require('./routes/sponsored');
const paymentRoutes = require('./routes/payments');
const reportRoutes = require('./routes/reports');
const documentRoutes = require('./routes/documents');
const backupRoutes = require('./routes/backup');
const activityLogRoutes = require('./routes/activityLog');
const settingsRoutes = require('./routes/settings');
const notificationRoutes = require('./routes/notifications');

const app = express();

// التحقق من إعدادات الأمان
validateSecurityConfig();

// Compression للأداء
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

// Request Timeout
app.use((req, res, next) => {
  req.setTimeout(30000); // 30 ثانية
  res.setTimeout(30000);
  next();
});

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' } // السماح بتحميل الملفات من ports مختلفة
}));
app.use(securityHeaders);

// CORS Configuration
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);

    // السماح لجميع نطاقات Vercel
    if (origin.endsWith('.vercel.app')) return callback(null, true);

    const allowedOrigins = process.env.NODE_ENV === 'production'
      ? [process.env.CORS_ORIGIN, process.env.CORS_ORIGIN_2].filter(Boolean)
      : [
          'http://localhost:3000',
          'http://127.0.0.1:3000',
          /^http:\/\/192\.168\.\d{1,3}\.\d{1,3}:3000$/
        ];

    const isAllowed = allowedOrigins.some(allowed => {
      if (allowed instanceof RegExp) return allowed.test(origin);
      return allowed === origin;
    });

    if (isAllowed) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(sanitizeMiddleware);

// Request Logging
app.use((req, res, next) => {
  logger.logRequest(req);
  next();
});

// Rate Limiting
app.use('/api', apiLimiter);

// Static files
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/sponsored', sponsoredRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/backup', backupRoutes);
app.use('/api/activity', activityLogRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/notifications', notificationRoutes);

// Health check - محسّن
app.get('/api/health', async (req, res) => {
  const { getDB } = require('./config/db');
  const db = getDB();
  
  const health = {
    status: 'ok',
    message: 'نظام إدارة المكفولين يعمل',
    database: 'SQLite',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    dbConnected: !!db
  };
  
  // فحص الاتصال بقاعدة البيانات
  try {
    if (db) {
      const { dbGet } = require('./config/db');
      await dbGet('SELECT 1');
      health.dbStatus = 'connected';
    } else {
      health.dbStatus = 'disconnected';
      health.status = 'degraded';
    }
  } catch (err) {
    health.dbStatus = 'error';
    health.status = 'unhealthy';
  }
  
  const statusCode = health.status === 'ok' ? 200 : health.status === 'degraded' ? 200 : 503;
  res.status(statusCode).json(health);
});

// 404 Handler
app.use(notFoundHandler);

// Error Handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
const HOST = '0.0.0.0';

const { createServer } = require('./config/https');

// Graceful Shutdown
let server;
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully...`);
  
  if (server) {
    server.close(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });
    
    // إجبار الإغلاق بعد 10 ثواني
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// معالجة الأخطاء غير المتوقعة
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

initDB().then(async () => {
  // إنشاء جدول الإشعارات
  const Notification = require('./models/Notification');
  await Notification.createTable();
  
  // تشغيل جدولة النسخ الاحتياطي
  initScheduler();
  
  server = createServer(app, PORT, HOST);
  server.listen(PORT, HOST, () => {
    const protocol = process.env.SSL_KEY_PATH ? 'https' : 'http';
    logger.info(`Server running on ${protocol}://${HOST}:${PORT}`);
    logger.info('🔒 Security features enabled: Rate Limiting, Helmet, Input Sanitization, Compression');
    logger.info('📅 Auto backup scheduled daily at 2:00 AM');
  });
}).catch(err => {
  logger.error('Failed to initialize database:', err);
  process.exit(1);
});
