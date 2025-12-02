// EVMS (c) Shane D. Shook, 2025 All Rights Reserved
// Centralized logging utility

const winston = require('winston');
const path = require('path');
const fs = require('fs');

class Logger {
  constructor() {
    this.logger = null;
    this.initialized = false;
  }

  initialize(config = null) {
    if (this.initialized) {
      return this.logger;
    }

    // Default configuration if none provided
    const defaultConfig = {
      level: process.env.LOG_LEVEL || 'info',
      format: 'json',
      console: { enabled: true },
      file: { 
        enabled: true, 
        dirname: path.join(process.cwd(), 'data', 'logs'),
        filename: 'evms.log'
      },
      errorFile: { 
        enabled: true, 
        dirname: path.join(process.cwd(), 'data', 'logs'),
        filename: 'error.log'
      }
    };

    const logConfig = config || defaultConfig;

    // Ensure log directory exists
    if (logConfig.file?.enabled || logConfig.errorFile?.enabled) {
      const logDir = logConfig.file?.dirname || path.join(process.cwd(), 'data', 'logs');
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
    }

    // Create winston logger
    const transports = [];

    // Console transport
    if (logConfig.console?.enabled !== false) {
      transports.push(new winston.transports.Console({
        level: logConfig.console?.level || logConfig.level,
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp(),
          winston.format.printf(({ timestamp, level, message, ...meta }) => {
            const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
            return `${timestamp} [${level}]: ${message} ${metaStr}`;
          })
        )
      }));
    }

    // File transport
    if (logConfig.file?.enabled) {
      transports.push(new winston.transports.File({
        level: logConfig.file.level || logConfig.level,
        filename: path.join(logConfig.file.dirname, logConfig.file.filename),
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        ),
        maxsize: logConfig.file.maxsize || 10 * 1024 * 1024, // 10MB
        maxFiles: logConfig.file.maxFiles || 5,
      }));
    }

    // Error file transport
    if (logConfig.errorFile?.enabled) {
      transports.push(new winston.transports.File({
        level: 'error',
        filename: path.join(logConfig.errorFile.dirname, logConfig.errorFile.filename),
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        ),
        maxsize: logConfig.errorFile.maxsize || 10 * 1024 * 1024, // 10MB
        maxFiles: logConfig.errorFile.maxFiles || 10,
      }));
    }

    this.logger = winston.createLogger({
      level: logConfig.level,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: {
        service: 'evms',
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        hostname: require('os').hostname(),
        pid: process.pid,
      },
      transports,
    });

    this.initialized = true;
    return this.logger;
  }

  getLogger() {
    if (!this.initialized) {
      this.initialize();
    }
    return this.logger;
  }

  // Convenience methods
  error(message, meta = {}) {
    this.getLogger().error(message, meta);
  }

  warn(message, meta = {}) {
    this.getLogger().warn(message, meta);
  }

  info(message, meta = {}) {
    this.getLogger().info(message, meta);
  }

  debug(message, meta = {}) {
    this.getLogger().debug(message, meta);
  }

  verbose(message, meta = {}) {
    this.getLogger().verbose(message, meta);
  }

  // Audit logging
  audit(event, details = {}) {
    this.getLogger().info('AUDIT', {
      event,
      details,
      timestamp: new Date().toISOString(),
      type: 'audit',
    });
  }

  // Security logging
  security(event, details = {}) {
    this.getLogger().warn('SECURITY', {
      event,
      details,
      timestamp: new Date().toISOString(),
      type: 'security',
    });
  }

  // Performance logging
  performance(operation, duration, details = {}) {
    this.getLogger().info('PERFORMANCE', {
      operation,
      duration,
      details,
      timestamp: new Date().toISOString(),
      type: 'performance',
    });
  }

  // Request logging middleware
  requestLogger() {
    return (req, res, next) => {
      const start = Date.now();
      
      // Generate request ID if not present
      req.id = req.headers['x-request-id'] || require('crypto').randomUUID();
      
      // Log request
      this.info('HTTP Request', {
        requestId: req.id,
        method: req.method,
        url: req.url,
        userAgent: req.headers['user-agent'],
        ip: req.ip || req.connection.remoteAddress,
        timestamp: new Date().toISOString(),
      });

      // Override res.end to log response
      const originalEnd = res.end;
      res.end = function(...args) {
        const duration = Date.now() - start;
        
        logger.info('HTTP Response', {
          requestId: req.id,
          method: req.method,
          url: req.url,
          statusCode: res.statusCode,
          duration,
          timestamp: new Date().toISOString(),
        });

        originalEnd.apply(res, args);
      };

      next();
    };
  }

  // Error logging middleware
  errorLogger() {
    return (err, req, res, next) => {
      this.error('HTTP Error', {
        requestId: req.id,
        method: req.method,
        url: req.url,
        error: {
          message: err.message,
          stack: err.stack,
          name: err.name,
        },
        statusCode: err.statusCode || 500,
        timestamp: new Date().toISOString(),
      });

      next(err);
    };
  }

  // Create child logger with additional context
  child(meta = {}) {
    return this.getLogger().child(meta);
  }
}

// Create singleton instance
const logger = new Logger();

module.exports = logger;