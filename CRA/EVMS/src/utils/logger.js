// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Centralized logging utility

const winston = require('winston');
const path = require('path');
const fs = require('fs');
const DailyRotateFile = require('winston-daily-rotate-file');

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
        filename: 'evms-%DATE%.log'
      },
      errorFile: { 
        enabled: true, 
        dirname: path.join(process.cwd(), 'data', 'logs'),
        filename: 'error-%DATE%.log'
      },
      auditFile: {
        enabled: true,
        dirname: path.join(process.cwd(), 'data', 'logs'),
        filename: 'audit-%DATE%.log'
      }
    };

    const logConfig = config || defaultConfig;

    // Ensure log directory exists
    if (logConfig.file?.enabled || logConfig.errorFile?.enabled || logConfig.auditFile?.enabled) {
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
          winston.format.printf(({ timestamp, level, message, service, requestId, ...meta }) => {
            const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
            const reqId = requestId ? ` [${requestId}]` : '';
            const svc = service ? ` [${service}]` : '';
            return `${timestamp}${svc}${reqId} [${level}]: ${message}${metaStr}`;
          })
        )
      }));
    }

    // File transport with rotation
    if (logConfig.file?.enabled) {
      transports.push(new DailyRotateFile({
        level: logConfig.file.level || logConfig.level,
        filename: path.join(logConfig.file.dirname, logConfig.file.filename),
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '14d',
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        )
      }));
    }

    // Error file transport with rotation
    if (logConfig.errorFile?.enabled) {
      transports.push(new DailyRotateFile({
        level: 'error',
        filename: path.join(logConfig.errorFile.dirname, logConfig.errorFile.filename),
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '30d',
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        )
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

    // Create separate audit logger
    this.auditLogger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new DailyRotateFile({
          filename: path.join(logConfig.auditFile?.dirname || logConfig.file.dirname, 
                            logConfig.auditFile?.filename || 'audit-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          zippedArchive: true,
          maxSize: '50m',
          maxFiles: '90d'
        })
      ]
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
  audit(event, details = {}, userId = null) {
    const auditEntry = {
      event,
      details,
      userId,
      timestamp: new Date().toISOString(),
      type: 'audit',
      sessionId: details.sessionId || null,
      ipAddress: details.ipAddress || null,
      userAgent: details.userAgent || null
    };
    
    this.auditLogger.info('AUDIT_EVENT', auditEntry);
    this.getLogger().info('AUDIT', auditEntry);
  }

  // Security logging
  security(event, details = {}, severity = 'medium') {
    const securityEntry = {
      event,
      details,
      severity,
      timestamp: new Date().toISOString(),
      type: 'security',
      source: details.source || 'unknown',
      threat_level: details.threat_level || severity
    };
    
    this.getLogger().warn('SECURITY', securityEntry);
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
    const self = this;
    return (req, res, next) => {
      const start = Date.now();
      
      // Generate request ID if not present
      req.id = req.headers['x-request-id'] || require('crypto').randomUUID();
      
      // Add request ID to response headers
      res.setHeader('X-Request-ID', req.id);
      
      // Log request
      self.info('HTTP Request', {
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
        
        self.info('HTTP Response', {
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
    const self = this;
    return (err, req, res, next) => {
      self.error('HTTP Error', {
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

  // Structured logging for different event types
  scanEvent(scanId, event, details = {}) {
    this.info('SCAN_EVENT', {
      scanId,
      event,
      details,
      timestamp: new Date().toISOString(),
      type: 'scan'
    });
  }

  vulnerabilityEvent(vulnId, event, details = {}) {
    this.info('VULNERABILITY_EVENT', {
      vulnId,
      event,
      details,
      timestamp: new Date().toISOString(),
      type: 'vulnerability'
    });
  }

  agentEvent(agentId, event, details = {}) {
    this.info('AGENT_EVENT', {
      agentId,
      event,
      details,
      timestamp: new Date().toISOString(),
      type: 'agent'
    });
  }

  graphrlEvent(event, details = {}) {
    this.info('GRAPHRL_EVENT', {
      event,
      details,
      timestamp: new Date().toISOString(),
      type: 'graphrl'
    });
  }
}

// Create singleton instance
const logger = new Logger();

module.exports = logger;