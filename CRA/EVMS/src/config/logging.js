// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Logging configuration

const config = require('./index');
const path = require('path');

class LoggingConfig {
  constructor() {
    this.loggingConfig = null;
  }

  getLoggingConfig() {
    if (!this.loggingConfig) {
      const environment = process.env.NODE_ENV || 'development';
      const logLevel = config.get('logging.level', environment === 'production' ? 'info' : 'debug');
      
      this.loggingConfig = {
        level: logLevel,
        format: config.get('logging.format', 'json'),
        timestamp: config.get('logging.timestamp', true),
        colorize: config.get('logging.colorize', environment !== 'production'),
        
        // Console logging
        console: {
          enabled: config.get('logging.console.enabled', true),
          level: config.get('logging.console.level', logLevel),
          format: config.get('logging.console.format', environment === 'production' ? 'json' : 'simple'),
        },
        
        // File logging
        file: {
          enabled: config.get('logging.file.enabled', true),
          level: config.get('logging.file.level', logLevel),
          filename: config.get('logging.file.filename', 'evms.log'),
          dirname: config.get('logging.file.dirname', path.join(process.cwd(), 'data', 'logs')),
          maxsize: config.get('logging.file.maxsize', 10 * 1024 * 1024), // 10MB
          maxFiles: config.get('logging.file.maxFiles', 5),
          datePattern: config.get('logging.file.datePattern', 'YYYY-MM-DD'),
          zippedArchive: config.get('logging.file.zippedArchive', true),
        },
        
        // Error file logging
        errorFile: {
          enabled: config.get('logging.errorFile.enabled', true),
          level: 'error',
          filename: config.get('logging.errorFile.filename', 'error.log'),
          dirname: config.get('logging.errorFile.dirname', path.join(process.cwd(), 'data', 'logs')),
          maxsize: config.get('logging.errorFile.maxsize', 10 * 1024 * 1024), // 10MB
          maxFiles: config.get('logging.errorFile.maxFiles', 10),
          datePattern: config.get('logging.errorFile.datePattern', 'YYYY-MM-DD'),
          zippedArchive: config.get('logging.errorFile.zippedArchive', true),
        },
        
        // Audit logging
        audit: {
          enabled: config.get('logging.audit.enabled', true),
          level: config.get('logging.audit.level', 'info'),
          filename: config.get('logging.audit.filename', 'audit.log'),
          dirname: config.get('logging.audit.dirname', path.join(process.cwd(), 'data', 'logs')),
          maxsize: config.get('logging.audit.maxsize', 50 * 1024 * 1024), // 50MB
          maxFiles: config.get('logging.audit.maxFiles', 20),
          datePattern: config.get('logging.audit.datePattern', 'YYYY-MM-DD'),
          zippedArchive: config.get('logging.audit.zippedArchive', true),
        },
        
        // Security logging
        security: {
          enabled: config.get('logging.security.enabled', true),
          level: config.get('logging.security.level', 'warn'),
          filename: config.get('logging.security.filename', 'security.log'),
          dirname: config.get('logging.security.dirname', path.join(process.cwd(), 'data', 'logs')),
          maxsize: config.get('logging.security.maxsize', 50 * 1024 * 1024), // 50MB
          maxFiles: config.get('logging.security.maxFiles', 30),
          datePattern: config.get('logging.security.datePattern', 'YYYY-MM-DD'),
          zippedArchive: config.get('logging.security.zippedArchive', true),
        },
        
        // Performance logging
        performance: {
          enabled: config.get('logging.performance.enabled', environment === 'production'),
          level: config.get('logging.performance.level', 'info'),
          filename: config.get('logging.performance.filename', 'performance.log'),
          dirname: config.get('logging.performance.dirname', path.join(process.cwd(), 'data', 'logs')),
          maxsize: config.get('logging.performance.maxsize', 25 * 1024 * 1024), // 25MB
          maxFiles: config.get('logging.performance.maxFiles', 10),
          datePattern: config.get('logging.performance.datePattern', 'YYYY-MM-DD'),
          zippedArchive: config.get('logging.performance.zippedArchive', true),
        },
        
        // External logging services
        external: {
          // Elasticsearch/ELK Stack
          elasticsearch: {
            enabled: config.get('logging.external.elasticsearch.enabled', false),
            level: config.get('logging.external.elasticsearch.level', 'info'),
            index: config.get('logging.external.elasticsearch.index', 'evms-logs'),
            host: config.get('logging.external.elasticsearch.host', 'localhost:9200'),
            auth: {
              username: config.get('logging.external.elasticsearch.username'),
              password: config.get('logging.external.elasticsearch.password'),
            },
          },
          
          // Syslog
          syslog: {
            enabled: config.get('logging.external.syslog.enabled', false),
            level: config.get('logging.external.syslog.level', 'info'),
            host: config.get('logging.external.syslog.host', 'localhost'),
            port: config.get('logging.external.syslog.port', 514),
            protocol: config.get('logging.external.syslog.protocol', 'udp4'),
            facility: config.get('logging.external.syslog.facility', 'local0'),
            app_name: config.get('logging.external.syslog.app_name', 'evms'),
          },
          
          // Splunk
          splunk: {
            enabled: config.get('logging.external.splunk.enabled', false),
            level: config.get('logging.external.splunk.level', 'info'),
            url: config.get('logging.external.splunk.url'),
            token: config.get('logging.external.splunk.token'),
            source: config.get('logging.external.splunk.source', 'evms'),
            sourcetype: config.get('logging.external.splunk.sourcetype', 'evms:application'),
            index: config.get('logging.external.splunk.index', 'main'),
          },
        },
        
        // Structured logging fields
        defaultMeta: {
          service: config.get('logging.defaultMeta.service', 'evms'),
          version: config.get('logging.defaultMeta.version', '1.0.0'),
          environment: environment,
          hostname: require('os').hostname(),
          pid: process.pid,
        },
        
        // Log filtering and sampling
        filters: {
          // Exclude sensitive fields from logs
          excludeFields: config.get('logging.filters.excludeFields', [
            'password',
            'token',
            'secret',
            'key',
            'authorization',
            'cookie',
          ]),
          
          // Sample high-volume logs
          sampling: {
            enabled: config.get('logging.filters.sampling.enabled', false),
            rate: config.get('logging.filters.sampling.rate', 0.1), // 10%
            levels: config.get('logging.filters.sampling.levels', ['debug', 'trace']),
          },
        },
        
        // Log correlation
        correlation: {
          enabled: config.get('logging.correlation.enabled', true),
          traceIdHeader: config.get('logging.correlation.traceIdHeader', 'x-trace-id'),
          requestIdHeader: config.get('logging.correlation.requestIdHeader', 'x-request-id'),
        },
      };
    }
    return this.loggingConfig;
  }

  getLogLevels() {
    return {
      error: 0,
      warn: 1,
      info: 2,
      http: 3,
      verbose: 4,
      debug: 5,
      silly: 6,
    };
  }

  getAuditEvents() {
    return {
      // Authentication events
      USER_LOGIN: 'user.login',
      USER_LOGOUT: 'user.logout',
      USER_LOGIN_FAILED: 'user.login.failed',
      
      // User management events
      USER_CREATED: 'user.created',
      USER_UPDATED: 'user.updated',
      USER_DELETED: 'user.deleted',
      USER_PASSWORD_CHANGED: 'user.password.changed',
      
      // System events
      SYSTEM_STARTUP: 'system.startup',
      SYSTEM_SHUTDOWN: 'system.shutdown',
      CONFIG_CHANGED: 'config.changed',
      
      // Scan events
      SCAN_STARTED: 'scan.started',
      SCAN_COMPLETED: 'scan.completed',
      SCAN_FAILED: 'scan.failed',
      
      // Security events
      UNAUTHORIZED_ACCESS: 'security.unauthorized_access',
      PERMISSION_DENIED: 'security.permission_denied',
      SUSPICIOUS_ACTIVITY: 'security.suspicious_activity',
      
      // Data events
      DATA_EXPORT: 'data.export',
      DATA_IMPORT: 'data.import',
      DATA_DELETION: 'data.deletion',
    };
  }

  getSecurityEvents() {
    return {
      // Authentication failures
      BRUTE_FORCE_ATTEMPT: 'security.brute_force_attempt',
      INVALID_TOKEN: 'security.invalid_token',
      TOKEN_EXPIRED: 'security.token_expired',
      
      // Authorization failures
      PRIVILEGE_ESCALATION: 'security.privilege_escalation',
      UNAUTHORIZED_API_ACCESS: 'security.unauthorized_api_access',
      
      // Input validation
      MALICIOUS_INPUT: 'security.malicious_input',
      SQL_INJECTION_ATTEMPT: 'security.sql_injection_attempt',
      XSS_ATTEMPT: 'security.xss_attempt',
      
      // System security
      CONFIGURATION_TAMPERING: 'security.configuration_tampering',
      SUSPICIOUS_FILE_ACCESS: 'security.suspicious_file_access',
      UNUSUAL_NETWORK_ACTIVITY: 'security.unusual_network_activity',
    };
  }

  validateConfig() {
    const loggingConfig = this.getLoggingConfig();
    
    if (!loggingConfig.level) {
      throw new Error('Logging level is required');
    }
    
    const validLevels = Object.keys(this.getLogLevels());
    if (!validLevels.includes(loggingConfig.level)) {
      throw new Error(`Invalid logging level: ${loggingConfig.level}. Valid levels: ${validLevels.join(', ')}`);
    }
    
    return true;
  }
}

module.exports = new LoggingConfig();