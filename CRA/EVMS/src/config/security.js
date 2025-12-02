// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Security configuration

const config = require('./index');
const crypto = require('crypto');

class SecurityConfig {
  constructor() {
    this.securityConfig = null;
  }

  getSecurityConfig() {
    if (!this.securityConfig) {
      this.securityConfig = {
        jwtSecret: config.get('security.jwtSecret') || this.generateSecret(),
        jwtExpiresIn: config.get('security.jwtExpiresIn', '24h'),
        jwtIssuer: config.get('security.jwtIssuer', 'evms'),
        jwtAudience: config.get('security.jwtAudience', 'evms-users'),
        
        // Password policy
        passwordMinLength: config.get('security.password.minLength', 12),
        passwordRequireUppercase: config.get('security.password.requireUppercase', true),
        passwordRequireLowercase: config.get('security.password.requireLowercase', true),
        passwordRequireNumbers: config.get('security.password.requireNumbers', true),
        passwordRequireSymbols: config.get('security.password.requireSymbols', true),
        passwordMaxAge: config.get('security.password.maxAge', 90), // days
        
        // Session configuration
        sessionSecret: config.get('security.sessionSecret') || this.generateSecret(),
        sessionMaxAge: config.get('security.sessionMaxAge', 24 * 60 * 60 * 1000), // 24 hours
        sessionSecure: config.get('security.sessionSecure', process.env.NODE_ENV === 'production'),
        sessionHttpOnly: config.get('security.sessionHttpOnly', true),
        sessionSameSite: config.get('security.sessionSameSite', 'strict'),
        
        // Rate limiting
        rateLimitWindowMs: config.get('security.rateLimit.windowMs', 15 * 60 * 1000), // 15 minutes
        rateLimitMax: config.get('security.rateLimit.max', 100),
        rateLimitSkipSuccessfulRequests: config.get('security.rateLimit.skipSuccessfulRequests', false),
        
        // CORS configuration
        corsOrigin: config.get('security.cors.origin', false),
        corsCredentials: config.get('security.cors.credentials', true),
        corsMethods: config.get('security.cors.methods', ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']),
        corsAllowedHeaders: config.get('security.cors.allowedHeaders', [
          'Origin',
          'X-Requested-With',
          'Content-Type',
          'Accept',
          'Authorization',
        ]),
        
        // Encryption
        encryptionAlgorithm: config.get('security.encryption.algorithm', 'aes-256-gcm'),
        encryptionKey: config.get('security.encryption.key') || this.generateEncryptionKey(),
        
        // API Security
        apiKeyHeader: config.get('security.api.keyHeader', 'X-API-Key'),
        apiKeyLength: config.get('security.api.keyLength', 32),
        
        // TLS Configuration
        tlsEnabled: config.get('security.tls.enabled', process.env.NODE_ENV === 'production'),
        tlsCertPath: config.get('security.tls.certPath'),
        tlsKeyPath: config.get('security.tls.keyPath'),
        tlsCaPath: config.get('security.tls.caPath'),
        
        // Security Headers
        securityHeaders: {
          contentSecurityPolicy: config.get('security.headers.csp', {
            directives: {
              defaultSrc: ["'self'"],
              styleSrc: ["'self'", "'unsafe-inline'"],
              scriptSrc: ["'self'"],
              imgSrc: ["'self'", 'data:', 'https:'],
              connectSrc: ["'self'"],
              fontSrc: ["'self'"],
              objectSrc: ["'none'"],
              mediaSrc: ["'self'"],
              frameSrc: ["'none'"],
            },
          }),
          hsts: config.get('security.headers.hsts', {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
          }),
          noSniff: config.get('security.headers.noSniff', true),
          frameguard: config.get('security.headers.frameguard', { action: 'deny' }),
          xssFilter: config.get('security.headers.xssFilter', true),
        },
      };
    }
    return this.securityConfig;
  }

  generateSecret() {
    return crypto.randomBytes(64).toString('hex');
  }

  generateEncryptionKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  generateApiKey() {
    const config = this.getSecurityConfig();
    return crypto.randomBytes(config.apiKeyLength).toString('hex');
  }

  hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return `${salt}:${hash}`;
  }

  verifyPassword(password, hashedPassword) {
    const [salt, hash] = hashedPassword.split(':');
    const verifyHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return hash === verifyHash;
  }

  encrypt(text) {
    const config = this.getSecurityConfig();
    const algorithm = config.encryptionAlgorithm;
    const key = Buffer.from(config.encryptionKey, 'hex');
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipher(algorithm, key);
    cipher.setAAD(Buffer.from('evms', 'utf8'));
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  }

  decrypt(encryptedData) {
    const config = this.getSecurityConfig();
    const algorithm = config.encryptionAlgorithm;
    const key = Buffer.from(config.encryptionKey, 'hex');
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    const decipher = crypto.createDecipher(algorithm, key);
    decipher.setAAD(Buffer.from('evms', 'utf8'));
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  validatePasswordPolicy(password) {
    const config = this.getSecurityConfig();
    const errors = [];
    
    if (password.length < config.passwordMinLength) {
      errors.push(`Password must be at least ${config.passwordMinLength} characters long`);
    }
    
    if (config.passwordRequireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (config.passwordRequireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (config.passwordRequireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (config.passwordRequireSymbols && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }

  getRoles() {
    return {
      SUPER_ADMIN: 'super_admin',
      ADMIN: 'admin',
      SECURITY_ANALYST: 'security_analyst',
      OPERATOR: 'operator',
      VIEWER: 'viewer',
    };
  }

  getPermissions() {
    return {
      // System permissions
      SYSTEM_ADMIN: 'system:admin',
      SYSTEM_CONFIG: 'system:config',
      
      // User management
      USER_CREATE: 'user:create',
      USER_READ: 'user:read',
      USER_UPDATE: 'user:update',
      USER_DELETE: 'user:delete',
      
      // Scan management
      SCAN_CREATE: 'scan:create',
      SCAN_READ: 'scan:read',
      SCAN_UPDATE: 'scan:update',
      SCAN_DELETE: 'scan:delete',
      SCAN_EXECUTE: 'scan:execute',
      
      // Vulnerability management
      VULN_READ: 'vulnerability:read',
      VULN_UPDATE: 'vulnerability:update',
      VULN_RESOLVE: 'vulnerability:resolve',
      
      // Risk management
      RISK_READ: 'risk:read',
      RISK_UPDATE: 'risk:update',
      RISK_APPROVE: 'risk:approve',
      
      // GraphRL management
      GRAPHRL_READ: 'graphrl:read',
      GRAPHRL_TRAIN: 'graphrl:train',
      GRAPHRL_DEPLOY: 'graphrl:deploy',
      
      // Reporting
      REPORT_READ: 'report:read',
      REPORT_CREATE: 'report:create',
      REPORT_EXPORT: 'report:export',
    };
  }

  getRolePermissions() {
    const permissions = this.getPermissions();
    const roles = this.getRoles();
    
    return {
      [roles.SUPER_ADMIN]: Object.values(permissions),
      [roles.ADMIN]: [
        permissions.SYSTEM_CONFIG,
        permissions.USER_CREATE,
        permissions.USER_READ,
        permissions.USER_UPDATE,
        permissions.USER_DELETE,
        permissions.SCAN_CREATE,
        permissions.SCAN_READ,
        permissions.SCAN_UPDATE,
        permissions.SCAN_DELETE,
        permissions.SCAN_EXECUTE,
        permissions.VULN_READ,
        permissions.VULN_UPDATE,
        permissions.VULN_RESOLVE,
        permissions.RISK_READ,
        permissions.RISK_UPDATE,
        permissions.RISK_APPROVE,
        permissions.GRAPHRL_READ,
        permissions.GRAPHRL_TRAIN,
        permissions.GRAPHRL_DEPLOY,
        permissions.REPORT_READ,
        permissions.REPORT_CREATE,
        permissions.REPORT_EXPORT,
      ],
      [roles.SECURITY_ANALYST]: [
        permissions.USER_READ,
        permissions.SCAN_CREATE,
        permissions.SCAN_READ,
        permissions.SCAN_UPDATE,
        permissions.SCAN_EXECUTE,
        permissions.VULN_READ,
        permissions.VULN_UPDATE,
        permissions.VULN_RESOLVE,
        permissions.RISK_READ,
        permissions.RISK_UPDATE,
        permissions.GRAPHRL_READ,
        permissions.REPORT_READ,
        permissions.REPORT_CREATE,
        permissions.REPORT_EXPORT,
      ],
      [roles.OPERATOR]: [
        permissions.SCAN_READ,
        permissions.SCAN_EXECUTE,
        permissions.VULN_READ,
        permissions.RISK_READ,
        permissions.REPORT_READ,
      ],
      [roles.VIEWER]: [
        permissions.SCAN_READ,
        permissions.VULN_READ,
        permissions.RISK_READ,
        permissions.REPORT_READ,
      ],
    };
  }

  validateConfig() {
    const securityConfig = this.getSecurityConfig();
    
    if (!securityConfig.jwtSecret) {
      throw new Error('JWT secret is required');
    }
    
    if (!securityConfig.sessionSecret) {
      throw new Error('Session secret is required');
    }
    
    if (!securityConfig.encryptionKey) {
      throw new Error('Encryption key is required');
    }
    
    return true;
  }
}

module.exports = new SecurityConfig();