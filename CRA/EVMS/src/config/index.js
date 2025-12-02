// EVMS (c) Shane D. Shook, 2025 All Rights Reserved
// Configuration management

const path = require('path');
const fs = require('fs').promises;
const logger = require('../utils/logger');

class ConfigManager {
  constructor() {
    this.config = {};
    this.environment = process.env.NODE_ENV || 'development';
    this.configPath = path.join(__dirname, '../../config');
  }

  async initialize() {
    try {
      // Load default configuration
      await this.loadConfig('default.json');
      
      // Load environment-specific configuration
      await this.loadConfig(`${this.environment}.json`);
      
      // Override with environment variables
      this.loadEnvironmentVariables();
      
      logger.info(`Configuration loaded for environment: ${this.environment}`);
      
    } catch (error) {
      logger.error('Failed to initialize configuration:', error);
      throw error;
    }
  }

  async loadConfig(filename) {
    try {
      const configFile = path.join(this.configPath, filename);
      const configData = await fs.readFile(configFile, 'utf8');
      const config = JSON.parse(configData);
      
      // Deep merge configuration
      this.config = this.deepMerge(this.config, config);
      
    } catch (error) {
      if (error.code !== 'ENOENT') {
        logger.warn(`Failed to load config file ${filename}:`, error.message);
      }
    }
  }

  loadEnvironmentVariables() {
    // Database configuration
    if (process.env.NEO4J_URI) {
      this.config.database = this.config.database || {};
      this.config.database.neo4j = this.config.database.neo4j || {};
      this.config.database.neo4j.uri = process.env.NEO4J_URI;
    }
    
    if (process.env.NEO4J_USERNAME) {
      this.config.database = this.config.database || {};
      this.config.database.neo4j = this.config.database.neo4j || {};
      this.config.database.neo4j.username = process.env.NEO4J_USERNAME;
    }
    
    if (process.env.NEO4J_PASSWORD) {
      this.config.database = this.config.database || {};
      this.config.database.neo4j = this.config.database.neo4j || {};
      this.config.database.neo4j.password = process.env.NEO4J_PASSWORD;
    }

    // NATS configuration
    if (process.env.NATS_URL) {
      this.config.messaging = this.config.messaging || {};
      this.config.messaging.nats = this.config.messaging.nats || {};
      this.config.messaging.nats.servers = [process.env.NATS_URL];
    }

    // Service ports
    if (process.env.PORT) {
      this.config.server = this.config.server || {};
      this.config.server.port = parseInt(process.env.PORT, 10);
    }

    // Security settings
    if (process.env.JWT_SECRET) {
      this.config.security = this.config.security || {};
      this.config.security.jwtSecret = process.env.JWT_SECRET;
    }

    // GraphRL configuration
    if (process.env.GRAPHRL_MODEL_PATH) {
      this.config.graphrl = this.config.graphrl || {};
      this.config.graphrl.modelPath = process.env.GRAPHRL_MODEL_PATH;
    }
  }

  deepMerge(target, source) {
    const result = { ...target };
    
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(result[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }
    
    return result;
  }

  get(path, defaultValue = undefined) {
    const keys = path.split('.');
    let current = this.config;
    
    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = current[key];
      } else {
        return defaultValue;
      }
    }
    
    return current;
  }

  set(path, value) {
    const keys = path.split('.');
    let current = this.config;
    
    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!(key in current) || typeof current[key] !== 'object') {
        current[key] = {};
      }
      current = current[key];
    }
    
    current[keys[keys.length - 1]] = value;
  }

  getAll() {
    return { ...this.config };
  }
}

// Create singleton instance
const configManager = new ConfigManager();

module.exports = configManager;