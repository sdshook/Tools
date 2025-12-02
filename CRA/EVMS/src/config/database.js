// EVMS (c) Shane D. Shook, 2025 All Rights Reserved
// Database configuration

const config = require('./index');

class DatabaseConfig {
  constructor() {
    this.neo4jConfig = null;
  }

  getNeo4jConfig() {
    if (!this.neo4jConfig) {
      this.neo4jConfig = {
        uri: config.get('database.neo4j.uri', 'bolt://localhost:7687'),
        username: config.get('database.neo4j.username', 'neo4j'),
        password: config.get('database.neo4j.password', 'password'),
        database: config.get('database.neo4j.database', 'evms'),
        maxConnectionPoolSize: config.get('database.neo4j.maxConnectionPoolSize', 50),
        connectionAcquisitionTimeout: config.get('database.neo4j.connectionAcquisitionTimeout', 60000),
        connectionTimeout: config.get('database.neo4j.connectionTimeout', 30000),
        maxTransactionRetryTime: config.get('database.neo4j.maxTransactionRetryTime', 30000),
        encrypted: config.get('database.neo4j.encrypted', false),
        trust: config.get('database.neo4j.trust', 'TRUST_ALL_CERTIFICATES'),
      };
    }
    return this.neo4jConfig;
  }

  getConnectionString() {
    const dbConfig = this.getNeo4jConfig();
    return `${dbConfig.uri}/${dbConfig.database}`;
  }

  validateConfig() {
    const dbConfig = this.getNeo4jConfig();
    
    if (!dbConfig.uri) {
      throw new Error('Neo4j URI is required');
    }
    
    if (!dbConfig.username) {
      throw new Error('Neo4j username is required');
    }
    
    if (!dbConfig.password) {
      throw new Error('Neo4j password is required');
    }
    
    return true;
  }

  getRetryConfig() {
    return {
      maxRetries: config.get('database.retry.maxRetries', 3),
      retryDelay: config.get('database.retry.retryDelay', 1000),
      backoffMultiplier: config.get('database.retry.backoffMultiplier', 2),
    };
  }

  getHealthCheckConfig() {
    return {
      enabled: config.get('database.healthCheck.enabled', true),
      interval: config.get('database.healthCheck.interval', 30000),
      timeout: config.get('database.healthCheck.timeout', 5000),
    };
  }
}

module.exports = new DatabaseConfig();