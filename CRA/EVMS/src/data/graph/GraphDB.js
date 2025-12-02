// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Graph database interface

const neo4j = require('neo4j-driver');
const logger = require('../../utils/logger');
const config = require('../../config');

class GraphDB {
  constructor() {
    this.driver = null;
    this.connected = false;
  }

  async connect() {
    try {
      const dbConfig = config.get('database.neo4j');
      
      logger.info('Connecting to Neo4j database', { 
        uri: dbConfig.uri,
        database: dbConfig.database 
      });

      this.driver = neo4j.driver(
        dbConfig.uri,
        neo4j.auth.basic(dbConfig.username, dbConfig.password),
        {
          maxConnectionPoolSize: dbConfig.maxConnectionPoolSize,
          connectionAcquisitionTimeout: dbConfig.connectionAcquisitionTimeout,
          connectionTimeout: dbConfig.connectionTimeout,
          maxTransactionRetryTime: dbConfig.maxTransactionRetryTime,
          encrypted: dbConfig.encrypted,
          trust: dbConfig.trust,
          disableLosslessIntegers: true
        }
      );

      // Verify connectivity
      await this.driver.verifyConnectivity();
      
      this.connected = true;
      logger.info('Successfully connected to Neo4j database');
      
      // Initialize schema
      await this.initializeSchema();
      
      return this.driver;
    } catch (error) {
      logger.error('Failed to connect to Neo4j database', { error: error.message });
      throw error;
    }
  }

  async initializeSchema() {
    const session = this.getSession();
    
    try {
      // Create constraints and indexes
      const constraints = [
        // Asset constraints
        'CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE',
        'CREATE CONSTRAINT asset_ip_unique IF NOT EXISTS FOR (a:Asset) REQUIRE a.ipAddress IS UNIQUE',
        
        // Vulnerability constraints
        'CREATE CONSTRAINT vulnerability_id_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE',
        'CREATE CONSTRAINT cve_id_unique IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE',
        
        // Scan constraints
        'CREATE CONSTRAINT scan_id_unique IF NOT EXISTS FOR (s:Scan) REQUIRE s.id IS UNIQUE',
        
        // User constraints
        'CREATE CONSTRAINT user_id_unique IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE',
        'CREATE CONSTRAINT user_email_unique IF NOT EXISTS FOR (u:User) REQUIRE u.email IS UNIQUE',
        
        // Risk constraints
        'CREATE CONSTRAINT risk_id_unique IF NOT EXISTS FOR (r:Risk) REQUIRE r.id IS UNIQUE'
      ];

      const indexes = [
        // Asset indexes
        'CREATE INDEX asset_hostname IF NOT EXISTS FOR (a:Asset) ON (a.hostname)',
        'CREATE INDEX asset_type IF NOT EXISTS FOR (a:Asset) ON (a.assetType)',
        'CREATE INDEX asset_os IF NOT EXISTS FOR (a:Asset) ON (a.operatingSystem)',
        'CREATE INDEX asset_risk_score IF NOT EXISTS FOR (a:Asset) ON (a.riskScore)',
        
        // Vulnerability indexes
        'CREATE INDEX vulnerability_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)',
        'CREATE INDEX vulnerability_cvss IF NOT EXISTS FOR (v:Vulnerability) ON (v.cvssScore)',
        'CREATE INDEX vulnerability_status IF NOT EXISTS FOR (v:Vulnerability) ON (v.status)',
        'CREATE INDEX vulnerability_discovered IF NOT EXISTS FOR (v:Vulnerability) ON (v.discoveredAt)',
        
        // CVE indexes
        'CREATE INDEX cve_published IF NOT EXISTS FOR (c:CVE) ON (c.publishedDate)',
        'CREATE INDEX cve_modified IF NOT EXISTS FOR (c:CVE) ON (c.lastModifiedDate)',
        'CREATE INDEX cve_score IF NOT EXISTS FOR (c:CVE) ON (c.baseScore)',
        
        // Scan indexes
        'CREATE INDEX scan_type IF NOT EXISTS FOR (s:Scan) ON (s.type)',
        'CREATE INDEX scan_status IF NOT EXISTS FOR (s:Scan) ON (s.status)',
        'CREATE INDEX scan_created IF NOT EXISTS FOR (s:Scan) ON (s.createdAt)',
        
        // Risk indexes
        'CREATE INDEX risk_level IF NOT EXISTS FOR (r:Risk) ON (r.level)',
        'CREATE INDEX risk_score IF NOT EXISTS FOR (r:Risk) ON (r.score)',
        'CREATE INDEX risk_status IF NOT EXISTS FOR (r:Risk) ON (r.status)'
      ];

      // Execute constraints
      for (const constraint of constraints) {
        try {
          await session.run(constraint);
          logger.debug('Created constraint', { constraint });
        } catch (error) {
          if (!error.message.includes('already exists')) {
            logger.warn('Failed to create constraint', { constraint, error: error.message });
          }
        }
      }

      // Execute indexes
      for (const index of indexes) {
        try {
          await session.run(index);
          logger.debug('Created index', { index });
        } catch (error) {
          if (!error.message.includes('already exists')) {
            logger.warn('Failed to create index', { index, error: error.message });
          }
        }
      }

      logger.info('Database schema initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize database schema', { error: error.message });
      throw error;
    } finally {
      await session.close();
    }
  }

  getSession(database = null) {
    if (!this.connected) {
      throw new Error('Database not connected');
    }
    
    const dbName = database || config.get('database.neo4j.database');
    return this.driver.session({ database: dbName });
  }

  async runQuery(query, parameters = {}, database = null) {
    const session = this.getSession(database);
    
    try {
      logger.debug('Executing query', { query, parameters });
      const result = await session.run(query, parameters);
      
      return {
        records: result.records,
        summary: result.summary
      };
    } catch (error) {
      logger.error('Query execution failed', { 
        query, 
        parameters, 
        error: error.message 
      });
      throw error;
    } finally {
      await session.close();
    }
  }

  async runTransaction(transactionFunction, database = null) {
    const session = this.getSession(database);
    
    try {
      return await session.executeWrite(transactionFunction);
    } catch (error) {
      logger.error('Transaction failed', { error: error.message });
      throw error;
    } finally {
      await session.close();
    }
  }

  // Asset operations
  async createAsset(assetData) {
    const query = `
      CREATE (a:Asset {
        id: $id,
        hostname: $hostname,
        ipAddress: $ipAddress,
        assetType: $assetType,
        operatingSystem: $operatingSystem,
        services: $services,
        lastSeen: datetime($lastSeen),
        riskScore: $riskScore,
        createdAt: datetime(),
        updatedAt: datetime()
      })
      RETURN a
    `;

    const result = await this.runQuery(query, assetData);
    return result.records[0]?.get('a').properties;
  }

  async updateAsset(assetId, updateData) {
    const setClause = Object.keys(updateData)
      .map(key => `a.${key} = $${key}`)
      .join(', ');

    const query = `
      MATCH (a:Asset {id: $assetId})
      SET ${setClause}, a.updatedAt = datetime()
      RETURN a
    `;

    const parameters = { assetId, ...updateData };
    const result = await this.runQuery(query, parameters);
    return result.records[0]?.get('a').properties;
  }

  async getAsset(assetId) {
    const query = `
      MATCH (a:Asset {id: $assetId})
      RETURN a
    `;

    const result = await this.runQuery(query, { assetId });
    return result.records[0]?.get('a').properties;
  }

  async getAssets(filters = {}, limit = 100, skip = 0) {
    let whereClause = '';
    const parameters = { limit, skip };

    if (Object.keys(filters).length > 0) {
      const conditions = Object.keys(filters).map(key => {
        parameters[key] = filters[key];
        return `a.${key} = $${key}`;
      });
      whereClause = `WHERE ${conditions.join(' AND ')}`;
    }

    const query = `
      MATCH (a:Asset)
      ${whereClause}
      RETURN a
      ORDER BY a.createdAt DESC
      SKIP $skip
      LIMIT $limit
    `;

    const result = await this.runQuery(query, parameters);
    return result.records.map(record => record.get('a').properties);
  }

  // Vulnerability operations
  async createVulnerability(vulnData) {
    const query = `
      CREATE (v:Vulnerability {
        id: $id,
        cveId: $cveId,
        title: $title,
        description: $description,
        severity: $severity,
        cvssScore: $cvssScore,
        status: $status,
        discoveredAt: datetime($discoveredAt),
        riskScore: $riskScore,
        createdAt: datetime(),
        updatedAt: datetime()
      })
      RETURN v
    `;

    const result = await this.runQuery(query, vulnData);
    return result.records[0]?.get('v').properties;
  }

  async linkVulnerabilityToAsset(vulnId, assetId, scanId = null) {
    const query = `
      MATCH (v:Vulnerability {id: $vulnId})
      MATCH (a:Asset {id: $assetId})
      CREATE (v)-[r:AFFECTS {
        discoveredAt: datetime(),
        scanId: $scanId
      }]->(a)
      RETURN r
    `;

    const result = await this.runQuery(query, { vulnId, assetId, scanId });
    return result.records[0]?.get('r').properties;
  }

  async getVulnerabilitiesForAsset(assetId) {
    const query = `
      MATCH (v:Vulnerability)-[:AFFECTS]->(a:Asset {id: $assetId})
      RETURN v
      ORDER BY v.cvssScore DESC, v.discoveredAt DESC
    `;

    const result = await this.runQuery(query, { assetId });
    return result.records.map(record => record.get('v').properties);
  }

  // Risk analysis queries
  async getHighRiskAssets(threshold = 7.0) {
    const query = `
      MATCH (a:Asset)
      WHERE a.riskScore >= $threshold
      OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS]->(a)
      RETURN a, count(v) as vulnerabilityCount
      ORDER BY a.riskScore DESC
    `;

    const result = await this.runQuery(query, { threshold });
    return result.records.map(record => ({
      asset: record.get('a').properties,
      vulnerabilityCount: record.get('vulnerabilityCount').toNumber()
    }));
  }

  async getCriticalVulnerabilities() {
    const query = `
      MATCH (v:Vulnerability)
      WHERE v.severity = 'critical' AND v.status = 'open'
      OPTIONAL MATCH (v)-[:AFFECTS]->(a:Asset)
      RETURN v, collect(a) as affectedAssets
      ORDER BY v.cvssScore DESC, v.discoveredAt DESC
    `;

    const result = await this.runQuery(query);
    return result.records.map(record => ({
      vulnerability: record.get('v').properties,
      affectedAssets: record.get('affectedAssets').map(asset => asset.properties)
    }));
  }

  // Graph analysis for GraphRL
  async getAssetVulnerabilityGraph(assetIds = null) {
    let whereClause = '';
    const parameters = {};

    if (assetIds && assetIds.length > 0) {
      whereClause = 'WHERE a.id IN $assetIds';
      parameters.assetIds = assetIds;
    }

    const query = `
      MATCH (a:Asset)
      ${whereClause}
      OPTIONAL MATCH (v:Vulnerability)-[r:AFFECTS]->(a)
      RETURN a, collect({vulnerability: v, relationship: r}) as vulnerabilities
    `;

    const result = await this.runQuery(query, parameters);
    return result.records.map(record => ({
      asset: record.get('a').properties,
      vulnerabilities: record.get('vulnerabilities')
        .filter(item => item.vulnerability !== null)
        .map(item => ({
          vulnerability: item.vulnerability.properties,
          relationship: item.relationship.properties
        }))
    }));
  }

  async getVulnerabilityCorrelations() {
    const query = `
      MATCH (v1:Vulnerability)-[:AFFECTS]->(a:Asset)<-[:AFFECTS]-(v2:Vulnerability)
      WHERE v1.id <> v2.id
      RETURN v1, v2, count(a) as sharedAssets
      ORDER BY sharedAssets DESC
      LIMIT 100
    `;

    const result = await this.runQuery(query);
    return result.records.map(record => ({
      vulnerability1: record.get('v1').properties,
      vulnerability2: record.get('v2').properties,
      sharedAssets: record.get('sharedAssets').toNumber()
    }));
  }

  // Scan operations
  async createScan(scanData) {
    const query = `
      CREATE (s:Scan {
        id: $id,
        name: $name,
        type: $type,
        targets: $targets,
        status: $status,
        progress: $progress,
        createdAt: datetime(),
        updatedAt: datetime()
      })
      RETURN s
    `;

    const result = await this.runQuery(query, scanData);
    return result.records[0]?.get('s').properties;
  }

  async updateScanStatus(scanId, status, progress = null, completedAt = null) {
    const updates = ['s.status = $status', 's.updatedAt = datetime()'];
    const parameters = { scanId, status };

    if (progress !== null) {
      updates.push('s.progress = $progress');
      parameters.progress = progress;
    }

    if (completedAt !== null) {
      updates.push('s.completedAt = datetime($completedAt)');
      parameters.completedAt = completedAt;
    }

    const query = `
      MATCH (s:Scan {id: $scanId})
      SET ${updates.join(', ')}
      RETURN s
    `;

    const result = await this.runQuery(query, parameters);
    return result.records[0]?.get('s').properties;
  }

  // Health check
  async healthCheck() {
    try {
      if (!this.connected) {
        return { healthy: false, error: 'Not connected' };
      }

      // Test basic connectivity
      const result = await this.runQuery('RETURN 1 as test');
      
      if (result.records.length === 0) {
        return { healthy: false, error: 'No response from database' };
      }

      // Test write capability
      const testId = `health_check_${Date.now()}`;
      await this.runQuery(
        'CREATE (t:HealthCheck {id: $id, timestamp: datetime()}) RETURN t',
        { id: testId }
      );
      
      // Clean up test node
      await this.runQuery('MATCH (t:HealthCheck {id: $id}) DELETE t', { id: testId });

      return { healthy: true };
    } catch (error) {
      logger.error('Graph database health check failed', { error: error.message });
      return { healthy: false, error: error.message };
    }
  }

  // Graceful shutdown
  async close() {
    try {
      if (this.driver) {
        await this.driver.close();
        this.connected = false;
        logger.info('Neo4j connection closed gracefully');
      }
    } catch (error) {
      logger.error('Error closing Neo4j connection', { error: error.message });
      throw error;
    }
  }

  // Getters
  isConnected() {
    return this.connected;
  }

  getDriver() {
    return this.driver;
  }
}

module.exports = GraphDB;
