// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// RAG Pipeline - Retrieval-Augmented Generation for deterministic responses

const Logger = require('../../utils/logger');
const GraphDB = require('../../utils/graph-db');
const LLMService = require('./llm-service');

class RAGPipeline {
  constructor(config = {}) {
    this.config = {
      maxRetrievalNodes: config.maxRetrievalNodes || 50,
      similarityThreshold: config.similarityThreshold || 0.7,
      contextWindow: config.contextWindow || 4000, // characters
      ...config
    };

    this.logger = new Logger('RAGPipeline');
    this.graphDB = new GraphDB();
    this.llm = new LLMService();
    this.queryTemplates = this.initializeQueryTemplates();
  }

  initializeQueryTemplates() {
    return {
      vulnerabilities: `
        MATCH (v:Vulnerability)-[:AFFECTS]->(a:Asset)
        WHERE toLower(v.description) CONTAINS toLower($searchTerm)
           OR toLower(v.cve) CONTAINS toLower($searchTerm)
           OR toLower(a.hostname) CONTAINS toLower($searchTerm)
        RETURN v, a, 
               v.severity as severity,
               v.cvss_score as cvssScore,
               v.cve as cve,
               a.hostname as hostname,
               a.ip_address as ipAddress
        ORDER BY v.cvss_score DESC
        LIMIT $limit
      `,

      assets: `
        MATCH (a:Asset)
        WHERE toLower(a.hostname) CONTAINS toLower($searchTerm)
           OR toLower(a.ip_address) CONTAINS toLower($searchTerm)
           OR toLower(a.asset_type) CONTAINS toLower($searchTerm)
        OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN a,
               collect(v) as vulnerabilities,
               a.hostname as hostname,
               a.ip_address as ipAddress,
               a.asset_type as assetType,
               a.risk_score as riskScore
        ORDER BY a.risk_score DESC
        LIMIT $limit
      `,

      risks: `
        MATCH (r:Risk)-[:ASSOCIATED_WITH]->(a:Asset)
        WHERE toLower(r.description) CONTAINS toLower($searchTerm)
           OR toLower(r.category) CONTAINS toLower($searchTerm)
        RETURN r, a,
               r.risk_score as riskScore,
               r.category as category,
               r.description as description,
               a.hostname as hostname
        ORDER BY r.risk_score DESC
        LIMIT $limit
      `,

      scans: `
        MATCH (s:Scan)-[:SCANNED]->(a:Asset)
        WHERE toLower(s.scan_type) CONTAINS toLower($searchTerm)
           OR toLower(a.hostname) CONTAINS toLower($searchTerm)
        OPTIONAL MATCH (s)-[:FOUND]->(v:Vulnerability)
        RETURN s, a, collect(v) as vulnerabilities,
               s.scan_type as scanType,
               s.timestamp as timestamp,
               s.status as status,
               a.hostname as hostname
        ORDER BY s.timestamp DESC
        LIMIT $limit
      `,

      trends: `
        MATCH (v:Vulnerability)-[:AFFECTS]->(a:Asset)
        WHERE v.discovered_date >= datetime($startDate)
        RETURN v.severity as severity,
               count(v) as count,
               date(v.discovered_date) as date
        ORDER BY date DESC
        LIMIT $limit
      `,

      compliance: `
        MATCH (c:ComplianceCheck)-[:APPLIES_TO]->(a:Asset)
        WHERE toLower(c.framework) CONTAINS toLower($searchTerm)
           OR toLower(c.control_id) CONTAINS toLower($searchTerm)
        RETURN c, a,
               c.framework as framework,
               c.control_id as controlId,
               c.status as status,
               c.description as description,
               a.hostname as hostname
        ORDER BY c.status DESC
        LIMIT $limit
      `
    };
  }

  async initialize() {
    try {
      await this.graphDB.connect();
      this.logger.info('RAG pipeline initialized');
    } catch (error) {
      this.logger.error('Failed to initialize RAG pipeline:', error);
      throw error;
    }
  }

  async retrieveRelevantData(query, context = {}) {
    try {
      // Analyze query to determine data types needed
      const queryAnalysis = await this.analyzeQuery(query);
      
      // Retrieve data from graph database
      const retrievedData = await this.retrieveFromGraph(queryAnalysis, context);
      
      // Rank and filter results
      const rankedData = await this.rankResults(retrievedData, query);
      
      // Format for LLM consumption
      const formattedData = this.formatForLLM(rankedData);
      
      return {
        nodes: rankedData,
        sources: this.extractSources(rankedData),
        context: formattedData,
        queryType: queryAnalysis.type,
        confidence: queryAnalysis.confidence
      };
      
    } catch (error) {
      this.logger.error('Data retrieval error:', error);
      throw error;
    }
  }

  async analyzeQuery(query) {
    try {
      // Use LLM to analyze query intent and extract key terms
      const analysisPrompt = `Analyze this cybersecurity query and extract key information:

Query: "${query}"

Determine:
1. Primary data type needed (vulnerabilities, assets, risks, scans, trends, compliance)
2. Key search terms and entities
3. Time constraints if any
4. Specific filters or conditions

Respond with JSON: {
  "type": "primary_data_type",
  "searchTerms": ["term1", "term2"],
  "timeConstraints": {"start": "date", "end": "date"},
  "filters": {"key": "value"},
  "confidence": 0.0-1.0
}`;

      const response = await this.llm.client.chat.completions.create({
        model: this.llm.config.model,
        messages: [{ role: 'user', content: analysisPrompt }],
        max_tokens: 300,
        temperature: 0.1
      });

      return JSON.parse(response.choices[0].message.content);
      
    } catch (error) {
      this.logger.error('Query analysis error:', error);
      // Fallback analysis
      return {
        type: 'vulnerabilities',
        searchTerms: [query],
        timeConstraints: {},
        filters: {},
        confidence: 0.5
      };
    }
  }

  async retrieveFromGraph(queryAnalysis, context) {
    try {
      const results = [];
      const { type, searchTerms, timeConstraints, filters } = queryAnalysis;
      
      // Get primary query template
      const queryTemplate = this.queryTemplates[type] || this.queryTemplates.vulnerabilities;
      
      // Execute queries for each search term
      for (const term of searchTerms) {
        const params = {
          searchTerm: term,
          limit: Math.ceil(this.config.maxRetrievalNodes / searchTerms.length),
          ...filters
        };
        
        // Add time constraints if present
        if (timeConstraints.start) {
          params.startDate = timeConstraints.start;
        }
        if (timeConstraints.end) {
          params.endDate = timeConstraints.end;
        }
        
        const queryResults = await this.graphDB.query(queryTemplate, params);
        results.push(...queryResults);
      }
      
      // Remove duplicates and limit results
      const uniqueResults = this.deduplicateResults(results);
      return uniqueResults.slice(0, this.config.maxRetrievalNodes);
      
    } catch (error) {
      this.logger.error('Graph retrieval error:', error);
      return [];
    }
  }

  async rankResults(results, originalQuery) {
    try {
      // Simple ranking based on relevance scores
      const rankedResults = results.map(result => {
        const relevanceScore = this.calculateRelevance(result, originalQuery);
        return {
          ...result,
          relevanceScore
        };
      });
      
      // Sort by relevance and return top results
      return rankedResults
        .sort((a, b) => b.relevanceScore - a.relevanceScore)
        .filter(r => r.relevanceScore >= this.config.similarityThreshold);
        
    } catch (error) {
      this.logger.error('Result ranking error:', error);
      return results;
    }
  }

  calculateRelevance(result, query) {
    // Simple text-based relevance scoring
    const queryLower = query.toLowerCase();
    let score = 0;
    
    // Check various fields for query terms
    const fields = ['description', 'hostname', 'cve', 'category', 'scanType'];
    
    fields.forEach(field => {
      if (result[field] && typeof result[field] === 'string') {
        const fieldValue = result[field].toLowerCase();
        if (fieldValue.includes(queryLower)) {
          score += 1;
        }
        // Partial matches
        const queryWords = queryLower.split(' ');
        queryWords.forEach(word => {
          if (word.length > 3 && fieldValue.includes(word)) {
            score += 0.5;
          }
        });
      }
    });
    
    // Boost score based on severity/risk
    if (result.cvssScore && result.cvssScore > 7) score += 0.5;
    if (result.riskScore && result.riskScore > 0.7) score += 0.5;
    if (result.severity === 'critical' || result.severity === 'high') score += 0.3;
    
    return Math.min(score, 1.0);
  }

  formatForLLM(results) {
    try {
      let formattedText = '';
      let currentLength = 0;
      
      for (const result of results) {
        const resultText = this.formatSingleResult(result);
        
        if (currentLength + resultText.length > this.config.contextWindow) {
          break;
        }
        
        formattedText += resultText + '\n\n';
        currentLength += resultText.length;
      }
      
      return formattedText;
      
    } catch (error) {
      this.logger.error('LLM formatting error:', error);
      return 'Error formatting results for analysis.';
    }
  }

  formatSingleResult(result) {
    const parts = [];
    
    // Format based on result type
    if (result.cve) {
      parts.push(`Vulnerability: ${result.cve}`);
      if (result.description) parts.push(`Description: ${result.description}`);
      if (result.cvssScore) parts.push(`CVSS Score: ${result.cvssScore}`);
      if (result.severity) parts.push(`Severity: ${result.severity}`);
    }
    
    if (result.hostname) {
      parts.push(`Asset: ${result.hostname}`);
      if (result.ipAddress) parts.push(`IP: ${result.ipAddress}`);
      if (result.assetType) parts.push(`Type: ${result.assetType}`);
    }
    
    if (result.riskScore) {
      parts.push(`Risk Score: ${result.riskScore}`);
    }
    
    if (result.timestamp) {
      parts.push(`Date: ${new Date(result.timestamp).toISOString()}`);
    }
    
    if (result.relevanceScore) {
      parts.push(`Relevance: ${result.relevanceScore.toFixed(2)}`);
    }
    
    return parts.join(' | ');
  }

  extractSources(results) {
    const sources = new Set();
    
    results.forEach(result => {
      if (result.cve) sources.add(`CVE: ${result.cve}`);
      if (result.hostname) sources.add(`Asset: ${result.hostname}`);
      if (result.scanType) sources.add(`Scan: ${result.scanType}`);
    });
    
    return Array.from(sources);
  }

  deduplicateResults(results) {
    const seen = new Set();
    return results.filter(result => {
      const key = this.generateResultKey(result);
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  generateResultKey(result) {
    // Generate unique key for deduplication
    const keyParts = [];
    
    if (result.cve) keyParts.push(`cve:${result.cve}`);
    if (result.hostname) keyParts.push(`host:${result.hostname}`);
    if (result.ipAddress) keyParts.push(`ip:${result.ipAddress}`);
    if (result.controlId) keyParts.push(`control:${result.controlId}`);
    
    return keyParts.join('|') || JSON.stringify(result);
  }

  async getSystemContext() {
    try {
      // Get recent system activity for conversational context
      const recentScans = await this.graphDB.query(`
        MATCH (s:Scan)
        WHERE s.timestamp >= datetime() - duration('PT24H')
        RETURN s.scan_type as scanType, 
               s.status as status,
               s.timestamp as timestamp
        ORDER BY s.timestamp DESC
        LIMIT 10
      `);
      
      const recentVulns = await this.graphDB.query(`
        MATCH (v:Vulnerability)
        WHERE v.discovered_date >= datetime() - duration('PT24H')
        RETURN count(v) as newVulnerabilities,
               v.severity as severity
      `);
      
      return {
        recentScans,
        recentVulnerabilities: recentVulns,
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      this.logger.error('System context error:', error);
      return { error: 'Unable to retrieve system context' };
    }
  }

  async retrieveAnalysisData(query, context) {
    // Similar to retrieveRelevantData but optimized for analysis
    const analysisData = await this.retrieveRelevantData(query, context);
    
    // Add aggregated metrics
    const metrics = await this.getAnalysisMetrics(context);
    
    return {
      ...analysisData,
      metrics,
      points: analysisData.nodes
    };
  }

  async getAnalysisMetrics(context) {
    try {
      const metrics = await this.graphDB.query(`
        MATCH (v:Vulnerability)
        RETURN 
          count(v) as totalVulnerabilities,
          avg(v.cvss_score) as avgCvssScore,
          collect(DISTINCT v.severity) as severities
      `);
      
      return metrics[0] || {};
      
    } catch (error) {
      this.logger.error('Analysis metrics error:', error);
      return {};
    }
  }

  async getDashboardData(widget, timeframe) {
    try {
      const timeConstraint = this.parseTimeframe(timeframe);
      
      switch (widget) {
        case 'risk_summary':
          return await this.getRiskSummaryData(timeConstraint);
        case 'vulnerability_trends':
          return await this.getVulnerabilityTrends(timeConstraint);
        case 'asset_status':
          return await this.getAssetStatusData(timeConstraint);
        case 'scan_results':
          return await this.getScanResultsData(timeConstraint);
        default:
          return { error: `Unknown widget: ${widget}` };
      }
      
    } catch (error) {
      this.logger.error(`Dashboard data error (${widget}):`, error);
      return { error: error.message };
    }
  }

  parseTimeframe(timeframe) {
    const now = new Date();
    let startDate;
    
    switch (timeframe) {
      case '1h':
        startDate = new Date(now.getTime() - 60 * 60 * 1000);
        break;
      case '24h':
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }
    
    return { start: startDate.toISOString(), end: now.toISOString() };
  }

  async getRiskSummaryData(timeConstraint) {
    const query = `
      MATCH (r:Risk)
      WHERE r.timestamp >= datetime($startDate)
      RETURN 
        count(r) as totalRisks,
        avg(r.risk_score) as avgRiskScore,
        collect(r.category) as categories
    `;
    
    const result = await this.graphDB.query(query, timeConstraint);
    return { ...result[0], dataPoints: result.length, widget: 'risk_summary' };
  }

  async getVulnerabilityTrends(timeConstraint) {
    const query = `
      MATCH (v:Vulnerability)
      WHERE v.discovered_date >= datetime($startDate)
      RETURN 
        date(v.discovered_date) as date,
        count(v) as count,
        v.severity as severity
      ORDER BY date DESC
    `;
    
    const result = await this.graphDB.query(query, timeConstraint);
    return { trends: result, dataPoints: result.length, widget: 'vulnerability_trends' };
  }

  async getAssetStatusData(timeConstraint) {
    const query = `
      MATCH (a:Asset)
      OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
      WHERE v.discovered_date >= datetime($startDate) OR v IS NULL
      RETURN 
        a.asset_type as assetType,
        count(DISTINCT a) as assetCount,
        count(v) as vulnerabilityCount
    `;
    
    const result = await this.graphDB.query(query, timeConstraint);
    return { assets: result, dataPoints: result.length, widget: 'asset_status' };
  }

  async getScanResultsData(timeConstraint) {
    const query = `
      MATCH (s:Scan)
      WHERE s.timestamp >= datetime($startDate)
      RETURN 
        s.scan_type as scanType,
        s.status as status,
        count(s) as count
      ORDER BY count DESC
    `;
    
    const result = await this.graphDB.query(query, timeConstraint);
    return { scans: result, dataPoints: result.length, widget: 'scan_results' };
  }
}

module.exports = RAGPipeline;