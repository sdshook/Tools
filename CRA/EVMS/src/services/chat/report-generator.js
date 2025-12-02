// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Report Generator - LLM-powered on-demand report generation

const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const Logger = require('../../utils/logger');
const GraphDB = require('../../utils/graph-db');
const LLMService = require('./llm-service');
const RAGPipeline = require('./rag-pipeline');

class ReportGenerator {
  constructor(config = {}) {
    this.config = {
      outputDir: config.outputDir || './reports',
      maxReportSize: config.maxReportSize || 10 * 1024 * 1024, // 10MB
      retentionDays: config.retentionDays || 30,
      ...config
    };

    this.logger = new Logger('ReportGenerator');
    this.graphDB = new GraphDB();
    this.llm = new LLMService();
    this.rag = new RAGPipeline();
    
    this.reportTemplates = this.initializeReportTemplates();
  }

  initializeReportTemplates() {
    return {
      vulnerability: {
        title: 'Vulnerability Assessment Report',
        sections: [
          'executive_summary',
          'vulnerability_overview',
          'critical_findings',
          'risk_analysis',
          'remediation_recommendations',
          'technical_details',
          'appendix'
        ]
      },
      
      risk: {
        title: 'Risk Assessment Report',
        sections: [
          'executive_summary',
          'risk_landscape',
          'threat_analysis',
          'impact_assessment',
          'mitigation_strategies',
          'compliance_status',
          'recommendations'
        ]
      },
      
      compliance: {
        title: 'Compliance Assessment Report',
        sections: [
          'executive_summary',
          'compliance_overview',
          'framework_analysis',
          'gap_analysis',
          'remediation_plan',
          'implementation_roadmap'
        ]
      },
      
      executive: {
        title: 'Executive Security Summary',
        sections: [
          'executive_summary',
          'security_posture',
          'key_metrics',
          'strategic_recommendations',
          'budget_considerations',
          'next_steps'
        ]
      },
      
      technical: {
        title: 'Technical Security Report',
        sections: [
          'technical_summary',
          'asset_inventory',
          'vulnerability_details',
          'configuration_analysis',
          'network_security',
          'remediation_procedures'
        ]
      }
    };
  }

  async initialize() {
    try {
      // Ensure output directory exists
      await fs.mkdir(this.config.outputDir, { recursive: true });
      
      await this.graphDB.connect();
      await this.llm.initialize();
      await this.rag.initialize();
      
      this.logger.info('Report generator initialized');
    } catch (error) {
      this.logger.error('Failed to initialize report generator:', error);
      throw error;
    }
  }

  async generate(reportType, parameters = {}, format = 'markdown') {
    try {
      const reportId = uuidv4();
      const timestamp = new Date().toISOString();
      
      this.logger.info(`Generating ${reportType} report`, { reportId, format });
      
      // Get report template
      const template = this.reportTemplates[reportType];
      if (!template) {
        throw new Error(`Unknown report type: ${reportType}`);
      }
      
      // Gather data for report
      const reportData = await this.gatherReportData(reportType, parameters);
      
      // Generate report content
      const reportContent = await this.generateReportContent(template, reportData, parameters);
      
      // Format report
      const formattedReport = await this.formatReport(reportContent, format);
      
      // Save report
      const filename = `${reportType}_${reportId}_${Date.now()}.${this.getFileExtension(format)}`;
      const filepath = path.join(this.config.outputDir, filename);
      
      await fs.writeFile(filepath, formattedReport);
      
      const report = {
        id: reportId,
        type: reportType,
        format,
        filename,
        filepath,
        url: `/reports/${filename}`,
        size: formattedReport.length,
        timestamp,
        parameters,
        sections: template.sections
      };
      
      this.logger.info(`Report generated successfully`, { reportId, size: report.size });
      
      return report;
      
    } catch (error) {
      this.logger.error('Report generation failed:', error);
      throw error;
    }
  }

  async gatherReportData(reportType, parameters) {
    try {
      const data = {};
      
      // Common data gathering
      data.metadata = {
        generatedAt: new Date().toISOString(),
        reportType,
        parameters
      };
      
      // Get system overview
      data.systemOverview = await this.getSystemOverview();
      
      // Type-specific data gathering
      switch (reportType) {
        case 'vulnerability':
          data.vulnerabilities = await this.getVulnerabilityData(parameters);
          data.assets = await this.getAssetData(parameters);
          data.riskMetrics = await this.getRiskMetrics(parameters);
          break;
          
        case 'risk':
          data.risks = await this.getRiskData(parameters);
          data.threats = await this.getThreatData(parameters);
          data.impacts = await this.getImpactData(parameters);
          break;
          
        case 'compliance':
          data.compliance = await this.getComplianceData(parameters);
          data.frameworks = await this.getFrameworkData(parameters);
          data.gaps = await this.getGapAnalysis(parameters);
          break;
          
        case 'executive':
          data.metrics = await this.getExecutiveMetrics(parameters);
          data.trends = await this.getTrendData(parameters);
          data.budget = await this.getBudgetData(parameters);
          break;
          
        case 'technical':
          data.technical = await this.getTechnicalData(parameters);
          data.configurations = await this.getConfigurationData(parameters);
          data.network = await this.getNetworkData(parameters);
          break;
      }
      
      return data;
      
    } catch (error) {
      this.logger.error('Data gathering failed:', error);
      throw error;
    }
  }

  async generateReportContent(template, data, parameters) {
    try {
      const content = {
        title: template.title,
        sections: {}
      };
      
      // Generate each section using LLM
      for (const sectionName of template.sections) {
        this.logger.debug(`Generating section: ${sectionName}`);
        
        const sectionContent = await this.generateSection(sectionName, data, parameters);
        content.sections[sectionName] = sectionContent;
      }
      
      return content;
      
    } catch (error) {
      this.logger.error('Content generation failed:', error);
      throw error;
    }
  }

  async generateSection(sectionName, data, parameters) {
    try {
      const sectionPrompt = this.getSectionPrompt(sectionName, data, parameters);
      
      const response = await this.llm.generateResponse(
        `Generate the ${sectionName} section for this cybersecurity report.`,
        sectionPrompt,
        { type: 'report' }
      );
      
      return {
        title: this.formatSectionTitle(sectionName),
        content: response.text,
        metadata: {
          generatedAt: new Date().toISOString(),
          confidence: response.confidence
        }
      };
      
    } catch (error) {
      this.logger.error(`Section generation failed (${sectionName}):`, error);
      return {
        title: this.formatSectionTitle(sectionName),
        content: `Error generating ${sectionName} section: ${error.message}`,
        metadata: { error: true }
      };
    }
  }

  getSectionPrompt(sectionName, data, parameters) {
    const basePrompt = `Generate a professional cybersecurity report section for "${sectionName}".

Available Data:
${JSON.stringify(data, null, 2)}

Parameters:
${JSON.stringify(parameters, null, 2)}

Requirements:
- Professional tone suitable for cybersecurity professionals
- Include specific data points and metrics where available
- Provide actionable insights and recommendations
- Use industry-standard terminology
- Format with appropriate headings and structure
`;

    // Section-specific prompts
    const sectionPrompts = {
      executive_summary: basePrompt + `
Focus on:
- High-level security posture overview
- Key findings and critical issues
- Business impact and risk exposure
- Strategic recommendations
- Executive-level language and metrics`,

      vulnerability_overview: basePrompt + `
Focus on:
- Total vulnerability count and severity distribution
- Critical and high-severity vulnerabilities
- Vulnerability trends and patterns
- Asset coverage and exposure
- Remediation progress and timelines`,

      critical_findings: basePrompt + `
Focus on:
- Most critical security issues identified
- Immediate threats and risks
- High-impact vulnerabilities
- Urgent remediation requirements
- Potential attack vectors`,

      risk_analysis: basePrompt + `
Focus on:
- Risk scoring methodology and results
- Risk categorization and prioritization
- Business impact assessment
- Likelihood and impact analysis
- Risk tolerance and acceptance criteria`,

      remediation_recommendations: basePrompt + `
Focus on:
- Prioritized remediation actions
- Implementation timelines and effort estimates
- Resource requirements and dependencies
- Quick wins and long-term strategies
- Monitoring and validation approaches`,

      technical_details: basePrompt + `
Focus on:
- Detailed vulnerability descriptions
- Technical impact and exploitation methods
- Affected systems and configurations
- Proof of concept or evidence
- Technical remediation procedures`
    };

    return sectionPrompts[sectionName] || basePrompt;
  }

  formatSectionTitle(sectionName) {
    return sectionName
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  async formatReport(content, format) {
    try {
      switch (format.toLowerCase()) {
        case 'markdown':
          return this.formatAsMarkdown(content);
        case 'html':
          return this.formatAsHTML(content);
        case 'json':
          return JSON.stringify(content, null, 2);
        case 'text':
          return this.formatAsText(content);
        default:
          throw new Error(`Unsupported format: ${format}`);
      }
    } catch (error) {
      this.logger.error('Report formatting failed:', error);
      throw error;
    }
  }

  formatAsMarkdown(content) {
    let markdown = `# ${content.title}\n\n`;
    markdown += `*Generated on ${new Date().toLocaleString()}*\n\n`;
    markdown += '---\n\n';
    
    Object.entries(content.sections).forEach(([sectionName, section]) => {
      markdown += `## ${section.title}\n\n`;
      markdown += `${section.content}\n\n`;
      
      if (section.metadata && section.metadata.error) {
        markdown += `*⚠️ Section generation error*\n\n`;
      }
      
      markdown += '---\n\n';
    });
    
    return markdown;
  }

  formatAsHTML(content) {
    let html = `<!DOCTYPE html>
<html>
<head>
    <title>${content.title}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; }
        h2 { color: #34495e; margin-top: 30px; }
        .metadata { color: #7f8c8d; font-style: italic; }
        .error { color: #e74c3c; background: #fdf2f2; padding: 10px; border-left: 4px solid #e74c3c; }
    </style>
</head>
<body>
    <h1>${content.title}</h1>
    <p class="metadata">Generated on ${new Date().toLocaleString()}</p>
`;
    
    Object.entries(content.sections).forEach(([sectionName, section]) => {
      html += `    <h2>${section.title}</h2>\n`;
      
      if (section.metadata && section.metadata.error) {
        html += `    <div class="error">⚠️ Section generation error</div>\n`;
      }
      
      // Convert markdown-style content to HTML
      const htmlContent = section.content
        .replace(/\n\n/g, '</p><p>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>');
      
      html += `    <p>${htmlContent}</p>\n`;
    });
    
    html += '</body>\n</html>';
    return html;
  }

  formatAsText(content) {
    let text = `${content.title}\n`;
    text += '='.repeat(content.title.length) + '\n\n';
    text += `Generated on ${new Date().toLocaleString()}\n\n`;
    
    Object.entries(content.sections).forEach(([sectionName, section]) => {
      text += `${section.title}\n`;
      text += '-'.repeat(section.title.length) + '\n\n';
      text += `${section.content}\n\n`;
      
      if (section.metadata && section.metadata.error) {
        text += `⚠️ Section generation error\n\n`;
      }
    });
    
    return text;
  }

  getFileExtension(format) {
    const extensions = {
      markdown: 'md',
      html: 'html',
      json: 'json',
      text: 'txt',
      pdf: 'pdf'
    };
    
    return extensions[format.toLowerCase()] || 'txt';
  }

  // Data gathering methods
  async getSystemOverview() {
    const query = `
      MATCH (a:Asset)
      OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
      RETURN 
        count(DISTINCT a) as totalAssets,
        count(v) as totalVulnerabilities,
        collect(DISTINCT a.asset_type) as assetTypes
    `;
    
    const result = await this.graphDB.query(query);
    return result[0] || {};
  }

  async getVulnerabilityData(parameters) {
    const timeConstraint = parameters.timeframe ? 
      `WHERE v.discovered_date >= datetime() - duration('P${parameters.timeframe}')` : '';
    
    const query = `
      MATCH (v:Vulnerability)-[:AFFECTS]->(a:Asset)
      ${timeConstraint}
      RETURN v, a,
             v.severity as severity,
             v.cvss_score as cvssScore,
             v.cve as cve,
             a.hostname as hostname
      ORDER BY v.cvss_score DESC
      LIMIT 100
    `;
    
    return await this.graphDB.query(query, parameters);
  }

  async getRiskMetrics(parameters) {
    const query = `
      MATCH (r:Risk)
      RETURN 
        avg(r.risk_score) as avgRiskScore,
        max(r.risk_score) as maxRiskScore,
        count(r) as totalRisks,
        collect(DISTINCT r.category) as riskCategories
    `;
    
    const result = await this.graphDB.query(query);
    return result[0] || {};
  }

  // Additional data gathering methods would be implemented here...
  async getAssetData(parameters) { return []; }
  async getRiskData(parameters) { return []; }
  async getThreatData(parameters) { return []; }
  async getImpactData(parameters) { return []; }
  async getComplianceData(parameters) { return []; }
  async getFrameworkData(parameters) { return []; }
  async getGapAnalysis(parameters) { return []; }
  async getExecutiveMetrics(parameters) { return []; }
  async getTrendData(parameters) { return []; }
  async getBudgetData(parameters) { return []; }
  async getTechnicalData(parameters) { return []; }
  async getConfigurationData(parameters) { return []; }
  async getNetworkData(parameters) { return []; }
}

module.exports = ReportGenerator;