// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// LLM Service - Language model integration for chat and analysis

const { OpenAI } = require('openai');
const Logger = require('../../utils/logger');

class LLMService {
  constructor(config = {}) {
    this.config = {
      provider: config.provider || process.env.LLM_PROVIDER || 'openai',
      apiKey: config.apiKey || process.env.OPENAI_API_KEY,
      model: config.model || process.env.LLM_MODEL || 'gpt-4',
      baseURL: config.baseURL || process.env.LLM_BASE_URL,
      temperature: config.temperature || 0.1, // Low temperature for deterministic responses
      maxTokens: config.maxTokens || 2048,
      ...config
    };

    this.logger = new Logger('LLMService');
    this.client = null;
    this.systemPrompts = this.initializeSystemPrompts();
  }

  initializeSystemPrompts() {
    return {
      query: `You are EVMS AI, an expert cybersecurity analyst specializing in vulnerability management and risk assessment. 

Your role is to provide accurate, deterministic responses based on the graph database data provided. Always:
- Base responses on the provided data from the graph database
- Cite specific sources and data points
- Provide actionable insights and recommendations
- Use precise cybersecurity terminology
- Highlight critical risks and vulnerabilities
- Suggest remediation steps when appropriate

When data is insufficient, clearly state limitations and suggest additional data collection.`,

      analysis: `You are EVMS AI, performing deep cybersecurity analysis. Your analysis should:
- Identify patterns and correlations in the data
- Assess risk levels and impact
- Provide strategic recommendations
- Highlight emerging threats or trends
- Suggest preventive measures
- Quantify risks where possible

Always ground your analysis in the provided data and explain your reasoning.`,

      report: `You are EVMS AI, generating professional cybersecurity reports. Your reports should:
- Follow industry-standard formats
- Include executive summaries
- Provide detailed technical findings
- Include risk matrices and scoring
- Offer clear remediation roadmaps
- Use appropriate visualizations and metrics

Ensure reports are suitable for both technical and executive audiences.`,

      conversation: `You are EVMS AI, a helpful cybersecurity assistant. You can:
- Answer questions about vulnerability management
- Explain security concepts and best practices
- Provide guidance on risk assessment
- Help interpret scan results and findings
- Suggest security improvements

Always be helpful, accurate, and security-focused in your responses.`
    };
  }

  async initialize() {
    try {
      if (this.config.provider === 'openai') {
        this.client = new OpenAI({
          apiKey: this.config.apiKey,
          baseURL: this.config.baseURL
        });
      } else {
        throw new Error(`Unsupported LLM provider: ${this.config.provider}`);
      }

      // Test connection
      await this.testConnection();
      this.logger.info(`LLM service initialized with provider: ${this.config.provider}`);
      
    } catch (error) {
      this.logger.error('Failed to initialize LLM service:', error);
      throw error;
    }
  }

  async testConnection() {
    try {
      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [{ role: 'user', content: 'Test connection' }],
        max_tokens: 10,
        temperature: 0
      });
      
      if (!response.choices || response.choices.length === 0) {
        throw new Error('Invalid response from LLM service');
      }
      
    } catch (error) {
      throw new Error(`LLM connection test failed: ${error.message}`);
    }
  }

  async classifyIntent(message) {
    try {
      const prompt = `Classify the following user message into one of these categories:
- query: Questions about vulnerabilities, assets, risks, or security status
- report: Requests for generating reports or documentation
- analysis: Requests for deep analysis, trends, or insights
- dashboard: Requests to update or populate dashboard widgets
- conversation: General chat, greetings, or other conversational content

Message: "${message}"

Respond with JSON: {"type": "category", "confidence": 0.0-1.0, "reasoning": "brief explanation"}`;

      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 150,
        temperature: 0.1
      });

      const result = JSON.parse(response.choices[0].message.content);
      return result;
      
    } catch (error) {
      this.logger.error('Intent classification error:', error);
      // Fallback to conversation type
      return { type: 'conversation', confidence: 0.5, reasoning: 'Classification failed' };
    }
  }

  async generateResponse(message, contextData, options = {}) {
    try {
      const systemPrompt = this.systemPrompts[options.type] || this.systemPrompts.conversation;
      
      const contextString = this.formatContextData(contextData);
      
      const userPrompt = `Context Data:
${contextString}

User Question: ${message}

Please provide a comprehensive response based on the context data provided.`;

      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        max_tokens: this.config.maxTokens,
        temperature: this.config.temperature
      });

      return {
        text: response.choices[0].message.content,
        confidence: this.calculateConfidence(response),
        usage: response.usage
      };
      
    } catch (error) {
      this.logger.error('Response generation error:', error);
      throw error;
    }
  }

  async extractReportParameters(message) {
    try {
      const prompt = `Extract report generation parameters from this message: "${message}"

Identify:
- type: vulnerability, risk, compliance, executive, technical, etc.
- parameters: specific filters, timeframes, assets, etc.
- format: pdf, html, markdown, json, etc.

Respond with JSON: {"type": "report_type", "parameters": {}, "format": "format"}`;

      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 200,
        temperature: 0.1
      });

      return JSON.parse(response.choices[0].message.content);
      
    } catch (error) {
      this.logger.error('Report parameter extraction error:', error);
      return { type: 'general', parameters: {}, format: 'markdown' };
    }
  }

  async extractDashboardParameters(message) {
    try {
      const prompt = `Extract dashboard parameters from this message: "${message}"

Identify:
- widgets: risk_summary, vulnerability_trends, asset_status, scan_results, etc.
- timeframe: 1h, 24h, 7d, 30d, etc.

Respond with JSON: {"widgets": ["widget1", "widget2"], "timeframe": "24h"}`;

      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 150,
        temperature: 0.1
      });

      return JSON.parse(response.choices[0].message.content);
      
    } catch (error) {
      this.logger.error('Dashboard parameter extraction error:', error);
      return { widgets: ['risk_summary'], timeframe: '24h' };
    }
  }

  async performAnalysis(message, data) {
    try {
      const systemPrompt = this.systemPrompts.analysis;
      const dataString = this.formatContextData(data);
      
      const userPrompt = `Analyze the following cybersecurity data based on this request: "${message}"

Data:
${dataString}

Provide analysis including:
1. Summary of key findings
2. Risk assessment and prioritization
3. Trends and patterns identified
4. Actionable insights and recommendations
5. Potential security implications

Format as JSON: {
  "summary": "brief summary",
  "type": "analysis_type",
  "insights": ["insight1", "insight2"],
  "recommendations": ["rec1", "rec2"],
  "riskLevel": "low|medium|high|critical"
}`;

      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        max_tokens: this.config.maxTokens,
        temperature: this.config.temperature
      });

      return JSON.parse(response.choices[0].message.content);
      
    } catch (error) {
      this.logger.error('Analysis error:', error);
      throw error;
    }
  }

  formatContextData(data) {
    if (!data) return 'No context data available.';
    
    if (typeof data === 'string') return data;
    
    if (Array.isArray(data)) {
      return data.map((item, index) => `${index + 1}. ${JSON.stringify(item)}`).join('\n');
    }
    
    if (typeof data === 'object') {
      return Object.entries(data)
        .map(([key, value]) => `${key}: ${JSON.stringify(value)}`)
        .join('\n');
    }
    
    return JSON.stringify(data);
  }

  calculateConfidence(response) {
    // Simple confidence calculation based on response characteristics
    const content = response.choices[0].message.content;
    const length = content.length;
    
    // Base confidence on response length and finish reason
    let confidence = 0.7;
    
    if (response.choices[0].finish_reason === 'stop') {
      confidence += 0.2;
    }
    
    if (length > 100) {
      confidence += 0.1;
    }
    
    return Math.min(confidence, 1.0);
  }

  async generateEmbedding(text) {
    try {
      if (this.config.provider !== 'openai') {
        throw new Error('Embeddings only supported with OpenAI provider');
      }

      const response = await this.client.embeddings.create({
        model: 'text-embedding-ada-002',
        input: text
      });

      return response.data[0].embedding;
      
    } catch (error) {
      this.logger.error('Embedding generation error:', error);
      throw error;
    }
  }

  async summarizeText(text, maxLength = 200) {
    try {
      const prompt = `Summarize the following text in ${maxLength} characters or less:

${text}

Summary:`;

      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [{ role: 'user', content: prompt }],
        max_tokens: Math.ceil(maxLength / 3), // Rough token estimation
        temperature: 0.1
      });

      return response.choices[0].message.content.trim();
      
    } catch (error) {
      this.logger.error('Text summarization error:', error);
      return text.substring(0, maxLength) + '...';
    }
  }
}

module.exports = LLMService;