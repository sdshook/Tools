// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Chat Service - LLM/RAG powered interactive chat interface

const express = require('express');
const { Server } = require('socket.io');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');

const Logger = require('../../utils/logger');
const NATSClient = require('../../utils/nats-client');
const LLMService = require('./llm-service');
const RAGPipeline = require('./rag-pipeline');
const ChatHistory = require('./chat-history');
const ReportGenerator = require('./report-generator');

class ChatService {
  constructor(config = {}) {
    this.config = {
      port: config.port || process.env.CHAT_PORT || 3003,
      host: config.host || process.env.CHAT_HOST || '0.0.0.0',
      corsOrigin: config.corsOrigin || process.env.CORS_ORIGIN || '*',
      ...config
    };

    this.logger = new Logger('ChatService');
    this.nats = new NATSClient();
    this.llm = new LLMService();
    this.rag = new RAGPipeline();
    this.chatHistory = new ChatHistory();
    this.reportGenerator = new ReportGenerator();
    
    this.app = express();
    this.server = http.createServer(this.app);
    this.io = new Server(this.server, {
      cors: {
        origin: this.config.corsOrigin,
        methods: ['GET', 'POST']
      }
    });

    this.activeSessions = new Map();
    this.setupMiddleware();
    this.setupRoutes();
    this.setupSocketHandlers();
  }

  setupMiddleware() {
    this.app.use(helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false
    }));
    
    this.app.use(cors({
      origin: this.config.corsOrigin,
      credentials: true
    }));
    
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Request logging
    this.app.use((req, res, next) => {
      this.logger.info(`${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      next();
    });
  }

  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        service: 'chat',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    });

    // Chat API endpoints
    this.app.post('/api/chat/message', async (req, res) => {
      try {
        const { message, sessionId, context } = req.body;
        const response = await this.processMessage(message, sessionId, context);
        res.json(response);
      } catch (error) {
        this.logger.error('Chat message error:', error);
        res.status(500).json({ error: 'Failed to process message' });
      }
    });

    this.app.get('/api/chat/history/:sessionId', async (req, res) => {
      try {
        const { sessionId } = req.params;
        const history = await this.chatHistory.getHistory(sessionId);
        res.json(history);
      } catch (error) {
        this.logger.error('Chat history error:', error);
        res.status(500).json({ error: 'Failed to retrieve chat history' });
      }
    });

    this.app.post('/api/reports/generate', async (req, res) => {
      try {
        const { type, parameters, format } = req.body;
        const report = await this.reportGenerator.generate(type, parameters, format);
        res.json(report);
      } catch (error) {
        this.logger.error('Report generation error:', error);
        res.status(500).json({ error: 'Failed to generate report' });
      }
    });

    this.app.get('/api/dashboard/populate', async (req, res) => {
      try {
        const { widgets, timeframe } = req.query;
        const data = await this.populateDashboard(widgets?.split(','), timeframe);
        res.json(data);
      } catch (error) {
        this.logger.error('Dashboard population error:', error);
        res.status(500).json({ error: 'Failed to populate dashboard' });
      }
    });
  }

  setupSocketHandlers() {
    this.io.on('connection', (socket) => {
      this.logger.info(`Client connected: ${socket.id}`);

      socket.on('join_session', async (sessionId) => {
        try {
          socket.join(sessionId);
          this.activeSessions.set(socket.id, sessionId);
          
          // Send chat history
          const history = await this.chatHistory.getHistory(sessionId);
          socket.emit('chat_history', history);
          
          this.logger.info(`Client ${socket.id} joined session ${sessionId}`);
        } catch (error) {
          this.logger.error('Join session error:', error);
          socket.emit('error', { message: 'Failed to join session' });
        }
      });

      socket.on('chat_message', async (data) => {
        try {
          const { message, sessionId, context } = data;
          const response = await this.processMessage(message, sessionId, context);
          
          // Emit to all clients in the session
          this.io.to(sessionId).emit('chat_response', response);
          
        } catch (error) {
          this.logger.error('Socket chat message error:', error);
          socket.emit('error', { message: 'Failed to process message' });
        }
      });

      socket.on('request_report', async (data) => {
        try {
          const { type, parameters, format, sessionId } = data;
          const report = await this.reportGenerator.generate(type, parameters, format);
          
          socket.emit('report_generated', {
            reportId: report.id,
            type,
            format,
            url: report.url,
            timestamp: new Date().toISOString()
          });
          
        } catch (error) {
          this.logger.error('Socket report generation error:', error);
          socket.emit('error', { message: 'Failed to generate report' });
        }
      });

      socket.on('disconnect', () => {
        const sessionId = this.activeSessions.get(socket.id);
        this.activeSessions.delete(socket.id);
        this.logger.info(`Client disconnected: ${socket.id} from session ${sessionId}`);
      });
    });
  }

  async processMessage(message, sessionId, context = {}) {
    const messageId = uuidv4();
    const timestamp = new Date().toISOString();

    try {
      // Store user message
      await this.chatHistory.addMessage(sessionId, {
        id: messageId,
        type: 'user',
        content: message,
        timestamp,
        context
      });

      // Determine message intent and route appropriately
      const intent = await this.llm.classifyIntent(message);
      
      let response;
      switch (intent.type) {
        case 'query':
          response = await this.handleQuery(message, sessionId, context);
          break;
        case 'report':
          response = await this.handleReportRequest(message, sessionId, context);
          break;
        case 'analysis':
          response = await this.handleAnalysisRequest(message, sessionId, context);
          break;
        case 'dashboard':
          response = await this.handleDashboardRequest(message, sessionId, context);
          break;
        default:
          response = await this.handleGeneralChat(message, sessionId, context);
      }

      // Store assistant response
      const responseId = uuidv4();
      await this.chatHistory.addMessage(sessionId, {
        id: responseId,
        type: 'assistant',
        content: response.content,
        timestamp: new Date().toISOString(),
        metadata: response.metadata
      });

      return {
        id: responseId,
        content: response.content,
        type: intent.type,
        metadata: response.metadata,
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      this.logger.error('Message processing error:', error);
      throw error;
    }
  }

  async handleQuery(message, sessionId, context) {
    // Use RAG pipeline to get relevant data from graph DB
    const relevantData = await this.rag.retrieveRelevantData(message, context);
    
    // Generate response using LLM with retrieved data
    const response = await this.llm.generateResponse(message, relevantData, {
      type: 'query',
      sessionId,
      context
    });

    return {
      content: response.text,
      metadata: {
        sources: relevantData.sources,
        confidence: response.confidence,
        retrievedNodes: relevantData.nodes?.length || 0,
        queryType: 'graph_query'
      }
    };
  }

  async handleReportRequest(message, sessionId, context) {
    // Extract report parameters from message
    const reportParams = await this.llm.extractReportParameters(message);
    
    // Generate report
    const report = await this.reportGenerator.generate(
      reportParams.type,
      reportParams.parameters,
      reportParams.format || 'markdown'
    );

    return {
      content: `I've generated a ${reportParams.type} report for you. You can access it [here](${report.url}).`,
      metadata: {
        reportId: report.id,
        reportType: reportParams.type,
        format: report.format,
        url: report.url,
        generatedAt: report.timestamp
      }
    };
  }

  async handleAnalysisRequest(message, sessionId, context) {
    // Get relevant data for analysis
    const data = await this.rag.retrieveAnalysisData(message, context);
    
    // Perform analysis using LLM
    const analysis = await this.llm.performAnalysis(message, data);

    return {
      content: analysis.summary,
      metadata: {
        analysisType: analysis.type,
        dataPoints: data.points?.length || 0,
        insights: analysis.insights,
        recommendations: analysis.recommendations
      }
    };
  }

  async handleDashboardRequest(message, sessionId, context) {
    // Extract dashboard requirements
    const dashboardParams = await this.llm.extractDashboardParameters(message);
    
    // Populate dashboard data
    const dashboardData = await this.populateDashboard(
      dashboardParams.widgets,
      dashboardParams.timeframe
    );

    return {
      content: `I've updated the dashboard with the requested information.`,
      metadata: {
        widgets: dashboardParams.widgets,
        timeframe: dashboardParams.timeframe,
        dataPoints: dashboardData.totalDataPoints,
        lastUpdated: new Date().toISOString()
      }
    };
  }

  async handleGeneralChat(message, sessionId, context) {
    // Get some context from recent system activity
    const systemContext = await this.rag.getSystemContext();
    
    // Generate conversational response
    const response = await this.llm.generateResponse(message, systemContext, {
      type: 'conversation',
      sessionId,
      context
    });

    return {
      content: response.text,
      metadata: {
        conversational: true,
        confidence: response.confidence
      }
    };
  }

  async populateDashboard(widgets = [], timeframe = '24h') {
    const dashboardData = {};
    let totalDataPoints = 0;

    for (const widget of widgets) {
      try {
        const data = await this.rag.getDashboardData(widget, timeframe);
        dashboardData[widget] = data;
        totalDataPoints += data.dataPoints || 0;
      } catch (error) {
        this.logger.error(`Dashboard widget error (${widget}):`, error);
        dashboardData[widget] = { error: 'Failed to load data' };
      }
    }

    return {
      widgets: dashboardData,
      totalDataPoints,
      timeframe,
      generatedAt: new Date().toISOString()
    };
  }

  async start() {
    try {
      // Initialize dependencies
      await this.nats.connect();
      await this.llm.initialize();
      await this.rag.initialize();
      await this.chatHistory.initialize();
      await this.reportGenerator.initialize();

      // Start server
      this.server.listen(this.config.port, this.config.host, () => {
        this.logger.info(`Chat service started on ${this.config.host}:${this.config.port}`);
      });

      // Subscribe to system events
      await this.subscribeToEvents();

    } catch (error) {
      this.logger.error('Failed to start chat service:', error);
      throw error;
    }
  }

  async subscribeToEvents() {
    // Subscribe to scan results for real-time updates
    await this.nats.subscribe('scan.completed', async (data) => {
      // Notify active chat sessions about new scan results
      this.io.emit('system_update', {
        type: 'scan_completed',
        data,
        timestamp: new Date().toISOString()
      });
    });

    // Subscribe to risk updates
    await this.nats.subscribe('risk.updated', async (data) => {
      this.io.emit('system_update', {
        type: 'risk_updated',
        data,
        timestamp: new Date().toISOString()
      });
    });
  }

  async stop() {
    try {
      this.server.close();
      await this.nats.disconnect();
      this.logger.info('Chat service stopped');
    } catch (error) {
      this.logger.error('Error stopping chat service:', error);
    }
  }
}

// Start service if called directly
if (require.main === module) {
  const chatService = new ChatService();
  
  chatService.start().catch((error) => {
    console.error('Failed to start chat service:', error);
    process.exit(1);
  });

  // Graceful shutdown
  process.on('SIGINT', async () => {
    console.log('Shutting down chat service...');
    await chatService.stop();
    process.exit(0);
  });
}

module.exports = ChatService;