// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Main application entry point

const logger = require('./utils/logger');
const config = require('./config');
const NATSClient = require('./data/messaging/NATSClient');
const GraphDB = require('./data/graph/GraphDB');

class EVMSApplication {
  constructor() {
    this.services = new Map();
    this.running = false;
    this.natsClient = null;
    this.graphDB = null;
  }

  async initialize() {
    try {
      logger.info('Initializing EVMS application');
      
      // Initialize configuration
      await config.initialize();
      
      // Initialize logger with config
      const loggingConfig = config.get('logging');
      logger.initialize(loggingConfig);
      
      // Initialize core infrastructure
      await this.initializeInfrastructure();
      
      logger.info('EVMS application initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize EVMS application', { error: error.message });
      throw error;
    }
  }

  async initializeInfrastructure() {
    try {
      logger.info('Initializing core infrastructure');

      // Initialize NATS messaging
      this.natsClient = new NATSClient();
      await this.natsClient.connect();
      this.services.set('nats', this.natsClient);

      // Initialize Graph Database
      this.graphDB = new GraphDB();
      await this.graphDB.connect();
      this.services.set('graphdb', this.graphDB);

      logger.info('Core infrastructure initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize core infrastructure', { error: error.message });
      throw error;
    }
  }

  async initializeServices() {
    try {
      logger.info('Initializing application services');

      // Initialize Orchestrator Service
      const OrchestratorService = require('./services/orchestrator');
      const orchestrator = new OrchestratorService(this.natsClient, this.graphDB);
      await orchestrator.initialize();
      this.services.set('orchestrator', orchestrator);

      // Initialize Agent Manager
      const AgentManager = require('./services/agents');
      const agentManager = new AgentManager(this.natsClient, this.graphDB);
      await agentManager.initialize();
      this.services.set('agents', agentManager);

      // Initialize HOTL Service
      const HOTLService = require('./services/hotl');
      const hotlService = new HOTLService(this.natsClient, this.graphDB);
      await hotlService.initialize();
      this.services.set('hotl', hotlService);

      // Initialize Dashboard Service
      const DashboardService = require('./services/dashboard/server');
      const dashboard = new DashboardService(this.natsClient, this.graphDB);
      await dashboard.initialize();
      this.services.set('dashboard', dashboard);

      logger.info('Application services initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize application services', { error: error.message });
      throw error;
    }
  }

  async start() {
    try {
      if (this.running) {
        logger.warn('EVMS application is already running');
        return;
      }

      await this.initialize();
      await this.initializeServices();
      
      logger.info('Starting EVMS application services');
      
      // Start all services
      for (const [name, service] of this.services) {
        if (typeof service.start === 'function') {
          logger.info(`Starting service: ${name}`);
          await service.start();
        }
      }
      
      this.running = true;
      logger.info('EVMS application started successfully');
      
      // Setup graceful shutdown
      this.setupGracefulShutdown();
      
      // Perform health checks
      await this.performHealthChecks();
      
      // Log startup summary
      this.logStartupSummary();
      
    } catch (error) {
      logger.error('Failed to start EVMS application', { error: error.message });
      await this.stop();
      throw error;
    }
  }

  async stop() {
    try {
      if (!this.running) {
        logger.warn('EVMS application is not running');
        return;
      }

      logger.info('Stopping EVMS application');
      
      // Stop services in reverse order
      const serviceEntries = Array.from(this.services.entries()).reverse();
      
      for (const [name, service] of serviceEntries) {
        try {
          if (typeof service.stop === 'function') {
            logger.info(`Stopping service: ${name}`);
            await service.stop();
          } else if (typeof service.close === 'function') {
            logger.info(`Closing service: ${name}`);
            await service.close();
          }
        } catch (error) {
          logger.error(`Failed to stop service: ${name}`, { error: error.message });
        }
      }
      
      this.services.clear();
      this.running = false;
      logger.info('EVMS application stopped successfully');
      
    } catch (error) {
      logger.error('Failed to stop EVMS application', { error: error.message });
      throw error;
    }
  }

  async performHealthChecks() {
    try {
      logger.info('Performing health checks');
      
      const healthResults = {};
      
      // Check NATS health
      if (this.natsClient) {
        healthResults.nats = await this.natsClient.healthCheck();
      }
      
      // Check GraphDB health
      if (this.graphDB) {
        healthResults.graphdb = await this.graphDB.healthCheck();
      }
      
      // Check service health
      for (const [name, service] of this.services) {
        if (typeof service.healthCheck === 'function') {
          try {
            healthResults[name] = await service.healthCheck();
          } catch (error) {
            healthResults[name] = { healthy: false, error: error.message };
          }
        }
      }
      
      const unhealthyServices = Object.entries(healthResults)
        .filter(([, result]) => !result.healthy)
        .map(([name]) => name);
      
      if (unhealthyServices.length > 0) {
        logger.warn('Some services are unhealthy', { 
          unhealthyServices,
          healthResults 
        });
      } else {
        logger.info('All services are healthy', { healthResults });
      }
      
      return healthResults;
    } catch (error) {
      logger.error('Health check failed', { error: error.message });
      return { healthy: false, error: error.message };
    }
  }

  logStartupSummary() {
    const summary = {
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      nodeVersion: process.version,
      platform: process.platform,
      architecture: process.arch,
      pid: process.pid,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      services: Array.from(this.services.keys()),
      startTime: new Date().toISOString()
    };
    
    logger.info('EVMS Application Startup Summary', summary);
  }

  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      logger.info(`Received ${signal}, shutting down gracefully`);
      try {
        await this.stop();
        process.exit(0);
      } catch (error) {
        logger.error('Error during graceful shutdown', { error: error.message });
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception', { 
        error: error.message, 
        stack: error.stack 
      });
      this.stop().finally(() => process.exit(1));
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled rejection', { 
        reason: reason?.message || reason, 
        promise: promise.toString() 
      });
      this.stop().finally(() => process.exit(1));
    });
  }

  // Service management methods
  getService(name) {
    return this.services.get(name);
  }

  isRunning() {
    return this.running;
  }

  getServices() {
    return Array.from(this.services.keys());
  }

  async restart() {
    logger.info('Restarting EVMS application');
    await this.stop();
    await this.start();
  }

  // Metrics and monitoring
  getMetrics() {
    return {
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      cpuUsage: process.cpuUsage(),
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      services: this.getServices(),
      running: this.running,
      timestamp: new Date().toISOString()
    };
  }
}

// Start the application if this file is run directly
if (require.main === module) {
  const app = new EVMSApplication();
  
  // Handle command line arguments
  const args = process.argv.slice(2);
  
  if (args.includes('--health-check')) {
    // Perform health check and exit
    app.initialize()
      .then(() => app.performHealthChecks())
      .then((results) => {
        console.log(JSON.stringify(results, null, 2));
        const allHealthy = Object.values(results).every(r => r.healthy);
        process.exit(allHealthy ? 0 : 1);
      })
      .catch((error) => {
        console.error('Health check failed:', error);
        process.exit(1);
      });
  } else {
    // Normal startup
    app.start().catch((error) => {
      console.error('Failed to start EVMS application:', error);
      process.exit(1);
    });
  }
}

module.exports = EVMSApplication;