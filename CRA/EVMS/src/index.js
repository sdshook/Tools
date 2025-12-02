// EVMS (c) Shane D. Shook, 2025 All Rights Reserved
// Main application entry point

const config = require('./config');
const logger = require('./utils/logger');
const { NATSClient } = require('./data/messaging/NATSClient');

async function startApplication() {
  try {
    logger.info('Starting EVMS Platform...');
    
    // Initialize configuration
    await config.initialize();
    
    // Initialize NATS connection
    const natsClient = new NATSClient();
    await natsClient.connect();
    
    // Start services based on configuration
    const serviceType = process.env.SERVICE_TYPE || 'all';
    
    switch (serviceType) {
      case 'orchestrator':
        const orchestrator = require('./services/orchestrator');
        await orchestrator.start();
        break;
        
      case 'agents':
        const agents = require('./services/agents');
        await agents.start();
        break;
        
      case 'dashboard':
        const dashboard = require('./services/dashboard/server');
        await dashboard.start();
        break;
        
      case 'hotl':
        const hotl = require('./services/hotl');
        await hotl.start();
        break;
        
      default:
        // Start all services
        logger.info('Starting all services...');
        const orchestrator = require('./services/orchestrator');
        const dashboard = require('./services/dashboard/server');
        const hotl = require('./services/hotl');
        
        await Promise.all([
          orchestrator.start(),
          dashboard.start(),
          hotl.start(),
        ]);
        break;
    }
    
    logger.info('EVMS Platform started successfully');
    
    // Graceful shutdown handling
    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);
    
  } catch (error) {
    logger.error('Failed to start EVMS Platform:', error);
    process.exit(1);
  }
}

async function gracefulShutdown() {
  logger.info('Shutting down EVMS Platform...');
  
  try {
    // Close NATS connection
    const natsClient = require('./data/messaging/NATSClient');
    await natsClient.disconnect();
    
    logger.info('EVMS Platform shutdown complete');
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown:', error);
    process.exit(1);
  }
}

// Start the application
if (require.main === module) {
  startApplication();
}

module.exports = { startApplication, gracefulShutdown };