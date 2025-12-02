// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Agent management service

const logger = require('../../utils/logger');
const config = require('../../config');
const VulnerabilityScanner = require('./vulnerability/VulnScanner');
const AssetDiscoveryAgent = require('./discovery/NetworkDiscovery');
const ConfigurationAuditor = require('./configuration/ConfigAuditor');
const { v4: uuidv4 } = require('uuid');

class AgentManager {
  constructor(natsClient, graphDB) {
    this.natsClient = natsClient;
    this.graphDB = graphDB;
    this.initialized = false;
    this.running = false;
    this.agents = new Map();
    this.agentId = uuidv4();
    this.capabilities = ['vulnerability_scan', 'asset_discovery', 'configuration_audit'];
    this.heartbeatInterval = null;
  }

  async initialize() {
    try {
      logger.info('Initializing Agent Manager');
      
      // Initialize scanner agents
      this.agents.set('vulnerability_scanner', new VulnerabilityScanner(this.natsClient, this.graphDB));
      this.agents.set('asset_discovery', new AssetDiscoveryAgent(this.natsClient, this.graphDB));
      this.agents.set('configuration_auditor', new ConfigurationAuditor(this.natsClient, this.graphDB));
      
      // Initialize all agents
      for (const [name, agent] of this.agents) {
        await agent.initialize();
        logger.info(`Initialized agent: ${name}`);
      }
      
      // Subscribe to task assignments
      this.natsClient.subscribe(`evms.agents.${this.agentId}.tasks`, this.handleTaskAssignment.bind(this));
      
      // Subscribe to task cancellations
      this.natsClient.subscribe(`evms.agents.${this.agentId}.cancel`, this.handleTaskCancellation.bind(this));
      
      this.initialized = true;
      logger.info('Agent Manager initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Agent Manager', { error: error.message });
      throw error;
    }
  }

  async start() {
    try {
      if (!this.initialized) {
        throw new Error('Agent Manager not initialized');
      }

      if (this.running) {
        logger.warn('Agent Manager is already running');
        return;
      }

      logger.info('Starting Agent Manager');
      
      this.running = true;
      
      // Register with orchestrator
      await this.registerWithOrchestrator();
      
      // Start heartbeat
      this.startHeartbeat();
      
      // Start all agents
      for (const [name, agent] of this.agents) {
        await agent.start();
        logger.info(`Started agent: ${name}`);
      }
      
      logger.info('Agent Manager started successfully');
    } catch (error) {
      logger.error('Failed to start Agent Manager', { error: error.message });
      throw error;
    }
  }

  async stop() {
    try {
      logger.info('Stopping Agent Manager');
      
      this.running = false;
      
      // Stop heartbeat
      if (this.heartbeatInterval) {
        clearInterval(this.heartbeatInterval);
        this.heartbeatInterval = null;
      }
      
      // Stop all agents
      for (const [name, agent] of this.agents) {
        try {
          await agent.stop();
          logger.info(`Stopped agent: ${name}`);
        } catch (error) {
          logger.error(`Failed to stop agent ${name}`, { error: error.message });
        }
      }
      
      logger.info('Agent Manager stopped successfully');
    } catch (error) {
      logger.error('Failed to stop Agent Manager', { error: error.message });
      throw error;
    }
  }

  async registerWithOrchestrator() {
    try {
      logger.info('Registering with orchestrator', { agentId: this.agentId });
      
      const response = await this.natsClient.request('evms.agents.register', {
        agentId: this.agentId,
        capabilities: this.capabilities,
        version: '1.0.0',
        hostname: require('os').hostname()
      });
      
      if (response.success) {
        logger.info('Successfully registered with orchestrator', { agentId: this.agentId });
      } else {
        throw new Error(`Registration failed: ${response.error}`);
      }
    } catch (error) {
      logger.error('Failed to register with orchestrator', { error: error.message });
      throw error;
    }
  }

  startHeartbeat() {
    this.heartbeatInterval = setInterval(async () => {
      if (!this.running) {
        return;
      }
      
      try {
        const metrics = this.getMetrics();
        
        await this.natsClient.publish('evms.agents.heartbeat', {
          agentId: this.agentId,
          status: 'active',
          metrics,
          timestamp: new Date().toISOString()
        });
        
        logger.debug('Heartbeat sent', { agentId: this.agentId });
      } catch (error) {
        logger.error('Failed to send heartbeat', { error: error.message });
      }
    }, 30000); // Send heartbeat every 30 seconds
  }

  async handleTaskAssignment(data, msg) {
    try {
      const { taskId, type, targets, parameters, priority } = data;
      
      logger.info('Task assignment received', { taskId, type, targets, priority });
      
      // Find appropriate agent for the task
      const agent = this.findAgentForTask(type);
      
      if (!agent) {
        logger.error('No suitable agent found for task type', { taskId, type });
        
        await this.natsClient.publishJS('evms.tasks.completed', {
          taskId,
          agentId: this.agentId,
          status: 'failed',
          error: `No suitable agent found for task type: ${type}`
        });
        return;
      }
      
      // Execute the task
      try {
        const results = await agent.executeTask({
          taskId,
          type,
          targets,
          parameters,
          priority
        });
        
        // Report task completion
        await this.natsClient.publishJS('evms.tasks.completed', {
          taskId,
          agentId: this.agentId,
          status: 'completed',
          results
        });
        
        logger.info('Task completed successfully', { taskId, type });
      } catch (taskError) {
        logger.error('Task execution failed', { taskId, type, error: taskError.message });
        
        await this.natsClient.publishJS('evms.tasks.completed', {
          taskId,
          agentId: this.agentId,
          status: 'failed',
          error: taskError.message
        });
      }
      
    } catch (error) {
      logger.error('Failed to handle task assignment', { error: error.message });
    }
  }

  async handleTaskCancellation(data, msg) {
    try {
      const { taskId } = data;
      
      logger.info('Task cancellation received', { taskId });
      
      // Cancel task in all agents
      for (const [name, agent] of this.agents) {
        if (typeof agent.cancelTask === 'function') {
          try {
            await agent.cancelTask(taskId);
          } catch (error) {
            logger.warn(`Failed to cancel task in agent ${name}`, { 
              taskId, 
              error: error.message 
            });
          }
        }
      }
      
      logger.info('Task cancellation processed', { taskId });
    } catch (error) {
      logger.error('Failed to handle task cancellation', { error: error.message });
    }
  }

  findAgentForTask(taskType) {
    switch (taskType) {
      case 'vulnerability_scan':
        return this.agents.get('vulnerability_scanner');
      case 'asset_discovery':
        return this.agents.get('asset_discovery');
      case 'configuration_audit':
        return this.agents.get('configuration_auditor');
      default:
        return null;
    }
  }

  getMetrics() {
    const metrics = {
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      cpuUsage: process.cpuUsage(),
      activeAgents: Array.from(this.agents.keys()),
      timestamp: new Date().toISOString()
    };
    
    // Add agent-specific metrics
    for (const [name, agent] of this.agents) {
      if (typeof agent.getMetrics === 'function') {
        metrics[name] = agent.getMetrics();
      }
    }
    
    return metrics;
  }

  // Health check
  async healthCheck() {
    try {
      const agentHealth = {};
      
      for (const [name, agent] of this.agents) {
        if (typeof agent.healthCheck === 'function') {
          agentHealth[name] = await agent.healthCheck();
        } else {
          agentHealth[name] = { healthy: true };
        }
      }
      
      const allHealthy = Object.values(agentHealth).every(health => health.healthy);
      
      return {
        healthy: this.running && this.initialized && allHealthy,
        agentId: this.agentId,
        agents: agentHealth,
        capabilities: this.capabilities
      };
    } catch (error) {
      return { healthy: false, error: error.message };
    }
  }

  // Getters
  getAgentId() {
    return this.agentId;
  }

  getCapabilities() {
    return [...this.capabilities];
  }

  getAgents() {
    return Array.from(this.agents.keys());
  }
}

module.exports = AgentManager;
