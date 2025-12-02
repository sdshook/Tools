// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Orchestrator service

const logger = require('../../utils/logger');
const config = require('../../config');
const { v4: uuidv4 } = require('uuid');

class OrchestratorService {
  constructor(natsClient, graphDB) {
    this.natsClient = natsClient;
    this.graphDB = graphDB;
    this.initialized = false;
    this.running = false;
    this.activeTasks = new Map();
    this.taskQueue = [];
    this.agents = new Map();
    this.scanSchedules = new Map();
  }

  async initialize() {
    try {
      logger.info('Initializing Orchestrator Service');
      
      // Subscribe to agent registration messages
      this.natsClient.subscribe('evms.agents.register', this.handleAgentRegistration.bind(this));
      
      // Subscribe to agent heartbeats
      this.natsClient.subscribe('evms.agents.heartbeat', this.handleAgentHeartbeat.bind(this));
      
      // Subscribe to task completion messages
      this.natsClient.subscribe('evms.tasks.completed', this.handleTaskCompletion.bind(this));
      
      // Subscribe to scan requests
      this.natsClient.subscribe('evms.scans.request', this.handleScanRequest.bind(this));
      
      // Subscribe to HOTL decisions
      this.natsClient.subscribe('evms.hotl.decision', this.handleHOTLDecision.bind(this));
      
      this.initialized = true;
      logger.info('Orchestrator Service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Orchestrator Service', { error: error.message });
      throw error;
    }
  }

  async start() {
    try {
      if (!this.initialized) {
        throw new Error('Orchestrator Service not initialized');
      }

      if (this.running) {
        logger.warn('Orchestrator Service is already running');
        return;
      }

      logger.info('Starting Orchestrator Service');
      
      this.running = true;
      
      // Start task processing loop
      this.startTaskProcessor();
      
      // Start agent health monitoring
      this.startAgentHealthMonitoring();
      
      // Start scheduled scan processor
      this.startScheduledScanProcessor();
      
      logger.info('Orchestrator Service started successfully');
    } catch (error) {
      logger.error('Failed to start Orchestrator Service', { error: error.message });
      throw error;
    }
  }

  async stop() {
    try {
      logger.info('Stopping Orchestrator Service');
      
      this.running = false;
      
      // Cancel all active tasks
      for (const [taskId, task] of this.activeTasks) {
        try {
          await this.cancelTask(taskId);
        } catch (error) {
          logger.error(`Failed to cancel task ${taskId}`, { error: error.message });
        }
      }
      
      this.activeTasks.clear();
      this.taskQueue = [];
      this.agents.clear();
      this.scanSchedules.clear();
      
      logger.info('Orchestrator Service stopped successfully');
    } catch (error) {
      logger.error('Failed to stop Orchestrator Service', { error: error.message });
      throw error;
    }
  }

  // Agent Management
  async handleAgentRegistration(data, msg) {
    try {
      const { agentId, capabilities, version, hostname } = data;
      
      logger.info('Agent registration received', { agentId, capabilities, hostname });
      
      const agent = {
        id: agentId,
        capabilities,
        version,
        hostname,
        status: 'active',
        lastHeartbeat: new Date(),
        registeredAt: new Date(),
        tasksAssigned: 0,
        tasksCompleted: 0
      };
      
      this.agents.set(agentId, agent);
      
      // Acknowledge registration
      await this.natsClient.publish(msg.reply, {
        success: true,
        message: 'Agent registered successfully',
        agentId
      });
      
      logger.info('Agent registered successfully', { agentId });
    } catch (error) {
      logger.error('Failed to handle agent registration', { error: error.message });
      
      if (msg.reply) {
        await this.natsClient.publish(msg.reply, {
          success: false,
          error: error.message
        });
      }
    }
  }

  async handleAgentHeartbeat(data, msg) {
    try {
      const { agentId, status, metrics } = data;
      
      const agent = this.agents.get(agentId);
      if (!agent) {
        logger.warn('Heartbeat from unknown agent', { agentId });
        return;
      }
      
      agent.lastHeartbeat = new Date();
      agent.status = status;
      agent.metrics = metrics;
      
      logger.debug('Agent heartbeat received', { agentId, status });
    } catch (error) {
      logger.error('Failed to handle agent heartbeat', { error: error.message });
    }
  }

  // Task Management
  async createTask(taskData) {
    try {
      const taskId = uuidv4();
      const task = {
        id: taskId,
        type: taskData.type,
        priority: taskData.priority || 'medium',
        targets: taskData.targets,
        parameters: taskData.parameters || {},
        status: 'pending',
        createdAt: new Date(),
        assignedAgent: null,
        retryCount: 0,
        maxRetries: taskData.maxRetries || 3
      };
      
      this.taskQueue.push(task);
      
      // Store task in graph database
      await this.graphDB.runQuery(
        `CREATE (t:Task {
          id: $id,
          type: $type,
          priority: $priority,
          status: $status,
          createdAt: datetime($createdAt),
          targets: $targets,
          parameters: $parameters
        }) RETURN t`,
        {
          id: taskId,
          type: task.type,
          priority: task.priority,
          status: task.status,
          createdAt: task.createdAt.toISOString(),
          targets: JSON.stringify(task.targets),
          parameters: JSON.stringify(task.parameters)
        }
      );
      
      logger.info('Task created', { taskId, type: task.type, priority: task.priority });
      
      return task;
    } catch (error) {
      logger.error('Failed to create task', { error: error.message });
      throw error;
    }
  }

  async assignTask(task) {
    try {
      // Find suitable agent
      const suitableAgent = this.findSuitableAgent(task);
      
      if (!suitableAgent) {
        logger.warn('No suitable agent found for task', { taskId: task.id, type: task.type });
        return false;
      }
      
      task.status = 'assigned';
      task.assignedAgent = suitableAgent.id;
      task.assignedAt = new Date();
      
      this.activeTasks.set(task.id, task);
      suitableAgent.tasksAssigned++;
      
      // Send task to agent
      await this.natsClient.publishJS(`evms.agents.${suitableAgent.id}.tasks`, {
        taskId: task.id,
        type: task.type,
        targets: task.targets,
        parameters: task.parameters,
        priority: task.priority
      });
      
      // Update task status in database
      await this.graphDB.runQuery(
        `MATCH (t:Task {id: $taskId})
         SET t.status = $status, t.assignedAgent = $agentId, t.assignedAt = datetime($assignedAt)
         RETURN t`,
        {
          taskId: task.id,
          status: task.status,
          agentId: suitableAgent.id,
          assignedAt: task.assignedAt.toISOString()
        }
      );
      
      logger.info('Task assigned to agent', { 
        taskId: task.id, 
        agentId: suitableAgent.id,
        type: task.type 
      });
      
      return true;
    } catch (error) {
      logger.error('Failed to assign task', { taskId: task.id, error: error.message });
      return false;
    }
  }

  findSuitableAgent(task) {
    const availableAgents = Array.from(this.agents.values())
      .filter(agent => 
        agent.status === 'active' && 
        this.agentHasCapability(agent, task.type) &&
        this.isAgentHealthy(agent)
      )
      .sort((a, b) => a.tasksAssigned - b.tasksAssigned); // Load balancing
    
    return availableAgents[0] || null;
  }

  agentHasCapability(agent, taskType) {
    if (!agent.capabilities || !Array.isArray(agent.capabilities)) {
      return false;
    }
    
    return agent.capabilities.includes(taskType) || agent.capabilities.includes('*');
  }

  isAgentHealthy(agent) {
    const now = new Date();
    const heartbeatThreshold = 60000; // 1 minute
    
    return (now - agent.lastHeartbeat) < heartbeatThreshold;
  }

  async handleTaskCompletion(data, msg) {
    try {
      const { taskId, agentId, status, results, error } = data;
      
      const task = this.activeTasks.get(taskId);
      if (!task) {
        logger.warn('Task completion for unknown task', { taskId });
        return;
      }
      
      const agent = this.agents.get(agentId);
      if (agent) {
        agent.tasksCompleted++;
      }
      
      task.status = status;
      task.completedAt = new Date();
      task.results = results;
      task.error = error;
      
      if (status === 'completed') {
        logger.info('Task completed successfully', { taskId, agentId });
        
        // Process results
        await this.processTaskResults(task);
        
        // Remove from active tasks
        this.activeTasks.delete(taskId);
      } else if (status === 'failed') {
        logger.warn('Task failed', { taskId, agentId, error });
        
        // Handle task failure
        await this.handleTaskFailure(task);
      }
      
      // Update task status in database
      await this.graphDB.runQuery(
        `MATCH (t:Task {id: $taskId})
         SET t.status = $status, t.completedAt = datetime($completedAt),
             t.results = $results, t.error = $error
         RETURN t`,
        {
          taskId,
          status,
          completedAt: task.completedAt.toISOString(),
          results: JSON.stringify(results || {}),
          error: error || null
        }
      );
      
    } catch (error) {
      logger.error('Failed to handle task completion', { error: error.message });
    }
  }

  async processTaskResults(task) {
    try {
      if (task.type === 'vulnerability_scan' && task.results) {
        await this.processVulnerabilityScanResults(task);
      } else if (task.type === 'asset_discovery' && task.results) {
        await this.processAssetDiscoveryResults(task);
      } else if (task.type === 'configuration_audit' && task.results) {
        await this.processConfigurationAuditResults(task);
      }
      
      // Notify GraphRL about new data
      await this.natsClient.publishJS('evms.graphrl.data_updated', {
        taskId: task.id,
        type: task.type,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Failed to process task results', { 
        taskId: task.id, 
        error: error.message 
      });
    }
  }

  async processVulnerabilityScanResults(task) {
    const { vulnerabilities, assetId } = task.results;
    
    for (const vuln of vulnerabilities) {
      // Create vulnerability in graph database
      const vulnId = uuidv4();
      await this.graphDB.createVulnerability({
        id: vulnId,
        cveId: vuln.cveId,
        title: vuln.title,
        description: vuln.description,
        severity: vuln.severity,
        cvssScore: vuln.cvssScore,
        status: 'open',
        discoveredAt: new Date().toISOString(),
        riskScore: this.calculateRiskScore(vuln)
      });
      
      // Link vulnerability to asset
      await this.graphDB.linkVulnerabilityToAsset(vulnId, assetId, task.id);
    }
    
    logger.info('Processed vulnerability scan results', { 
      taskId: task.id, 
      vulnerabilityCount: vulnerabilities.length 
    });
  }

  async processAssetDiscoveryResults(task) {
    const { assets } = task.results;
    
    for (const asset of assets) {
      const assetId = uuidv4();
      await this.graphDB.createAsset({
        id: assetId,
        hostname: asset.hostname,
        ipAddress: asset.ipAddress,
        assetType: asset.type,
        operatingSystem: asset.os,
        services: JSON.stringify(asset.services || []),
        lastSeen: new Date().toISOString(),
        riskScore: 0 // Will be calculated by GraphRL
      });
    }
    
    logger.info('Processed asset discovery results', { 
      taskId: task.id, 
      assetCount: assets.length 
    });
  }

  async processConfigurationAuditResults(task) {
    const { findings, assetId } = task.results;
    
    for (const finding of findings) {
      if (finding.severity === 'high' || finding.severity === 'critical') {
        // Create vulnerability for configuration issues
        const vulnId = uuidv4();
        await this.graphDB.createVulnerability({
          id: vulnId,
          cveId: null,
          title: finding.title,
          description: finding.description,
          severity: finding.severity,
          cvssScore: finding.score || 0,
          status: 'open',
          discoveredAt: new Date().toISOString(),
          riskScore: this.calculateRiskScore(finding)
        });
        
        await this.graphDB.linkVulnerabilityToAsset(vulnId, assetId, task.id);
      }
    }
    
    logger.info('Processed configuration audit results', { 
      taskId: task.id, 
      findingCount: findings.length 
    });
  }

  calculateRiskScore(vulnerability) {
    let score = vulnerability.cvssScore || 0;
    
    // Adjust based on severity
    const severityMultipliers = {
      'critical': 1.0,
      'high': 0.8,
      'medium': 0.6,
      'low': 0.4,
      'info': 0.2
    };
    
    score *= severityMultipliers[vulnerability.severity] || 0.5;
    
    // Additional factors can be added here
    
    return Math.min(score, 10.0);
  }

  async handleTaskFailure(task) {
    task.retryCount++;
    
    if (task.retryCount < task.maxRetries) {
      // Retry the task
      task.status = 'pending';
      task.assignedAgent = null;
      this.taskQueue.push(task);
      this.activeTasks.delete(task.id);
      
      logger.info('Task queued for retry', { 
        taskId: task.id, 
        retryCount: task.retryCount 
      });
    } else {
      // Mark as permanently failed
      task.status = 'failed_permanently';
      this.activeTasks.delete(task.id);
      
      logger.error('Task failed permanently', { 
        taskId: task.id, 
        retryCount: task.retryCount 
      });
    }
  }

  // Scan Request Handling
  async handleScanRequest(data, msg) {
    try {
      const { type, targets, priority, parameters } = data;
      
      logger.info('Scan request received', { type, targets, priority });
      
      const task = await this.createTask({
        type,
        targets,
        priority,
        parameters
      });
      
      // Acknowledge scan request
      if (msg.reply) {
        await this.natsClient.publish(msg.reply, {
          success: true,
          taskId: task.id,
          message: 'Scan request queued successfully'
        });
      }
      
    } catch (error) {
      logger.error('Failed to handle scan request', { error: error.message });
      
      if (msg.reply) {
        await this.natsClient.publish(msg.reply, {
          success: false,
          error: error.message
        });
      }
    }
  }

  // HOTL Decision Handling
  async handleHOTLDecision(data, msg) {
    try {
      const { taskId, decision, feedback } = data;
      
      logger.info('HOTL decision received', { taskId, decision });
      
      // Process the decision
      if (decision === 'approve') {
        // Continue with automated actions
        await this.natsClient.publishJS('evms.graphrl.decision_approved', {
          taskId,
          feedback,
          timestamp: new Date().toISOString()
        });
      } else if (decision === 'reject') {
        // Stop automated actions
        await this.natsClient.publishJS('evms.graphrl.decision_rejected', {
          taskId,
          feedback,
          timestamp: new Date().toISOString()
        });
      }
      
    } catch (error) {
      logger.error('Failed to handle HOTL decision', { error: error.message });
    }
  }

  // Background Processes
  startTaskProcessor() {
    const processInterval = setInterval(async () => {
      if (!this.running) {
        clearInterval(processInterval);
        return;
      }
      
      try {
        // Process pending tasks
        while (this.taskQueue.length > 0) {
          const task = this.taskQueue.shift();
          const assigned = await this.assignTask(task);
          
          if (!assigned) {
            // Put task back in queue if no agent available
            this.taskQueue.unshift(task);
            break;
          }
        }
      } catch (error) {
        logger.error('Error in task processor', { error: error.message });
      }
    }, 5000); // Process every 5 seconds
  }

  startAgentHealthMonitoring() {
    const monitorInterval = setInterval(() => {
      if (!this.running) {
        clearInterval(monitorInterval);
        return;
      }
      
      const now = new Date();
      const healthThreshold = 120000; // 2 minutes
      
      for (const [agentId, agent] of this.agents) {
        if ((now - agent.lastHeartbeat) > healthThreshold) {
          logger.warn('Agent appears unhealthy', { agentId, lastHeartbeat: agent.lastHeartbeat });
          agent.status = 'unhealthy';
          
          // Reassign tasks from unhealthy agent
          this.reassignTasksFromAgent(agentId);
        }
      }
    }, 30000); // Check every 30 seconds
  }

  startScheduledScanProcessor() {
    const scheduleInterval = setInterval(async () => {
      if (!this.running) {
        clearInterval(scheduleInterval);
        return;
      }
      
      try {
        // Process scheduled scans
        const now = new Date();
        
        for (const [scheduleId, schedule] of this.scanSchedules) {
          if (schedule.nextRun <= now) {
            await this.createTask({
              type: schedule.scanType,
              targets: schedule.targets,
              priority: schedule.priority,
              parameters: schedule.parameters
            });
            
            // Update next run time
            schedule.nextRun = new Date(now.getTime() + schedule.interval);
            
            logger.info('Scheduled scan triggered', { scheduleId, scanType: schedule.scanType });
          }
        }
      } catch (error) {
        logger.error('Error in scheduled scan processor', { error: error.message });
      }
    }, 60000); // Check every minute
  }

  async reassignTasksFromAgent(agentId) {
    const tasksToReassign = Array.from(this.activeTasks.values())
      .filter(task => task.assignedAgent === agentId);
    
    for (const task of tasksToReassign) {
      task.status = 'pending';
      task.assignedAgent = null;
      this.taskQueue.push(task);
      this.activeTasks.delete(task.id);
      
      logger.info('Task reassigned due to agent failure', { 
        taskId: task.id, 
        failedAgent: agentId 
      });
    }
  }

  async cancelTask(taskId) {
    const task = this.activeTasks.get(taskId);
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }
    
    if (task.assignedAgent) {
      // Send cancellation message to agent
      await this.natsClient.publish(`evms.agents.${task.assignedAgent}.cancel`, {
        taskId
      });
    }
    
    task.status = 'cancelled';
    this.activeTasks.delete(taskId);
    
    logger.info('Task cancelled', { taskId });
  }

  // Health check
  async healthCheck() {
    try {
      const activeAgents = Array.from(this.agents.values())
        .filter(agent => agent.status === 'active').length;
      
      const healthyAgents = Array.from(this.agents.values())
        .filter(agent => this.isAgentHealthy(agent)).length;
      
      return {
        healthy: this.running && this.initialized,
        agents: {
          total: this.agents.size,
          active: activeAgents,
          healthy: healthyAgents
        },
        tasks: {
          active: this.activeTasks.size,
          queued: this.taskQueue.length
        }
      };
    } catch (error) {
      return { healthy: false, error: error.message };
    }
  }

  // Getters
  getActiveTasks() {
    return Array.from(this.activeTasks.values());
  }

  getQueuedTasks() {
    return [...this.taskQueue];
  }

  getAgents() {
    return Array.from(this.agents.values());
  }
}

module.exports = OrchestratorService;
