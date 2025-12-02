// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// NATS messaging configuration

const config = require('./index');

class NATSConfig {
  constructor() {
    this.natsConfig = null;
  }

  getNATSConfig() {
    if (!this.natsConfig) {
      this.natsConfig = {
        servers: config.get('messaging.nats.servers', ['nats://localhost:4222']),
        name: config.get('messaging.nats.name', 'evms-client'),
        user: config.get('messaging.nats.user'),
        pass: config.get('messaging.nats.pass'),
        token: config.get('messaging.nats.token'),
        maxReconnectAttempts: config.get('messaging.nats.maxReconnectAttempts', -1),
        reconnectTimeWait: config.get('messaging.nats.reconnectTimeWait', 2000),
        timeout: config.get('messaging.nats.timeout', 20000),
        pingInterval: config.get('messaging.nats.pingInterval', 120000),
        maxPingOut: config.get('messaging.nats.maxPingOut', 2),
        verbose: config.get('messaging.nats.verbose', false),
        pedantic: config.get('messaging.nats.pedantic', false),
      };
    }
    return this.natsConfig;
  }

  getJetStreamConfig() {
    return {
      domain: config.get('messaging.jetstream.domain'),
      apiPrefix: config.get('messaging.jetstream.apiPrefix', '$JS.API'),
      timeout: config.get('messaging.jetstream.timeout', 5000),
    };
  }

  getStreamConfig() {
    return {
      name: config.get('messaging.streams.evms.name', 'EVMS'),
      subjects: config.get('messaging.streams.evms.subjects', [
        'evms.scans.*',
        'evms.vulnerabilities.*',
        'evms.risks.*',
        'evms.alerts.*',
        'evms.tasks.*',
        'evms.agents.*',
        'evms.graphrl.*',
        'evms.hotl.*',
      ]),
      retention: config.get('messaging.streams.evms.retention', 'limits'),
      maxConsumers: config.get('messaging.streams.evms.maxConsumers', -1),
      maxMsgs: config.get('messaging.streams.evms.maxMsgs', 1000000),
      maxBytes: config.get('messaging.streams.evms.maxBytes', -1),
      maxAge: config.get('messaging.streams.evms.maxAge', 7 * 24 * 60 * 60 * 1000000000), // 7 days in nanoseconds
      maxMsgSize: config.get('messaging.streams.evms.maxMsgSize', -1),
      storage: config.get('messaging.streams.evms.storage', 'file'),
      replicas: config.get('messaging.streams.evms.replicas', 1),
      duplicateWindow: config.get('messaging.streams.evms.duplicateWindow', 2 * 60 * 1000000000), // 2 minutes in nanoseconds
    };
  }

  getKVConfig() {
    return {
      bucket: config.get('messaging.kv.bucket', 'evms-cache'),
      description: config.get('messaging.kv.description', 'EVMS Key-Value Store'),
      maxValueSize: config.get('messaging.kv.maxValueSize', 1024 * 1024), // 1MB
      history: config.get('messaging.kv.history', 10),
      ttl: config.get('messaging.kv.ttl', 24 * 60 * 60 * 1000000000), // 24 hours in nanoseconds
      maxBytes: config.get('messaging.kv.maxBytes', 100 * 1024 * 1024), // 100MB
      storage: config.get('messaging.kv.storage', 'file'),
      replicas: config.get('messaging.kv.replicas', 1),
    };
  }

  getConsumerConfig(name) {
    const baseConfig = {
      deliverPolicy: 'new',
      ackPolicy: 'explicit',
      ackWait: 30000000000, // 30 seconds in nanoseconds
      maxDeliver: 3,
      replayPolicy: 'instant',
      maxAckPending: 1000,
    };

    const consumerConfigs = {
      'scan-processor': {
        ...baseConfig,
        filterSubject: 'evms.scans.*',
        deliverGroup: 'scan-processors',
      },
      'vulnerability-processor': {
        ...baseConfig,
        filterSubject: 'evms.vulnerabilities.*',
        deliverGroup: 'vuln-processors',
      },
      'risk-processor': {
        ...baseConfig,
        filterSubject: 'evms.risks.*',
        deliverGroup: 'risk-processors',
      },
      'alert-processor': {
        ...baseConfig,
        filterSubject: 'evms.alerts.*',
        deliverGroup: 'alert-processors',
      },
      'graphrl-processor': {
        ...baseConfig,
        filterSubject: 'evms.graphrl.*',
        deliverGroup: 'graphrl-processors',
      },
      'hotl-processor': {
        ...baseConfig,
        filterSubject: 'evms.hotl.*',
        deliverGroup: 'hotl-processors',
      },
    };

    return consumerConfigs[name] || baseConfig;
  }

  getSubjects() {
    return {
      // Scan-related subjects
      SCAN_STARTED: 'evms.scans.started',
      SCAN_COMPLETED: 'evms.scans.completed',
      SCAN_FAILED: 'evms.scans.failed',
      
      // Vulnerability subjects
      VULNERABILITY_DISCOVERED: 'evms.vulnerabilities.discovered',
      VULNERABILITY_UPDATED: 'evms.vulnerabilities.updated',
      VULNERABILITY_RESOLVED: 'evms.vulnerabilities.resolved',
      
      // Risk subjects
      RISK_CALCULATED: 'evms.risks.calculated',
      RISK_UPDATED: 'evms.risks.updated',
      RISK_ESCALATED: 'evms.risks.escalated',
      
      // Alert subjects
      ALERT_CREATED: 'evms.alerts.created',
      ALERT_ACKNOWLEDGED: 'evms.alerts.acknowledged',
      ALERT_RESOLVED: 'evms.alerts.resolved',
      
      // Task subjects
      TASK_CREATED: 'evms.tasks.created',
      TASK_ASSIGNED: 'evms.tasks.assigned',
      TASK_COMPLETED: 'evms.tasks.completed',
      
      // Agent subjects
      AGENT_REGISTERED: 'evms.agents.registered',
      AGENT_HEARTBEAT: 'evms.agents.heartbeat',
      AGENT_OFFLINE: 'evms.agents.offline',
      
      // GraphRL subjects
      GRAPHRL_PREDICTION: 'evms.graphrl.prediction',
      GRAPHRL_FEEDBACK: 'evms.graphrl.feedback',
      GRAPHRL_MODEL_UPDATE: 'evms.graphrl.model_update',
      
      // HOTL subjects
      HOTL_REVIEW_REQUEST: 'evms.hotl.review_request',
      HOTL_APPROVAL: 'evms.hotl.approval',
      HOTL_REJECTION: 'evms.hotl.rejection',
    };
  }

  validateConfig() {
    const natsConfig = this.getNATSConfig();
    
    if (!natsConfig.servers || natsConfig.servers.length === 0) {
      throw new Error('NATS servers configuration is required');
    }
    
    return true;
  }
}

module.exports = new NATSConfig();