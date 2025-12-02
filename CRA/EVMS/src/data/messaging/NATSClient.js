// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// NATS client wrapper

const { connect, StringCodec, JSONCodec, headers } = require('nats');
const logger = require('../../utils/logger');
const config = require('../../config');

class NATSClient {
  constructor() {
    this.connection = null;
    this.jetstream = null;
    this.kv = null;
    this.stringCodec = StringCodec();
    this.jsonCodec = JSONCodec();
    this.connected = false;
    this.reconnecting = false;
  }

  async connect() {
    try {
      const natsConfig = config.get('messaging.nats');
      
      logger.info('Connecting to NATS server', { servers: natsConfig.servers });
      
      this.connection = await connect({
        servers: natsConfig.servers,
        name: natsConfig.name,
        maxReconnectAttempts: natsConfig.maxReconnectAttempts,
        reconnectTimeWait: natsConfig.reconnectTimeWait,
        timeout: natsConfig.timeout,
        pingInterval: natsConfig.pingInterval,
        maxPingOut: natsConfig.maxPingOut,
        verbose: natsConfig.verbose,
        pedantic: natsConfig.pedantic,
      });

      // Set up connection event handlers
      this.setupEventHandlers();

      // Initialize JetStream
      await this.initializeJetStream();

      // Initialize Key-Value store
      await this.initializeKV();

      this.connected = true;
      logger.info('Successfully connected to NATS server');
      
      return this.connection;
    } catch (error) {
      logger.error('Failed to connect to NATS server', { error: error.message });
      throw error;
    }
  }

  setupEventHandlers() {
    // Connection closed
    this.connection.closed().then((err) => {
      this.connected = false;
      if (err) {
        logger.error('NATS connection closed with error', { error: err.message });
      } else {
        logger.info('NATS connection closed gracefully');
      }
    });

    // Handle reconnection events
    (async () => {
      for await (const s of this.connection.status()) {
        switch (s.type) {
          case 'disconnect':
            logger.warn('NATS disconnected', { data: s.data });
            this.connected = false;
            break;
          case 'reconnecting':
            logger.info('NATS reconnecting', { data: s.data });
            this.reconnecting = true;
            break;
          case 'reconnect':
            logger.info('NATS reconnected', { data: s.data });
            this.connected = true;
            this.reconnecting = false;
            break;
          case 'error':
            logger.error('NATS connection error', { error: s.data });
            break;
        }
      }
    })();
  }

  async initializeJetStream() {
    try {
      this.jetstream = this.connection.jetstream();
      
      const streamConfig = config.get('messaging.streams.evms');
      
      // Create or update the stream
      const jsm = await this.connection.jetstreamManager();
      
      try {
        await jsm.streams.info(streamConfig.name);
        logger.info('JetStream stream already exists', { stream: streamConfig.name });
      } catch (err) {
        if (err.message.includes('stream not found')) {
          await jsm.streams.add({
            name: streamConfig.name,
            subjects: streamConfig.subjects,
            retention: streamConfig.retention,
            max_consumers: streamConfig.maxConsumers,
            max_msgs: streamConfig.maxMsgs,
            max_bytes: streamConfig.maxBytes,
            max_age: streamConfig.maxAge,
            max_msg_size: streamConfig.maxMsgSize,
            storage: streamConfig.storage,
            num_replicas: streamConfig.replicas,
            duplicate_window: streamConfig.duplicateWindow,
          });
          logger.info('Created JetStream stream', { stream: streamConfig.name });
        } else {
          throw err;
        }
      }
    } catch (error) {
      logger.error('Failed to initialize JetStream', { error: error.message });
      throw error;
    }
  }

  async initializeKV() {
    try {
      const kvConfig = config.get('messaging.kv');
      const jsm = await this.connection.jetstreamManager();
      
      try {
        this.kv = await jsm.views.kv(kvConfig.bucket);
        logger.info('Connected to existing KV bucket', { bucket: kvConfig.bucket });
      } catch (err) {
        if (err.message.includes('bucket not found')) {
          this.kv = await jsm.views.kv(kvConfig.bucket, {
            description: kvConfig.description,
            max_value_size: kvConfig.maxValueSize,
            history: kvConfig.history,
            ttl: kvConfig.ttl,
            max_bytes: kvConfig.maxBytes,
            storage: kvConfig.storage,
            num_replicas: kvConfig.replicas,
          });
          logger.info('Created KV bucket', { bucket: kvConfig.bucket });
        } else {
          throw err;
        }
      }
    } catch (error) {
      logger.error('Failed to initialize KV store', { error: error.message });
      throw error;
    }
  }

  // Publish message to subject
  async publish(subject, data, options = {}) {
    if (!this.connected) {
      throw new Error('NATS client not connected');
    }

    try {
      const payload = typeof data === 'string' ? 
        this.stringCodec.encode(data) : 
        this.jsonCodec.encode(data);

      const h = options.headers ? headers(options.headers) : undefined;
      
      await this.connection.publish(subject, payload, { headers: h });
      
      logger.debug('Published message', { subject, dataType: typeof data });
    } catch (error) {
      logger.error('Failed to publish message', { 
        subject, 
        error: error.message 
      });
      throw error;
    }
  }

  // Publish message to JetStream
  async publishJS(subject, data, options = {}) {
    if (!this.jetstream) {
      throw new Error('JetStream not initialized');
    }

    try {
      const payload = typeof data === 'string' ? 
        this.stringCodec.encode(data) : 
        this.jsonCodec.encode(data);

      const h = options.headers ? headers(options.headers) : undefined;
      
      const ack = await this.jetstream.publish(subject, payload, { 
        headers: h,
        msgID: options.msgID,
        expect: options.expect
      });
      
      logger.debug('Published JetStream message', { 
        subject, 
        sequence: ack.seq,
        duplicate: ack.duplicate 
      });
      
      return ack;
    } catch (error) {
      logger.error('Failed to publish JetStream message', { 
        subject, 
        error: error.message 
      });
      throw error;
    }
  }

  // Subscribe to subject
  subscribe(subject, callback, options = {}) {
    if (!this.connected) {
      throw new Error('NATS client not connected');
    }

    const sub = this.connection.subscribe(subject, {
      queue: options.queue,
      max: options.max
    });

    (async () => {
      for await (const msg of sub) {
        try {
          let data;
          try {
            data = this.jsonCodec.decode(msg.data);
          } catch {
            data = this.stringCodec.decode(msg.data);
          }

          await callback(data, msg);
          
          logger.debug('Processed message', { 
            subject: msg.subject, 
            reply: msg.reply 
          });
        } catch (error) {
          logger.error('Error processing message', { 
            subject: msg.subject, 
            error: error.message 
          });
        }
      }
    })();

    return sub;
  }

  // Subscribe to JetStream consumer
  async subscribeJS(subject, callback, options = {}) {
    if (!this.jetstream) {
      throw new Error('JetStream not initialized');
    }

    try {
      const consumer = await this.jetstream.consumers.get(
        config.get('messaging.streams.evms.name'),
        options.consumer || `${subject.replace(/\./g, '_')}_consumer`
      );

      const messages = await consumer.consume({
        max_messages: options.maxMessages || 100,
        expires: options.expires || 30000
      });

      (async () => {
        for await (const msg of messages) {
          try {
            let data;
            try {
              data = this.jsonCodec.decode(msg.data);
            } catch {
              data = this.stringCodec.decode(msg.data);
            }

            await callback(data, msg);
            msg.ack();
            
            logger.debug('Processed JetStream message', { 
              subject: msg.subject,
              sequence: msg.seq
            });
          } catch (error) {
            logger.error('Error processing JetStream message', { 
              subject: msg.subject, 
              error: error.message 
            });
            msg.nak();
          }
        }
      })();

      return messages;
    } catch (error) {
      logger.error('Failed to subscribe to JetStream', { 
        subject, 
        error: error.message 
      });
      throw error;
    }
  }

  // Request-reply pattern
  async request(subject, data, options = {}) {
    if (!this.connected) {
      throw new Error('NATS client not connected');
    }

    try {
      const payload = typeof data === 'string' ? 
        this.stringCodec.encode(data) : 
        this.jsonCodec.encode(data);

      const response = await this.connection.request(subject, payload, {
        timeout: options.timeout || 5000,
        headers: options.headers ? headers(options.headers) : undefined
      });

      let responseData;
      try {
        responseData = this.jsonCodec.decode(response.data);
      } catch {
        responseData = this.stringCodec.decode(response.data);
      }

      logger.debug('Request-reply completed', { subject });
      return responseData;
    } catch (error) {
      logger.error('Request-reply failed', { 
        subject, 
        error: error.message 
      });
      throw error;
    }
  }

  // Key-Value operations
  async kvPut(key, value, options = {}) {
    if (!this.kv) {
      throw new Error('KV store not initialized');
    }

    try {
      const result = await this.kv.put(key, this.jsonCodec.encode(value), {
        previousSeq: options.previousSeq
      });
      
      logger.debug('KV put operation', { key, sequence: result });
      return result;
    } catch (error) {
      logger.error('KV put failed', { key, error: error.message });
      throw error;
    }
  }

  async kvGet(key) {
    if (!this.kv) {
      throw new Error('KV store not initialized');
    }

    try {
      const entry = await this.kv.get(key);
      if (!entry) {
        return null;
      }

      const value = this.jsonCodec.decode(entry.value);
      logger.debug('KV get operation', { key, sequence: entry.seq });
      return { value, seq: entry.seq, created: entry.created };
    } catch (error) {
      if (error.message.includes('key not found')) {
        return null;
      }
      logger.error('KV get failed', { key, error: error.message });
      throw error;
    }
  }

  async kvDelete(key) {
    if (!this.kv) {
      throw new Error('KV store not initialized');
    }

    try {
      await this.kv.delete(key);
      logger.debug('KV delete operation', { key });
    } catch (error) {
      logger.error('KV delete failed', { key, error: error.message });
      throw error;
    }
  }

  async kvList(prefix = '') {
    if (!this.kv) {
      throw new Error('KV store not initialized');
    }

    try {
      const keys = [];
      const iter = await this.kv.keys(prefix);
      for await (const key of iter) {
        keys.push(key);
      }
      
      logger.debug('KV list operation', { prefix, count: keys.length });
      return keys;
    } catch (error) {
      logger.error('KV list failed', { prefix, error: error.message });
      throw error;
    }
  }

  // Health check
  async healthCheck() {
    try {
      if (!this.connected) {
        return { healthy: false, error: 'Not connected' };
      }

      // Test basic connectivity
      await this.connection.flush();

      // Test JetStream
      if (this.jetstream) {
        const jsm = await this.connection.jetstreamManager();
        await jsm.streams.info(config.get('messaging.streams.evms.name'));
      }

      // Test KV store
      if (this.kv) {
        await this.kvPut('health_check', { timestamp: Date.now() });
        await this.kvGet('health_check');
      }

      return { healthy: true };
    } catch (error) {
      logger.error('NATS health check failed', { error: error.message });
      return { healthy: false, error: error.message };
    }
  }

  // Graceful shutdown
  async close() {
    try {
      if (this.connection) {
        await this.connection.drain();
        await this.connection.close();
        this.connected = false;
        logger.info('NATS connection closed gracefully');
      }
    } catch (error) {
      logger.error('Error closing NATS connection', { error: error.message });
      throw error;
    }
  }

  // Getters
  isConnected() {
    return this.connected;
  }

  isReconnecting() {
    return this.reconnecting;
  }

  getConnection() {
    return this.connection;
  }

  getJetStream() {
    return this.jetstream;
  }

  getKV() {
    return this.kv;
  }
}

module.exports = NATSClient;
