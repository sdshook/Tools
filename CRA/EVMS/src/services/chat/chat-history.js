// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Chat History - Persistent chat session management

const Logger = require('../../utils/logger');
const NATSClient = require('../../utils/nats-client');

class ChatHistory {
  constructor(config = {}) {
    this.config = {
      maxHistoryLength: config.maxHistoryLength || 100,
      retentionDays: config.retentionDays || 30,
      kvBucket: config.kvBucket || 'chat-history',
      ...config
    };

    this.logger = new Logger('ChatHistory');
    this.nats = new NATSClient();
    this.kv = null;
  }

  async initialize() {
    try {
      await this.nats.connect();
      
      // Get or create KV bucket for chat history
      this.kv = await this.nats.getKVStore(this.config.kvBucket, {
        history: 10,
        ttl: this.config.retentionDays * 24 * 60 * 60 * 1000 // Convert days to ms
      });
      
      this.logger.info('Chat history initialized');
    } catch (error) {
      this.logger.error('Failed to initialize chat history:', error);
      throw error;
    }
  }

  async addMessage(sessionId, message) {
    try {
      // Get existing history
      const history = await this.getHistory(sessionId);
      
      // Add new message
      history.messages.push({
        ...message,
        timestamp: message.timestamp || new Date().toISOString()
      });
      
      // Trim history if too long
      if (history.messages.length > this.config.maxHistoryLength) {
        history.messages = history.messages.slice(-this.config.maxHistoryLength);
      }
      
      // Update metadata
      history.lastUpdated = new Date().toISOString();
      history.messageCount = history.messages.length;
      
      // Store updated history
      await this.kv.put(sessionId, JSON.stringify(history));
      
      this.logger.debug(`Added message to session ${sessionId}`, {
        messageId: message.id,
        type: message.type
      });
      
      return message;
      
    } catch (error) {
      this.logger.error('Failed to add message:', error);
      throw error;
    }
  }

  async getHistory(sessionId) {
    try {
      const entry = await this.kv.get(sessionId);
      
      if (entry && entry.value) {
        const history = JSON.parse(entry.value.toString());
        return history;
      }
      
      // Return empty history for new sessions
      return {
        sessionId,
        messages: [],
        createdAt: new Date().toISOString(),
        lastUpdated: new Date().toISOString(),
        messageCount: 0
      };
      
    } catch (error) {
      if (error.code === 'NOT_FOUND') {
        // Return empty history for new sessions
        return {
          sessionId,
          messages: [],
          createdAt: new Date().toISOString(),
          lastUpdated: new Date().toISOString(),
          messageCount: 0
        };
      }
      
      this.logger.error('Failed to get chat history:', error);
      throw error;
    }
  }

  async getRecentMessages(sessionId, count = 10) {
    try {
      const history = await this.getHistory(sessionId);
      return history.messages.slice(-count);
    } catch (error) {
      this.logger.error('Failed to get recent messages:', error);
      return [];
    }
  }

  async searchMessages(sessionId, searchTerm, limit = 20) {
    try {
      const history = await this.getHistory(sessionId);
      const searchLower = searchTerm.toLowerCase();
      
      const matchingMessages = history.messages
        .filter(message => 
          message.content.toLowerCase().includes(searchLower) ||
          (message.metadata && JSON.stringify(message.metadata).toLowerCase().includes(searchLower))
        )
        .slice(-limit);
      
      return matchingMessages;
      
    } catch (error) {
      this.logger.error('Failed to search messages:', error);
      return [];
    }
  }

  async getSessionSummary(sessionId) {
    try {
      const history = await this.getHistory(sessionId);
      
      if (history.messages.length === 0) {
        return {
          sessionId,
          messageCount: 0,
          summary: 'No messages in this session'
        };
      }
      
      // Analyze message types and topics
      const messageTypes = {};
      const topics = new Set();
      let userMessages = 0;
      let assistantMessages = 0;
      
      history.messages.forEach(message => {
        if (message.type === 'user') {
          userMessages++;
        } else if (message.type === 'assistant') {
          assistantMessages++;
        }
        
        // Extract topics from metadata
        if (message.metadata) {
          if (message.metadata.queryType) {
            topics.add(message.metadata.queryType);
          }
          if (message.metadata.analysisType) {
            topics.add(message.metadata.analysisType);
          }
        }
        
        // Count message types
        const type = message.metadata?.queryType || 'general';
        messageTypes[type] = (messageTypes[type] || 0) + 1;
      });
      
      return {
        sessionId,
        messageCount: history.messages.length,
        userMessages,
        assistantMessages,
        messageTypes,
        topics: Array.from(topics),
        createdAt: history.createdAt,
        lastUpdated: history.lastUpdated,
        duration: this.calculateSessionDuration(history)
      };
      
    } catch (error) {
      this.logger.error('Failed to get session summary:', error);
      throw error;
    }
  }

  calculateSessionDuration(history) {
    if (history.messages.length < 2) {
      return 0;
    }
    
    const firstMessage = new Date(history.messages[0].timestamp);
    const lastMessage = new Date(history.messages[history.messages.length - 1].timestamp);
    
    return lastMessage.getTime() - firstMessage.getTime();
  }

  async deleteSession(sessionId) {
    try {
      await this.kv.delete(sessionId);
      this.logger.info(`Deleted chat session: ${sessionId}`);
    } catch (error) {
      this.logger.error('Failed to delete session:', error);
      throw error;
    }
  }

  async listSessions(limit = 50) {
    try {
      const sessions = [];
      const keys = await this.kv.keys();
      
      for await (const key of keys) {
        if (sessions.length >= limit) break;
        
        try {
          const summary = await this.getSessionSummary(key);
          sessions.push(summary);
        } catch (error) {
          this.logger.warn(`Failed to get summary for session ${key}:`, error);
        }
      }
      
      // Sort by last updated
      sessions.sort((a, b) => new Date(b.lastUpdated) - new Date(a.lastUpdated));
      
      return sessions;
      
    } catch (error) {
      this.logger.error('Failed to list sessions:', error);
      return [];
    }
  }

  async exportSession(sessionId, format = 'json') {
    try {
      const history = await this.getHistory(sessionId);
      
      switch (format.toLowerCase()) {
        case 'json':
          return JSON.stringify(history, null, 2);
          
        case 'markdown':
          return this.formatAsMarkdown(history);
          
        case 'text':
          return this.formatAsText(history);
          
        default:
          throw new Error(`Unsupported export format: ${format}`);
      }
      
    } catch (error) {
      this.logger.error('Failed to export session:', error);
      throw error;
    }
  }

  formatAsMarkdown(history) {
    let markdown = `# Chat Session: ${history.sessionId}\n\n`;
    markdown += `**Created:** ${new Date(history.createdAt).toLocaleString()}\n`;
    markdown += `**Last Updated:** ${new Date(history.lastUpdated).toLocaleString()}\n`;
    markdown += `**Messages:** ${history.messageCount}\n\n`;
    markdown += '---\n\n';
    
    history.messages.forEach(message => {
      const timestamp = new Date(message.timestamp).toLocaleString();
      const role = message.type === 'user' ? '👤 User' : '🤖 Assistant';
      
      markdown += `## ${role} - ${timestamp}\n\n`;
      markdown += `${message.content}\n\n`;
      
      if (message.metadata) {
        markdown += `*Metadata: ${JSON.stringify(message.metadata, null, 2)}*\n\n`;
      }
      
      markdown += '---\n\n';
    });
    
    return markdown;
  }

  formatAsText(history) {
    let text = `Chat Session: ${history.sessionId}\n`;
    text += `Created: ${new Date(history.createdAt).toLocaleString()}\n`;
    text += `Last Updated: ${new Date(history.lastUpdated).toLocaleString()}\n`;
    text += `Messages: ${history.messageCount}\n\n`;
    text += '=' .repeat(50) + '\n\n';
    
    history.messages.forEach(message => {
      const timestamp = new Date(message.timestamp).toLocaleString();
      const role = message.type === 'user' ? 'User' : 'Assistant';
      
      text += `[${timestamp}] ${role}:\n`;
      text += `${message.content}\n\n`;
      
      if (message.metadata) {
        text += `Metadata: ${JSON.stringify(message.metadata)}\n\n`;
      }
      
      text += '-'.repeat(30) + '\n\n';
    });
    
    return text;
  }

  async getConversationContext(sessionId, messageCount = 5) {
    try {
      const recentMessages = await this.getRecentMessages(sessionId, messageCount);
      
      // Format for LLM context
      const context = recentMessages.map(message => ({
        role: message.type === 'user' ? 'user' : 'assistant',
        content: message.content,
        timestamp: message.timestamp
      }));
      
      return context;
      
    } catch (error) {
      this.logger.error('Failed to get conversation context:', error);
      return [];
    }
  }

  async cleanupOldSessions() {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);
      
      const keys = await this.kv.keys();
      let deletedCount = 0;
      
      for await (const key of keys) {
        try {
          const history = await this.getHistory(key);
          const lastUpdated = new Date(history.lastUpdated);
          
          if (lastUpdated < cutoffDate) {
            await this.deleteSession(key);
            deletedCount++;
          }
        } catch (error) {
          this.logger.warn(`Failed to check session ${key} for cleanup:`, error);
        }
      }
      
      this.logger.info(`Cleaned up ${deletedCount} old chat sessions`);
      return deletedCount;
      
    } catch (error) {
      this.logger.error('Failed to cleanup old sessions:', error);
      return 0;
    }
  }
}

module.exports = ChatHistory;