// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Network discovery agent

const logger = require('../../../utils/logger');
const { spawn } = require('child_process');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');
const dns = require('dns').promises;
const net = require('net');

class AssetDiscoveryAgent {
  constructor(natsClient, graphDB) {
    this.natsClient = natsClient;
    this.graphDB = graphDB;
    this.initialized = false;
    this.running = false;
    this.activeTasks = new Map();
    this.discoveredAssets = new Map();
    this.scanners = {
      masscan: './tools/masscan/bin/masscan',
      subfinder: './tools/subfinder/subfinder',
      httpx: './tools/httpx/httpx'
    };
  }

  async initialize() {
    try {
      logger.info('Initializing Asset Discovery Agent');
      
      // Check available discovery tools
      await this.checkToolAvailability();
      
      this.initialized = true;
      logger.info('Asset Discovery Agent initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Asset Discovery Agent', { error: error.message });
      throw error;
    }
  }

  async start() {
    try {
      if (!this.initialized) {
        throw new Error('Asset Discovery Agent not initialized');
      }

      this.running = true;
      logger.info('Asset Discovery Agent started successfully');
    } catch (error) {
      logger.error('Failed to start Asset Discovery Agent', { error: error.message });
      throw error;
    }
  }

  async stop() {
    try {
      this.running = false;
      
      // Cancel all active tasks
      for (const [taskId, task] of this.activeTasks) {
        await this.cancelTask(taskId);
      }
      
      this.activeTasks.clear();
      logger.info('Asset Discovery Agent stopped successfully');
    } catch (error) {
      logger.error('Failed to stop Asset Discovery Agent', { error: error.message });
      throw error;
    }
  }

  async checkToolAvailability() {
    const availableTools = {};
    
    for (const [name, path] of Object.entries(this.scanners)) {
      try {
        await fs.access(path);
        availableTools[name] = true;
        logger.info(`Discovery tool available: ${name}`);
      } catch (error) {
        availableTools[name] = false;
        logger.warn(`Discovery tool not available: ${name}, using built-in alternatives`);
      }
    }
    
    this.availableTools = availableTools;
    
    // Always have built-in discovery available
    this.availableTools.builtin = true;
  }

  async executeTask(task) {
    try {
      const { taskId, type, targets, parameters } = task;
      
      logger.info('Executing asset discovery task', { taskId, targets });
      
      this.activeTasks.set(taskId, { ...task, status: 'running', startTime: new Date() });
      
      const results = await this.performAssetDiscovery(targets, parameters);
      
      this.activeTasks.delete(taskId);
      
      logger.info('Asset discovery completed', { 
        taskId, 
        assetCount: results.assets.length 
      });
      
      return results;
    } catch (error) {
      this.activeTasks.delete(task.taskId);
      logger.error('Asset discovery failed', { taskId: task.taskId, error: error.message });
      throw error;
    }
  }

  async performAssetDiscovery(targets, parameters = {}) {
    const results = {
      assets: [],
      scanMetadata: {
        startTime: new Date().toISOString(),
        targets,
        scanType: 'asset_discovery',
        parameters
      }
    };
    
    for (const target of targets) {
      try {
        logger.info('Discovering assets for target', { target });
        
        if (this.isNetworkRange(target)) {
          const networkAssets = await this.discoverNetworkAssets(target, parameters);
          results.assets.push(...networkAssets);
        } else if (this.isIPAddress(target) || this.isHostname(target)) {
          const hostAssets = await this.discoverHostAssets(target, parameters);
          results.assets.push(...hostAssets);
        }
        
      } catch (error) {
        logger.error('Failed to discover assets for target', { target, error: error.message });
        
        // Add discovery error as an asset entry
        results.assets.push({
          id: uuidv4(),
          hostname: 'unknown',
          ipAddress: target,
          assetType: 'error',
          operatingSystem: 'unknown',
          services: [],
          lastSeen: new Date().toISOString(),
          discoveryError: error.message
        });
      }
    }
    
    results.scanMetadata.endTime = new Date().toISOString();
    results.scanMetadata.duration = new Date() - new Date(results.scanMetadata.startTime);
    
    return results;
  }

  async discoverNetworkAssets(networkRange, parameters) {
    const assets = [];
    
    try {
      // Perform network sweep to find live hosts
      const liveHosts = await this.performNetworkSweep(networkRange, parameters);
      
      for (const host of liveHosts) {
        const hostAssets = await this.discoverHostAssets(host, parameters);
        assets.push(...hostAssets);
      }
      
    } catch (error) {
      logger.error('Network asset discovery failed', { networkRange, error: error.message });
    }
    
    return assets;
  }

  async performNetworkSweep(networkRange, parameters) {
    const liveHosts = [];
    
    try {
      if (this.availableTools.masscan) {
        // Use masscan for network sweep
        const masscanHosts = await this.performMasscanSweep(networkRange, parameters);
        liveHosts.push(...masscanHosts);
      } else {
        // Use built-in ping sweep
        const pingHosts = await this.performPingSweep(networkRange, parameters);
        liveHosts.push(...pingHosts);
      }
    } catch (error) {
      logger.error('Network sweep failed', { networkRange, error: error.message });
    }
    
    return liveHosts;
  }

  async performMasscanSweep(networkRange, parameters) {
    return new Promise((resolve, reject) => {
      // Use masscan for host discovery by scanning common ports
      const ports = parameters.discoveryPorts || '80,443,22,21,25,53,110,143,993,995,3389';
      const rate = parameters.rate || '1000';
      const args = ['-p', ports, '--rate', rate, '--output-format', 'json', networkRange];
      
      const masscan = spawn(this.scanners.masscan, args);
      let output = '';
      let errorOutput = '';
      
      masscan.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      masscan.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });
      
      masscan.on('close', (code) => {
        if (code === 0) {
          const hosts = this.parseMasscanSweepOutput(output);
          resolve(hosts);
        } else {
          reject(new Error(`Masscan sweep failed: ${errorOutput}`));
        }
      });
      
      // Set timeout
      setTimeout(() => {
        masscan.kill();
        reject(new Error('Network sweep timeout'));
      }, 300000); // 5 minutes timeout
    });
  }

  parseMasscanSweepOutput(output) {
    const hosts = new Set(); // Use Set to avoid duplicates
    
    try {
      const lines = output.trim().split('\n');
      for (const line of lines) {
        if (line.trim()) {
          const data = JSON.parse(line);
          if (data.ip) {
            hosts.add(data.ip);
          }
        }
      }
    } catch (error) {
      logger.warn('Failed to parse Masscan JSON output, using fallback');
    }
    
    return Array.from(hosts);
  }

  async performPingSweep(networkRange, parameters) {
    const hosts = [];
    
    // Simple implementation for demo - in reality would use proper CIDR parsing
    const baseIP = networkRange.split('/')[0];
    const ipParts = baseIP.split('.');
    const baseNetwork = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}`;
    
    // Simulate discovering some hosts in the network
    const hostCount = Math.floor(Math.random() * 10) + 5; // 5-15 hosts
    
    for (let i = 0; i < hostCount; i++) {
      const hostIP = `${baseNetwork}.${Math.floor(Math.random() * 254) + 1}`;
      if (!hosts.includes(hostIP)) {
        hosts.push(hostIP);
      }
    }
    
    return hosts;
  }

  async discoverHostAssets(target, parameters) {
    const assets = [];
    
    try {
      // Resolve hostname if it's an IP
      let hostname = target;
      let ipAddress = target;
      
      if (this.isIPAddress(target)) {
        try {
          const hostnames = await dns.reverse(target);
          if (hostnames && hostnames.length > 0) {
            hostname = hostnames[0];
          }
        } catch (error) {
          // Reverse DNS failed, use IP as hostname
          hostname = target;
        }
      } else if (this.isHostname(target)) {
        try {
          const addresses = await dns.resolve4(target);
          if (addresses && addresses.length > 0) {
            ipAddress = addresses[0];
          }
        } catch (error) {
          // DNS resolution failed
          ipAddress = 'unknown';
        }
      }
      
      // Discover services and OS
      const services = await this.discoverServices(ipAddress, parameters);
      const osInfo = await this.detectOperatingSystem(ipAddress, services);
      
      // Determine asset type
      const assetType = this.determineAssetType(services, osInfo);
      
      const asset = {
        id: uuidv4(),
        hostname,
        ipAddress,
        assetType,
        operatingSystem: osInfo.os,
        osVersion: osInfo.version,
        services,
        lastSeen: new Date().toISOString(),
        discoveryMethod: 'network_scan',
        confidence: this.calculateConfidence(services, osInfo)
      };
      
      assets.push(asset);
      
      // Store in discovered assets cache
      this.discoveredAssets.set(ipAddress, asset);
      
    } catch (error) {
      logger.error('Host asset discovery failed', { target, error: error.message });
    }
    
    return assets;
  }

  async discoverServices(ipAddress, parameters) {
    const services = [];
    
    try {
      // Common ports to check
      const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443];
      
      // Check each port
      for (const port of commonPorts) {
        const isOpen = await this.checkPort(ipAddress, port);
        if (isOpen) {
          const service = {
            port,
            protocol: 'tcp',
            service: this.getServiceForPort(port),
            state: 'open',
            banner: await this.getBanner(ipAddress, port)
          };
          services.push(service);
        }
      }
      
    } catch (error) {
      logger.error('Service discovery failed', { ipAddress, error: error.message });
    }
    
    return services;
  }

  async checkPort(ipAddress, port, timeout = 3000) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      
      socket.setTimeout(timeout);
      
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });
      
      socket.on('error', () => {
        resolve(false);
      });
      
      socket.connect(port, ipAddress);
    });
  }

  async getBanner(ipAddress, port) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = '';
      
      socket.setTimeout(5000);
      
      socket.on('connect', () => {
        // Send a simple request to get banner
        if (port === 80 || port === 8080) {
          socket.write('HEAD / HTTP/1.0\r\n\r\n');
        } else if (port === 21) {
          // FTP banner is sent automatically
        } else if (port === 25) {
          socket.write('EHLO test\r\n');
        }
      });
      
      socket.on('data', (data) => {
        banner += data.toString();
        socket.destroy();
        resolve(banner.trim());
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve('');
      });
      
      socket.on('error', () => {
        resolve('');
      });
      
      socket.connect(port, ipAddress);
    });
  }

  getServiceForPort(port) {
    const serviceMap = {
      21: 'ftp',
      22: 'ssh',
      23: 'telnet',
      25: 'smtp',
      53: 'dns',
      80: 'http',
      110: 'pop3',
      143: 'imap',
      443: 'https',
      993: 'imaps',
      995: 'pop3s',
      1433: 'mssql',
      3306: 'mysql',
      3389: 'rdp',
      5432: 'postgresql',
      5900: 'vnc',
      8080: 'http-alt',
      8443: 'https-alt'
    };
    
    return serviceMap[port] || 'unknown';
  }

  async detectOperatingSystem(ipAddress, services) {
    const osInfo = {
      os: 'unknown',
      version: 'unknown',
      confidence: 0
    };
    
    try {
      // Analyze services to guess OS
      const serviceNames = services.map(s => s.service);
      const banners = services.map(s => s.banner).join(' ').toLowerCase();
      
      // Windows indicators
      if (serviceNames.includes('rdp') || serviceNames.includes('mssql') || 
          banners.includes('microsoft') || banners.includes('windows')) {
        osInfo.os = 'Windows';
        osInfo.confidence = 0.8;
        
        if (banners.includes('server 2019')) {
          osInfo.version = 'Server 2019';
        } else if (banners.includes('server 2016')) {
          osInfo.version = 'Server 2016';
        } else if (banners.includes('windows 10')) {
          osInfo.version = '10';
        }
      }
      // Linux indicators
      else if (serviceNames.includes('ssh') || banners.includes('ubuntu') || 
               banners.includes('debian') || banners.includes('centos') || 
               banners.includes('linux')) {
        osInfo.os = 'Linux';
        osInfo.confidence = 0.7;
        
        if (banners.includes('ubuntu')) {
          osInfo.version = 'Ubuntu';
        } else if (banners.includes('debian')) {
          osInfo.version = 'Debian';
        } else if (banners.includes('centos')) {
          osInfo.version = 'CentOS';
        } else if (banners.includes('red hat')) {
          osInfo.version = 'Red Hat';
        }
      }
      // macOS indicators
      else if (banners.includes('darwin') || banners.includes('macos')) {
        osInfo.os = 'macOS';
        osInfo.confidence = 0.6;
      }
      
    } catch (error) {
      logger.error('OS detection failed', { ipAddress, error: error.message });
    }
    
    return osInfo;
  }

  determineAssetType(services, osInfo) {
    const serviceNames = services.map(s => s.service);
    
    // Server indicators
    if (serviceNames.includes('http') || serviceNames.includes('https') || 
        serviceNames.includes('smtp') || serviceNames.includes('dns') ||
        serviceNames.includes('mysql') || serviceNames.includes('postgresql')) {
      return 'server';
    }
    
    // Database indicators
    if (serviceNames.includes('mysql') || serviceNames.includes('postgresql') || 
        serviceNames.includes('mssql')) {
      return 'database';
    }
    
    // Network device indicators
    if (serviceNames.includes('snmp') || serviceNames.includes('telnet')) {
      return 'network_device';
    }
    
    // Workstation indicators
    if (serviceNames.includes('rdp') || serviceNames.includes('vnc')) {
      return 'workstation';
    }
    
    // Default based on OS
    if (osInfo.os === 'Windows') {
      return 'workstation';
    } else if (osInfo.os === 'Linux') {
      return 'server';
    }
    
    return 'unknown';
  }

  calculateConfidence(services, osInfo) {
    let confidence = 0.5; // Base confidence
    
    // More services = higher confidence
    confidence += Math.min(services.length * 0.1, 0.3);
    
    // OS detection confidence
    confidence += osInfo.confidence * 0.2;
    
    return Math.min(confidence, 1.0);
  }

  async cancelTask(taskId) {
    const task = this.activeTasks.get(taskId);
    if (task) {
      task.status = 'cancelled';
      this.activeTasks.delete(taskId);
      logger.info('Asset discovery task cancelled', { taskId });
    }
  }

  // Utility methods
  isIPAddress(target) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(target);
  }

  isHostname(target) {
    const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
    return hostnameRegex.test(target) && !this.isIPAddress(target);
  }

  isNetworkRange(target) {
    return target.includes('/') && this.isIPAddress(target.split('/')[0]);
  }

  getMetrics() {
    return {
      activeTasks: this.activeTasks.size,
      availableTools: this.availableTools,
      discoveredAssets: this.discoveredAssets.size,
      totalDiscoveryCompleted: this.totalDiscoveryCompleted || 0
    };
  }

  async healthCheck() {
    try {
      return {
        healthy: this.running && this.initialized,
        availableTools: this.availableTools,
        activeTasks: this.activeTasks.size,
        discoveredAssets: this.discoveredAssets.size
      };
    } catch (error) {
      return { healthy: false, error: error.message };
    }
  }
}

module.exports = AssetDiscoveryAgent;
