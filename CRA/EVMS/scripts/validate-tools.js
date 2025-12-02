#!/usr/bin/env node

// EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
// Tool validation script

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const packageJson = require('../package.json');

class ToolValidator {
  constructor() {
    this.tools = packageJson.evms.requiredTools;
    this.results = {};
  }

  async validateAll() {
    console.log('🔍 EVMS Tool Validation');
    console.log('========================\n');

    for (const [toolName, toolConfig] of Object.entries(this.tools)) {
      await this.validateTool(toolName, toolConfig);
    }

    this.printSummary();
    return this.results;
  }

  async validateTool(toolName, config) {
    console.log(`Checking ${toolName}...`);
    
    const result = {
      name: toolName,
      path: config.path,
      description: config.description,
      url: config.url,
      required: config.required,
      exists: false,
      executable: false,
      version: null,
      error: null
    };

    try {
      // Check if file exists
      const toolPath = path.resolve(config.path);
      
      if (fs.existsSync(toolPath)) {
        result.exists = true;
        
        // Check if executable
        try {
          fs.accessSync(toolPath, fs.constants.X_OK);
          result.executable = true;
          
          // Try to get version
          result.version = await this.getToolVersion(toolName, toolPath);
          
        } catch (error) {
          result.error = 'File exists but is not executable';
        }
      } else {
        result.error = 'Tool not found at specified path';
      }
      
    } catch (error) {
      result.error = error.message;
    }

    this.results[toolName] = result;
    this.printToolResult(result);
  }

  async getToolVersion(toolName, toolPath) {
    return new Promise((resolve) => {
      let versionArgs = [];
      
      // Different tools use different version flags
      switch (toolName) {
        case 'masscan':
          versionArgs = ['--version'];
          break;
        case 'nuclei':
          versionArgs = ['-version'];
          break;
        case 'subfinder':
          versionArgs = ['-version'];
          break;
        case 'httpx':
          versionArgs = ['-version'];
          break;
        default:
          versionArgs = ['--version'];
      }

      const process = spawn(toolPath, versionArgs, { timeout: 5000 });
      let output = '';

      process.stdout.on('data', (data) => {
        output += data.toString();
      });

      process.stderr.on('data', (data) => {
        output += data.toString();
      });

      process.on('close', (code) => {
        if (output) {
          // Extract version from output
          const versionMatch = output.match(/v?(\d+\.\d+\.\d+)/);
          resolve(versionMatch ? versionMatch[1] : 'unknown');
        } else {
          resolve('unknown');
        }
      });

      process.on('error', () => {
        resolve('unknown');
      });

      // Timeout fallback
      setTimeout(() => {
        process.kill();
        resolve('timeout');
      }, 5000);
    });
  }

  printToolResult(result) {
    const status = result.exists && result.executable ? '✅' : '❌';
    const version = result.version ? ` (v${result.version})` : '';
    
    console.log(`  ${status} ${result.name}${version}`);
    
    if (result.error) {
      console.log(`     Error: ${result.error}`);
    }
    
    if (!result.exists) {
      console.log(`     Install from: ${result.url}`);
      console.log(`     Expected path: ${result.path}`);
    }
    
    console.log();
  }

  printSummary() {
    console.log('Summary');
    console.log('=======');
    
    const available = Object.values(this.results).filter(r => r.exists && r.executable).length;
    const total = Object.keys(this.results).length;
    
    console.log(`Available tools: ${available}/${total}`);
    
    if (available === total) {
      console.log('🎉 All tools are available and ready!');
    } else {
      console.log('⚠️  Some tools are missing. EVMS will use built-in fallbacks.');
      console.log('   For optimal performance, install the missing tools.');
    }
    
    console.log('\nNote: All tools are optional. EVMS includes built-in scanning capabilities.');
  }
}

// Run validation if called directly
if (require.main === module) {
  const validator = new ToolValidator();
  validator.validateAll().catch(console.error);
}

module.exports = ToolValidator;