<!-- EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved -->
# GraphRL Design for EVMS

## Overview

The GraphRL (Graph Reinforcement Learning) component is the intelligence core of EVMS, providing autonomous decision-making capabilities for vulnerability management through deep reinforcement learning on graph-structured data. This system learns optimal scanning strategies, risk prioritization, and resource allocation through continuous interaction with the environment and human feedback.

## Graph Representation

### Node Types and Features

#### Asset Nodes
```python
class AssetNode:
    features = {
        'node_type': 'asset',
        'ip_address': str,
        'hostname': str,
        'os_type': categorical,
        'os_version': str,
        'criticality_score': float,  # Business criticality
        'exposure_score': float,     # Network exposure
        'vulnerability_count': int,
        'last_scan_time': timestamp,
        'patch_level': float,        # 0-1 scale
        'configuration_score': float, # Security configuration
        'service_count': int,
        'open_ports': list,
        'network_zone': categorical,
        'compliance_status': categorical
    }
```

#### Vulnerability Nodes
```python
class VulnerabilityNode:
    features = {
        'node_type': 'vulnerability',
        'cve_id': str,
        'cvss_base_score': float,
        'cvss_temporal_score': float,
        'cvss_environmental_score': float,
        'exploit_available': boolean,
        'exploit_maturity': categorical,
        'patch_available': boolean,
        'patch_age_days': int,
        'affected_asset_count': int,
        'discovery_date': timestamp,
        'severity_category': categorical,
        'attack_vector': categorical,
        'attack_complexity': categorical,
        'privileges_required': categorical,
        'user_interaction': categorical,
        'scope': categorical,
        'confidentiality_impact': categorical,
        'integrity_impact': categorical,
        'availability_impact': categorical
    }
```

#### Service Nodes
```python
class ServiceNode:
    features = {
        'node_type': 'service',
        'service_name': str,
        'port': int,
        'protocol': categorical,
        'version': str,
        'banner': str,
        'is_encrypted': boolean,
        'authentication_required': boolean,
        'default_credentials': boolean,
        'vulnerability_count': int,
        'last_updated': timestamp,
        'configuration_issues': int
    }
```

### Edge Types and Features

#### Asset-Vulnerability Relationships
```python
class AssetVulnerabilityEdge:
    features = {
        'edge_type': 'has_vulnerability',
        'discovery_method': categorical,
        'confidence_score': float,
        'false_positive_probability': float,
        'remediation_effort': categorical,
        'business_impact': categorical,
        'exploitability_score': float,
        'detection_date': timestamp,
        'last_verified': timestamp
    }
```

#### Asset-Asset Relationships
```python
class AssetAssetEdge:
    features = {
        'edge_type': 'network_connection',
        'connection_type': categorical,  # direct, routed, vpn
        'protocol': categorical,
        'port_range': str,
        'traffic_volume': float,
        'trust_level': categorical,
        'firewall_rules': list,
        'encryption_status': boolean,
        'monitoring_enabled': boolean
    }
```

## State Space Design

### Graph State Representation
```python
class GraphState:
    def __init__(self, graph_data):
        self.nodes = graph_data.nodes
        self.edges = graph_data.edges
        self.global_features = self.compute_global_features()
        
    def compute_global_features(self):
        return {
            'total_assets': len([n for n in self.nodes if n.type == 'asset']),
            'total_vulnerabilities': len([n for n in self.nodes if n.type == 'vulnerability']),
            'average_risk_score': np.mean([n.risk_score for n in self.nodes if hasattr(n, 'risk_score')]),
            'network_density': self.compute_network_density(),
            'vulnerability_density': self.compute_vulnerability_density(),
            'critical_path_length': self.compute_critical_path_length(),
            'scan_coverage': self.compute_scan_coverage(),
            'time_since_last_scan': self.compute_time_metrics(),
            'resource_utilization': self.get_resource_utilization(),
            'pending_hotl_reviews': self.count_pending_reviews()
        }
```

### State Embedding
```python
class GraphStateEncoder(nn.Module):
    def __init__(self, node_feature_dim, edge_feature_dim, hidden_dim):
        super().__init__()
        self.node_encoder = nn.Linear(node_feature_dim, hidden_dim)
        self.edge_encoder = nn.Linear(edge_feature_dim, hidden_dim)
        self.gnn_layers = nn.ModuleList([
            GraphConvLayer(hidden_dim, hidden_dim) for _ in range(4)
        ])
        self.global_pool = GlobalAttentionPool(hidden_dim)
        
    def forward(self, graph):
        # Encode node and edge features
        node_embeddings = self.node_encoder(graph.node_features)
        edge_embeddings = self.edge_encoder(graph.edge_features)
        
        # Apply graph neural network layers
        for layer in self.gnn_layers:
            node_embeddings = layer(node_embeddings, graph.edge_index, edge_embeddings)
            node_embeddings = F.relu(node_embeddings)
            
        # Global graph representation
        graph_embedding = self.global_pool(node_embeddings, graph.batch)
        
        return node_embeddings, graph_embedding
```

## Action Space Design

### Action Categories

#### 1. Scanning Actions
```python
class ScanningActions:
    VULNERABILITY_SCAN = 0      # Full vulnerability assessment
    QUICK_SCAN = 1             # Fast port scan and service detection
    DEEP_SCAN = 2              # Comprehensive security audit
    COMPLIANCE_SCAN = 3        # Policy compliance check
    CONFIGURATION_AUDIT = 4    # Security configuration review
    THREAT_HUNT = 5           # IOC and threat intelligence scan
    NO_SCAN = 6               # Skip scanning this cycle
```

#### 2. Prioritization Actions
```python
class PrioritizationActions:
    HIGH_PRIORITY = 0          # Immediate attention required
    MEDIUM_PRIORITY = 1        # Schedule within 24 hours
    LOW_PRIORITY = 2           # Schedule within week
    DEFER = 3                  # Postpone to next cycle
    IGNORE = 4                 # Mark as accepted risk
```

#### 3. Resource Allocation Actions
```python
class ResourceActions:
    ALLOCATE_MORE_AGENTS = 0   # Increase scanning resources
    REDUCE_AGENTS = 1          # Decrease scanning resources
    REDISTRIBUTE = 2           # Rebalance agent assignments
    MAINTAIN_CURRENT = 3       # Keep current allocation
```

#### 4. Threshold Adjustment Actions
```python
class ThresholdActions:
    INCREASE_SENSITIVITY = 0   # Lower detection thresholds
    DECREASE_SENSITIVITY = 1   # Raise detection thresholds
    ADJUST_RISK_WEIGHTS = 2    # Modify risk calculation weights
    MAINTAIN_THRESHOLDS = 3    # Keep current settings
```

### Action Masking
```python
def get_valid_actions(state, constraints):
    """
    Mask invalid actions based on current state and constraints
    """
    valid_actions = []
    
    # Resource constraints
    if state.available_agents < 2:
        valid_actions.remove(ScanningActions.DEEP_SCAN)
        
    # Time constraints
    if state.time_until_deadline < 1:  # Less than 1 hour
        valid_actions.remove(ScanningActions.DEEP_SCAN)
        valid_actions.remove(ScanningActions.COMPLIANCE_SCAN)
        
    # Asset constraints
    if state.target_asset.last_scan_time < 24:  # Scanned within 24 hours
        valid_actions.remove(ScanningActions.VULNERABILITY_SCAN)
        
    # Business constraints
    if state.target_asset.business_hours and state.current_time.is_business_hours():
        valid_actions.remove(ScanningActions.DEEP_SCAN)  # Avoid disruption
        
    return valid_actions
```

## Reward Function Design

### Multi-Objective Reward Structure
```python
class RewardCalculator:
    def __init__(self, weights):
        self.weights = weights
        
    def calculate_reward(self, action, outcome, context):
        rewards = {
            'vulnerability_detection': self.vulnerability_reward(outcome),
            'false_positive_penalty': self.false_positive_penalty(outcome),
            'resource_efficiency': self.resource_efficiency_reward(action, outcome),
            'hotl_feedback': self.hotl_feedback_reward(outcome),
            'risk_reduction': self.risk_reduction_reward(outcome),
            'compliance_improvement': self.compliance_reward(outcome),
            'time_efficiency': self.time_efficiency_reward(action, outcome),
            'business_impact': self.business_impact_reward(action, outcome)
        }
        
        total_reward = sum(self.weights[key] * value for key, value in rewards.items())
        return total_reward, rewards
    
    def vulnerability_detection_reward(self, outcome):
        """Reward for successfully detecting vulnerabilities"""
        base_reward = 0
        
        for vuln in outcome.detected_vulnerabilities:
            # Base reward by severity
            severity_multiplier = {
                'CRITICAL': 100,
                'HIGH': 50,
                'MEDIUM': 20,
                'LOW': 5
            }
            base_reward += severity_multiplier.get(vuln.severity, 0)
            
            # Bonus for new vulnerabilities
            if vuln.is_new_discovery:
                base_reward += 50
                
            # Bonus for exploitable vulnerabilities
            if vuln.exploit_available:
                base_reward += 25
                
        return base_reward
    
    def false_positive_penalty(self, outcome):
        """Penalty for false positive detections"""
        penalty = 0
        
        for fp in outcome.false_positives:
            # Penalty based on severity of false positive
            severity_penalty = {
                'CRITICAL': -50,
                'HIGH': -25,
                'MEDIUM': -10,
                'LOW': -2
            }
            penalty += severity_penalty.get(fp.reported_severity, 0)
            
            # Additional penalty if it required HOTL review
            if fp.required_hotl_review:
                penalty -= 20
                
        return penalty
    
    def hotl_feedback_reward(self, outcome):
        """Reward based on human operator feedback"""
        if not outcome.hotl_feedback:
            return 0
            
        feedback = outcome.hotl_feedback
        
        if feedback.action == 'APPROVED':
            return 75
        elif feedback.action == 'APPROVED_WITH_MODIFICATIONS':
            return 25
        elif feedback.action == 'REJECTED':
            return -50
        elif feedback.action == 'ESCALATED':
            return 10  # Neutral, appropriate escalation
            
        return 0
    
    def risk_reduction_reward(self, outcome):
        """Reward for actual risk reduction achieved"""
        risk_before = outcome.risk_score_before
        risk_after = outcome.risk_score_after
        risk_reduction = risk_before - risk_after
        
        # Scale reward by magnitude of risk reduction
        return risk_reduction * 200
    
    def resource_efficiency_reward(self, action, outcome):
        """Reward for efficient resource utilization"""
        efficiency_score = outcome.results_quality / outcome.resources_consumed
        
        # Normalize to reasonable range
        normalized_efficiency = min(efficiency_score / 10.0, 1.0)
        
        return normalized_efficiency * 30
```

### Reward Shaping Techniques
```python
class RewardShaper:
    def __init__(self):
        self.potential_function = self.create_potential_function()
        
    def create_potential_function(self):
        """Potential-based reward shaping to guide learning"""
        def potential(state):
            # Potential increases with better security posture
            security_potential = -state.total_risk_score / 1000
            
            # Potential increases with scan coverage
            coverage_potential = state.scan_coverage * 10
            
            # Potential decreases with pending high-risk items
            urgency_potential = -state.high_risk_pending_count * 5
            
            return security_potential + coverage_potential + urgency_potential
            
        return potential
    
    def shape_reward(self, reward, prev_state, action, next_state):
        """Apply potential-based reward shaping"""
        shaped_reward = reward + self.gamma * self.potential_function(next_state) - self.potential_function(prev_state)
        return shaped_reward
```

## Learning Algorithm

### Double DQN with Graph Neural Networks
```python
class GraphDQN(nn.Module):
    def __init__(self, node_feature_dim, edge_feature_dim, action_dim, hidden_dim=256):
        super().__init__()
        self.state_encoder = GraphStateEncoder(node_feature_dim, edge_feature_dim, hidden_dim)
        self.q_network = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim)
        )
        
    def forward(self, graph_state):
        node_embeddings, graph_embedding = self.state_encoder(graph_state)
        q_values = self.q_network(graph_embedding)
        return q_values

class GraphRLAgent:
    def __init__(self, state_dim, action_dim, lr=1e-4):
        self.q_network = GraphDQN(state_dim, action_dim)
        self.target_network = GraphDQN(state_dim, action_dim)
        self.optimizer = torch.optim.Adam(self.q_network.parameters(), lr=lr)
        self.memory = ReplayBuffer(capacity=100000)
        
        # Hyperparameters
        self.gamma = 0.99
        self.epsilon = 1.0
        self.epsilon_decay = 0.995
        self.epsilon_min = 0.01
        self.target_update_freq = 1000
        self.batch_size = 32
        
    def select_action(self, state, valid_actions=None):
        if random.random() < self.epsilon:
            # Epsilon-greedy exploration
            if valid_actions:
                return random.choice(valid_actions)
            return random.randint(0, self.action_dim - 1)
        
        with torch.no_grad():
            q_values = self.q_network(state)
            
            # Mask invalid actions
            if valid_actions:
                masked_q_values = torch.full_like(q_values, float('-inf'))
                masked_q_values[valid_actions] = q_values[valid_actions]
                q_values = masked_q_values
                
            return torch.argmax(q_values).item()
    
    def update(self, batch):
        states, actions, rewards, next_states, dones, valid_actions = batch
        
        # Current Q values
        current_q_values = self.q_network(states).gather(1, actions.unsqueeze(1))
        
        # Next Q values using target network (Double DQN)
        with torch.no_grad():
            # Use main network to select actions
            next_actions = self.q_network(next_states).argmax(1)
            
            # Use target network to evaluate actions
            next_q_values = self.target_network(next_states).gather(1, next_actions.unsqueeze(1))
            target_q_values = rewards + (1 - dones) * self.gamma * next_q_values.squeeze()
        
        # Compute loss
        loss = F.mse_loss(current_q_values.squeeze(), target_q_values)
        
        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), max_norm=1.0)
        self.optimizer.step()
        
        # Update epsilon
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
        
        return loss.item()
    
    def update_target_network(self):
        self.target_network.load_state_dict(self.q_network.state_dict())
```

### Experience Replay with Prioritization
```python
class PrioritizedReplayBuffer:
    def __init__(self, capacity, alpha=0.6, beta=0.4):
        self.capacity = capacity
        self.alpha = alpha
        self.beta = beta
        self.buffer = []
        self.priorities = np.zeros(capacity)
        self.position = 0
        
    def add(self, experience, td_error):
        priority = (abs(td_error) + 1e-6) ** self.alpha
        
        if len(self.buffer) < self.capacity:
            self.buffer.append(experience)
        else:
            self.buffer[self.position] = experience
            
        self.priorities[self.position] = priority
        self.position = (self.position + 1) % self.capacity
    
    def sample(self, batch_size):
        if len(self.buffer) < batch_size:
            return None
            
        # Calculate sampling probabilities
        priorities = self.priorities[:len(self.buffer)]
        probabilities = priorities / priorities.sum()
        
        # Sample indices
        indices = np.random.choice(len(self.buffer), batch_size, p=probabilities)
        
        # Calculate importance sampling weights
        weights = (len(self.buffer) * probabilities[indices]) ** (-self.beta)
        weights = weights / weights.max()
        
        # Get experiences
        experiences = [self.buffer[i] for i in indices]
        
        return experiences, indices, weights
```

## Training Pipeline

### Online Learning Loop
```python
class GraphRLTrainer:
    def __init__(self, agent, environment, reward_calculator):
        self.agent = agent
        self.environment = environment
        self.reward_calculator = reward_calculator
        self.training_metrics = TrainingMetrics()
        
    def train_episode(self):
        state = self.environment.reset()
        episode_reward = 0
        episode_steps = 0
        
        while not self.environment.done:
            # Select action
            valid_actions = self.environment.get_valid_actions(state)
            action = self.agent.select_action(state, valid_actions)
            
            # Execute action
            next_state, outcome = self.environment.step(action)
            
            # Calculate reward
            reward, reward_components = self.reward_calculator.calculate_reward(
                action, outcome, state
            )
            
            # Store experience
            self.agent.memory.add((state, action, reward, next_state, self.environment.done))
            
            # Update agent
            if len(self.agent.memory) > self.agent.batch_size:
                batch = self.agent.memory.sample(self.agent.batch_size)
                loss = self.agent.update(batch)
                self.training_metrics.record_loss(loss)
            
            # Update target network periodically
            if episode_steps % self.agent.target_update_freq == 0:
                self.agent.update_target_network()
            
            state = next_state
            episode_reward += reward
            episode_steps += 1
            
        return episode_reward, episode_steps
    
    def train(self, num_episodes):
        for episode in range(num_episodes):
            episode_reward, episode_steps = self.train_episode()
            
            self.training_metrics.record_episode(episode_reward, episode_steps)
            
            # Log progress
            if episode % 100 == 0:
                avg_reward = self.training_metrics.get_average_reward(100)
                print(f"Episode {episode}, Average Reward: {avg_reward:.2f}")
                
            # Save model periodically
            if episode % 1000 == 0:
                self.save_model(f"model_episode_{episode}.pt")
```

### Curriculum Learning
```python
class CurriculumLearning:
    def __init__(self, stages):
        self.stages = stages
        self.current_stage = 0
        
    def get_current_difficulty(self):
        return self.stages[self.current_stage]
    
    def should_advance(self, performance_metrics):
        current_stage = self.stages[self.current_stage]
        
        # Advance if performance threshold is met
        if performance_metrics.success_rate > current_stage.advancement_threshold:
            if self.current_stage < len(self.stages) - 1:
                self.current_stage += 1
                return True
        return False

# Define curriculum stages
curriculum_stages = [
    CurriculumStage(
        name="Basic Scanning",
        max_assets=10,
        max_vulnerabilities=5,
        complexity_level=1,
        advancement_threshold=0.8
    ),
    CurriculumStage(
        name="Medium Networks",
        max_assets=50,
        max_vulnerabilities=20,
        complexity_level=2,
        advancement_threshold=0.75
    ),
    CurriculumStage(
        name="Complex Environments",
        max_assets=200,
        max_vulnerabilities=100,
        complexity_level=3,
        advancement_threshold=0.7
    )
]
```

## Evaluation Metrics

### Performance Metrics
```python
class GraphRLMetrics:
    def __init__(self):
        self.metrics = {
            'vulnerability_detection_rate': [],
            'false_positive_rate': [],
            'resource_efficiency': [],
            'risk_reduction_rate': [],
            'hotl_approval_rate': [],
            'scan_coverage': [],
            'response_time': [],
            'model_confidence': []
        }
    
    def calculate_detection_metrics(self, predictions, ground_truth):
        tp = len(set(predictions) & set(ground_truth))
        fp = len(set(predictions) - set(ground_truth))
        fn = len(set(ground_truth) - set(predictions))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'true_positives': tp,
            'false_positives': fp,
            'false_negatives': fn
        }
    
    def calculate_business_impact(self, actions, outcomes):
        total_risk_reduction = sum(o.risk_reduction for o in outcomes)
        total_cost = sum(a.resource_cost for a in actions)
        
        roi = total_risk_reduction / total_cost if total_cost > 0 else 0
        
        return {
            'total_risk_reduction': total_risk_reduction,
            'total_cost': total_cost,
            'roi': roi,
            'average_response_time': np.mean([o.response_time for o in outcomes])
        }
```

This GraphRL design provides a comprehensive framework for autonomous vulnerability management that learns from experience, adapts to changing environments, and incorporates human feedback for continuous improvement.