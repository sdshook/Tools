
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime
import os

# Set style
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

# Create output directory
os.makedirs('images', exist_ok=True)

# Load data
results_df = pd.read_csv('results/comprehensive_test_results.csv')
progress_df = pd.read_csv('results/adaptive_learning_progress.csv')

# 1. Accuracy Over Time
plt.figure(figsize=(12, 8))
plt.subplot(2, 2, 1)
plt.plot(results_df.index, results_df['accuracy'] * 100, marker='o', linewidth=2, markersize=4)
plt.title('Accuracy Progression Over Time', fontsize=14, fontweight='bold')
plt.xlabel('Test Iteration')
plt.ylabel('Accuracy (%)')
plt.grid(True, alpha=0.3)

# 2. Precision, Recall, F1 Score
plt.subplot(2, 2, 2)
plt.plot(results_df.index, results_df['precision'], label='Precision', marker='s', linewidth=2)
plt.plot(results_df.index, results_df['recall'], label='Recall', marker='^', linewidth=2)
plt.plot(results_df.index, results_df['f1_score'], label='F1 Score', marker='d', linewidth=2)
plt.title('Performance Metrics Evolution', fontsize=14, fontweight='bold')
plt.xlabel('Test Iteration')
plt.ylabel('Score')
plt.legend()
plt.grid(True, alpha=0.3)

# 3. Memory System Growth
plt.subplot(2, 2, 3)
plt.plot(results_df.index, results_df['memory_traces'], label='Memory Traces', marker='o')
plt.plot(results_df.index, results_df['hebbian_connections'], label='Hebbian Connections', marker='s')
plt.plot(results_df.index, results_df['psi_entries'], label='PSI Entries', marker='^')
plt.title('Memory System Evolution', fontsize=14, fontweight='bold')
plt.xlabel('Test Iteration')
plt.ylabel('Count')
plt.legend()
plt.grid(True, alpha=0.3)

# 4. EQ/IQ Balance Evolution
plt.subplot(2, 2, 4)
plt.plot(results_df.index, results_df['eq_weight'], label='EQ Weight', marker='o', linewidth=2)
plt.plot(results_df.index, results_df['iq_weight'], label='IQ Weight', marker='s', linewidth=2)
plt.plot(results_df.index, results_df['empathic_accuracy'], label='Empathic Accuracy', marker='^', linewidth=2)
plt.title('EQ/IQ Balance Evolution', fontsize=14, fontweight='bold')
plt.xlabel('Test Iteration')
plt.ylabel('Weight/Score')
plt.legend()
plt.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('images/comprehensive_performance_overview.png', dpi=300, bbox_inches='tight')
plt.close()

# 5. Adaptive Learning Detailed Analysis
fig, axes = plt.subplots(2, 3, figsize=(18, 12))

# Accuracy improvement over scenarios
axes[0, 0].bar(progress_df['iteration'], progress_df['accuracy_improvement'] * 100)
axes[0, 0].set_title('Accuracy Improvement by Scenario', fontweight='bold')
axes[0, 0].set_xlabel('Scenario')
axes[0, 0].set_ylabel('Accuracy Improvement (%)')
axes[0, 0].grid(True, alpha=0.3)

# Memory growth
axes[0, 1].plot(progress_df['iteration'], progress_df['memory_growth'], marker='o', linewidth=3)
axes[0, 1].set_title('Memory Growth Progression', fontweight='bold')
axes[0, 1].set_xlabel('Scenario')
axes[0, 1].set_ylabel('Memory Traces')
axes[0, 1].grid(True, alpha=0.3)

# Connection strength evolution
axes[0, 2].plot(progress_df['iteration'], progress_df['connection_strength'], marker='s', linewidth=3, color='red')
axes[0, 2].set_title('Hebbian Connection Strength', fontweight='bold')
axes[0, 2].set_xlabel('Scenario')
axes[0, 2].set_ylabel('Connection Count')
axes[0, 2].grid(True, alpha=0.3)

# EQ/IQ balance evolution
axes[1, 0].plot(progress_df['iteration'], progress_df['eq_iq_balance_evolution'], marker='^', linewidth=3, color='green')
axes[1, 0].axhline(y=0, color='black', linestyle='--', alpha=0.5)
axes[1, 0].set_title('EQ/IQ Balance Evolution', fontweight='bold')
axes[1, 0].set_xlabel('Scenario')
axes[1, 0].set_ylabel('EQ - IQ Weight Difference')
axes[1, 0].grid(True, alpha=0.3)

# Retrospective learning impact
axes[1, 1].bar(progress_df['iteration'], progress_df['retrospective_learning_impact'], color='orange')
axes[1, 1].set_title('Retrospective Learning Impact', fontweight='bold')
axes[1, 1].set_xlabel('Scenario')
axes[1, 1].set_ylabel('Impact Score')
axes[1, 1].grid(True, alpha=0.3)

# Processing time efficiency
axes[1, 2].plot(results_df.index, results_df['processing_time_ms'], marker='d', linewidth=2, color='purple')
axes[1, 2].set_title('Processing Time Efficiency', fontweight='bold')
axes[1, 2].set_xlabel('Test Iteration')
axes[1, 2].set_ylabel('Processing Time (ms)')
axes[1, 2].grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('images/adaptive_learning_analysis.png', dpi=300, bbox_inches='tight')
plt.close()

# 6. False Positive/Negative Analysis
plt.figure(figsize=(14, 6))

plt.subplot(1, 2, 1)
plt.plot(results_df.index, results_df['false_positive_rate'] * 100, marker='o', linewidth=2, color='red', label='False Positive Rate')
plt.plot(results_df.index, results_df['false_negative_rate'] * 100, marker='s', linewidth=2, color='blue', label='False Negative Rate')
plt.title('Error Rate Evolution', fontsize=14, fontweight='bold')
plt.xlabel('Test Iteration')
plt.ylabel('Error Rate (%)')
plt.legend()
plt.grid(True, alpha=0.3)

plt.subplot(1, 2, 2)
plt.scatter(results_df['false_positive_rate'] * 100, results_df['false_negative_rate'] * 100, 
           c=results_df.index, cmap='viridis', s=50, alpha=0.7)
plt.colorbar(label='Test Iteration')
plt.title('False Positive vs False Negative Trade-off', fontsize=14, fontweight='bold')
plt.xlabel('False Positive Rate (%)')
plt.ylabel('False Negative Rate (%)')
plt.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('images/error_analysis.png', dpi=300, bbox_inches='tight')
plt.close()

# 7. System State Heatmap
plt.figure(figsize=(12, 8))
metrics_for_heatmap = results_df[['accuracy', 'precision', 'recall', 'f1_score', 'eq_weight', 'iq_weight', 'empathic_accuracy']].T
sns.heatmap(metrics_for_heatmap, cmap='RdYlBu_r', center=0.5, annot=False, cbar_kws={'label': 'Score'})
plt.title('System Performance Heatmap Over Time', fontsize=16, fontweight='bold')
plt.xlabel('Test Iteration')
plt.ylabel('Metrics')
plt.tight_layout()
plt.savefig('images/system_state_heatmap.png', dpi=300, bbox_inches='tight')
plt.close()

print("✅ All visualizations generated successfully!")
print("📊 Saved to images/:")
print("   - comprehensive_performance_overview.png")
print("   - adaptive_learning_analysis.png") 
print("   - error_analysis.png")
print("   - system_state_heatmap.png")
