
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Set style
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

# Load data
df = pd.read_csv('webguard_test_metrics.csv')

# Create comprehensive visualization dashboard
fig, axes = plt.subplots(3, 3, figsize=(20, 15))
fig.suptitle('WebGuard Comprehensive Multipass Learning Analysis', fontsize=16, fontweight='bold')

# 1. Threat Detection Rate Over Time
axes[0, 0].plot(df['pass_number'], df['threat_detection_rate'] * 100, 'o-', linewidth=2, markersize=6)
axes[0, 0].set_title('Threat Detection Rate Improvement')
axes[0, 0].set_xlabel('Learning Pass')
axes[0, 0].set_ylabel('Detection Rate (%)')
axes[0, 0].grid(True, alpha=0.3)

# 2. False Positive vs False Negative Rates
axes[0, 1].plot(df['pass_number'], df['false_positive_rate'] * 100, 'o-', label='False Positives', linewidth=2)
axes[0, 1].plot(df['pass_number'], df['false_negative_rate'] * 100, 's-', label='False Negatives', linewidth=2)
axes[0, 1].set_title('Error Rates Over Learning Passes')
axes[0, 1].set_xlabel('Learning Pass')
axes[0, 1].set_ylabel('Error Rate (%)')
axes[0, 1].legend()
axes[0, 1].grid(True, alpha=0.3)

# 3. Confidence Score Evolution
axes[0, 2].plot(df['pass_number'], df['confidence_score'], 'o-', color='green', linewidth=2, markersize=6)
axes[0, 2].set_title('System Confidence Evolution')
axes[0, 2].set_xlabel('Learning Pass')
axes[0, 2].set_ylabel('Confidence Score')
axes[0, 2].grid(True, alpha=0.3)

# 4. Memory Utilization
axes[1, 0].plot(df['pass_number'], df['memory_utilization'] * 100, 'o-', color='orange', linewidth=2, markersize=6)
axes[1, 0].set_title('Memory Utilization Growth')
axes[1, 0].set_xlabel('Learning Pass')
axes[1, 0].set_ylabel('Memory Utilization (%)')
axes[1, 0].grid(True, alpha=0.3)

# 5. EQ/IQ Balance
axes[1, 1].plot(df['pass_number'], df['eq_iq_balance'], 'o-', color='purple', linewidth=2, markersize=6)
axes[1, 1].axhline(y=0.5, color='red', linestyle='--', alpha=0.7, label='Perfect Balance')
axes[1, 1].set_title('EQ/IQ Balance Regulation')
axes[1, 1].set_xlabel('Learning Pass')
axes[1, 1].set_ylabel('EQ/IQ Balance')
axes[1, 1].legend()
axes[1, 1].grid(True, alpha=0.3)

# 6. Fear Mitigation and Experiential Context
ax6 = axes[1, 2]
ax6_twin = ax6.twinx()
line1 = ax6.plot(df['pass_number'], df['fear_mitigation_count'], 'o-', color='red', linewidth=2, label='Fear Mitigation')
line2 = ax6_twin.plot(df['pass_number'], df['experiential_context_usage'], 's-', color='blue', linewidth=2, label='Experiential Context')
ax6.set_title('Fear Mitigation & Experiential Learning')
ax6.set_xlabel('Learning Pass')
ax6.set_ylabel('Fear Mitigation Count', color='red')
ax6_twin.set_ylabel('Experiential Context Usage', color='blue')
lines = line1 + line2
labels = [l.get_label() for l in lines]
ax6.legend(lines, labels, loc='upper left')
ax6.grid(True, alpha=0.3)

# 7. Learning Efficiency
axes[2, 0].plot(df['pass_number'], df['learning_efficiency'] * 100, 'o-', color='teal', linewidth=2, markersize=6)
axes[2, 0].set_title('Learning Efficiency Over Time')
axes[2, 0].set_xlabel('Learning Pass')
axes[2, 0].set_ylabel('Learning Efficiency (%)')
axes[2, 0].grid(True, alpha=0.3)

# 8. Adaptation Speed
axes[2, 1].plot(df['pass_number'], df['adaptation_speed'], 'o-', color='brown', linewidth=2, markersize=6)
axes[2, 1].set_title('Adaptation Speed')
axes[2, 1].set_xlabel('Learning Pass')
axes[2, 1].set_ylabel('Adaptation Speed')
axes[2, 1].grid(True, alpha=0.3)

# 9. Response Time Performance
axes[2, 2].plot(df['pass_number'], df['response_time_ms'], 'o-', color='magenta', linewidth=2, markersize=6)
axes[2, 2].set_title('Response Time Performance')
axes[2, 2].set_xlabel('Learning Pass')
axes[2, 2].set_ylabel('Response Time (ms)')
axes[2, 2].grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('webguard_comprehensive_analysis.png', dpi=300, bbox_inches='tight')
plt.show()

# Generate summary statistics
print("=== WebGuard Multipass Learning Test Summary ===")
print(f"Initial Detection Rate: {df['threat_detection_rate'].iloc[0]*100:.1f}%")
print(f"Final Detection Rate: {df['threat_detection_rate'].iloc[-1]*100:.1f}%")
print(f"Total Improvement: {(df['threat_detection_rate'].iloc[-1] - df['threat_detection_rate'].iloc[0])*100:.1f}%")
print(f"Average Learning Efficiency: {df['learning_efficiency'].mean()*100:.1f}%")
print(f"Final False Negative Rate: {df['false_negative_rate'].iloc[-1]*100:.1f}%")
print(f"Final Confidence Score: {df['confidence_score'].iloc[-1]:.3f}")
print(f"Peak Memory Utilization: {df['memory_utilization'].max()*100:.1f}%")
print(f"Average Response Time: {df['response_time_ms'].mean():.2f}ms")
