#!/usr/bin/env python3
import json
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from pathlib import Path
from datetime import datetime

plt.style.use('seaborn-v0_8-whitegrid')

def load_data(results_dir):
    data = {}
    with open(results_dir / "comprehensive_learning_results.json", 'r') as f:
        data['results'] = json.load(f)
    data['progression'] = pd.read_csv(results_dir / "learning_progression.csv")
    data['multipass'] = pd.read_csv(results_dir / "multipass_results.csv")
    with open(results_dir / "attack_type_breakdown.json", 'r') as f:
        data['attacks'] = json.load(f)
    return data

def generate_dashboard(data, output_dir):
    print("📊 Generating dashboard...")
    fig = plt.figure(figsize=(20, 16))
    fig.suptitle('WebGuard Experiential Learning Dashboard', fontsize=20, fontweight='bold', y=0.98)
    gs = fig.add_gridspec(4, 4, hspace=0.35, wspace=0.3)
    
    results = data['results']
    progression = data['progression']
    multipass = data['multipass']
    attacks = data['attacks']
    
    ax1 = fig.add_subplot(gs[0, :])
    colors = {'Benign Training': '#3498db', 'Threat Introduction': '#e74c3c'}
    for phase in progression['phase'].unique():
        if 'Multipass' in str(phase):
            colors[phase] = '#2ecc71'
    for i, row in progression.iterrows():
        color = colors.get(row['phase'], '#2ecc71')
        ax1.bar(row['iteration'], row['accuracy'], color=color, alpha=0.7, width=0.8)
    ax1.set_xlabel('Iteration')
    ax1.set_ylabel('Accuracy')
    ax1.set_title('Learning Progression by Phase', fontweight='bold')
    ax1.set_ylim(0, 1)
    legend_patches = [mpatches.Patch(color='#3498db', label='Benign Training'),
                     mpatches.Patch(color='#e74c3c', label='Threat Introduction'),
                     mpatches.Patch(color='#2ecc71', label='Multipass Learning')]
    ax1.legend(handles=legend_patches, loc='upper right')
    
    ax2 = fig.add_subplot(gs[1, :2])
    attack_names = [a['attack_type'] for a in attacks]
    detection_rates = [a['detection_rate'] * 100 for a in attacks]
    colors_attack = plt.cm.RdYlGn([r/100 for r in detection_rates])
    bars = ax2.barh(attack_names, detection_rates, color=colors_attack)
    ax2.set_xlabel('Detection Rate (%)')
    ax2.set_title('Attack Type Detection Performance', fontweight='bold')
    ax2.set_xlim(0, 110)
    for bar, rate in zip(bars, detection_rates):
        ax2.text(rate + 2, bar.get_y() + bar.get_height()/2, f'{rate:.0f}%', va='center')
    
    ax3 = fig.add_subplot(gs[1, 2:])
    ax3.plot(multipass['pass_number'], multipass['f1_score'], 'o-', linewidth=2, markersize=10, color='#9b59b6')
    ax3.fill_between(multipass['pass_number'], multipass['f1_score'], alpha=0.3, color='#9b59b6')
    ax3.set_xlabel('Learning Pass')
    ax3.set_ylabel('F1 Score')
    ax3.set_title('Multipass Self-Learning Progression', fontweight='bold')
    
    ax4 = fig.add_subplot(gs[2, :2])
    ax4.plot(progression['iteration'], progression['true_positives'], 'g-', linewidth=2, label='True Pos', marker='o', markersize=4)
    ax4.plot(progression['iteration'], progression['true_negatives'], 'b-', linewidth=2, label='True Neg', marker='s', markersize=4)
    ax4.plot(progression['iteration'], progression['false_positives'], 'r-', linewidth=2, label='False Pos', marker='^', markersize=4)
    ax4.plot(progression['iteration'], progression['false_negatives'], 'm-', linewidth=2, label='False Neg', marker='d', markersize=4)
    ax4.set_xlabel('Iteration')
    ax4.set_ylabel('Count')
    ax4.set_title('Classification Results Over Time', fontweight='bold')
    ax4.legend(loc='upper right', fontsize=8)
    
    ax5 = fig.add_subplot(gs[2, 2:])
    ax5.plot(progression['iteration'], progression['cumulative_reward'], linewidth=2, color='#f39c12')
    ax5.fill_between(progression['iteration'], progression['cumulative_reward'], alpha=0.3, color='#f39c12')
    ax5.axhline(y=0, color='gray', linestyle='--', alpha=0.5)
    ax5.set_xlabel('Iteration')
    ax5.set_ylabel('Cumulative Reward')
    ax5.set_title('Reward System Performance', fontweight='bold')
    
    ax6 = fig.add_subplot(gs[3, :2])
    ax6.axis('off')
    summary = f"""
    FINAL RESULTS SUMMARY
    ─────────────────────────────────────
    Total Samples:      {results['total_samples_processed']:,}
    Patterns Learned:   {results['patterns_learned']}
    Final Accuracy:     {results['final_accuracy']*100:.1f}%
    Final Precision:    {results['final_precision']*100:.1f}%
    Final Recall:       {results['final_recall']*100:.1f}%
    Final F1 Score:     {results['final_f1_score']:.3f}
    """
    ax6.text(0.1, 0.5, summary, transform=ax6.transAxes, fontsize=12, verticalalignment='center',
             fontfamily='monospace', bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.8))
    
    ax7 = fig.add_subplot(gs[3, 2:])
    ax7.axis('off')
    rm = results['reward_metrics']
    reward = f"""
    REWARD SYSTEM ANALYSIS
    ─────────────────────────────────────
    Cumulative Reward:  {rm['total_rewards']:.2f}
    Positive Rewards:   {rm['positive_rewards']}
    Negative Rewards:   {rm['negative_rewards']}
    Reward Efficiency:  {rm['reward_efficiency']*100:.1f}%
    """
    ax7.text(0.1, 0.5, reward, transform=ax7.transAxes, fontsize=12, verticalalignment='center',
             fontfamily='monospace', bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))
    
    plt.savefig(output_dir / "experiential_learning_dashboard.png", dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print("  ✅ Dashboard saved")

def generate_attack_chart(data, output_dir):
    print("🎯 Generating attack detection chart...")
    attacks = data['attacks']
    fig, ax = plt.subplots(figsize=(12, 8))
    attack_names = [a['attack_type'] for a in attacks]
    detected = [a['detected'] for a in attacks]
    missed = [a['missed'] for a in attacks]
    x = np.arange(len(attack_names))
    width = 0.35
    ax.bar(x - width/2, detected, width, label='Detected', color='#2ecc71')
    ax.bar(x + width/2, missed, width, label='Missed', color='#e74c3c')
    ax.set_xlabel('Attack Type')
    ax.set_ylabel('Sample Count')
    ax.set_title('Attack Detection: Detected vs Missed', fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(attack_names, rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    (output_dir / "threat_detection").mkdir(exist_ok=True)
    plt.savefig(output_dir / "threat_detection" / "attack_detection_by_type.png", dpi=150, bbox_inches='tight')
    plt.close()

def generate_multipass(data, output_dir):
    print("🔄 Generating multipass analysis...")
    mp = data['multipass']
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Multipass Self-Learning Analysis', fontsize=16, fontweight='bold')
    axes[0, 0].plot(mp['pass_number'], mp['accuracy']*100, 'o-', linewidth=2, markersize=10, color='#3498db')
    axes[0, 0].set_xlabel('Pass')
    axes[0, 0].set_ylabel('Accuracy (%)')
    axes[0, 0].set_title('Accuracy per Pass')
    axes[0, 1].plot(mp['pass_number'], mp['precision']*100, 'o-', label='Precision', color='#e74c3c')
    axes[0, 1].plot(mp['pass_number'], mp['recall']*100, 's-', label='Recall', color='#2ecc71')
    axes[0, 1].set_xlabel('Pass')
    axes[0, 1].set_ylabel('Score (%)')
    axes[0, 1].set_title('Precision vs Recall')
    axes[0, 1].legend()
    axes[1, 0].bar(mp['pass_number'], mp['f1_score'], color='#9b59b6', alpha=0.8)
    axes[1, 0].set_xlabel('Pass')
    axes[1, 0].set_ylabel('F1 Score')
    axes[1, 0].set_title('F1 Score per Pass')
    axes[1, 1].bar(mp['pass_number'], mp['improvement'], color='#f39c12', alpha=0.8)
    axes[1, 1].axhline(y=0, color='gray', linestyle='--')
    axes[1, 1].set_xlabel('Pass')
    axes[1, 1].set_ylabel('Improvement')
    axes[1, 1].set_title('Pass-to-Pass Improvement')
    plt.tight_layout()
    (output_dir / "multipass_learning").mkdir(exist_ok=True)
    plt.savefig(output_dir / "multipass_learning" / "multipass_analysis.png", dpi=150, bbox_inches='tight')
    plt.close()

def generate_reward(data, output_dir):
    print("🎁 Generating reward analysis...")
    prog = data['progression']
    rm = data['results']['reward_metrics']
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Reward System Analysis', fontsize=16, fontweight='bold')
    axes[0, 0].plot(prog['iteration'], prog['cumulative_reward'], linewidth=2, color='#f39c12')
    axes[0, 0].fill_between(prog['iteration'], prog['cumulative_reward'], alpha=0.3, color='#f39c12')
    axes[0, 0].axhline(y=0, color='gray', linestyle='--')
    axes[0, 0].set_xlabel('Iteration')
    axes[0, 0].set_ylabel('Cumulative Reward')
    axes[0, 0].set_title('Cumulative Reward Over Time')
    axes[0, 1].bar(prog['iteration'], prog['reward_delta'], color='#3498db', alpha=0.7)
    axes[0, 1].set_xlabel('Iteration')
    axes[0, 1].set_ylabel('Reward Delta')
    axes[0, 1].set_title('Reward per Iteration')
    axes[1, 0].pie([rm['positive_rewards'], rm['negative_rewards']], labels=['Positive', 'Negative'],
                   colors=['#2ecc71', '#e74c3c'], autopct='%1.1f%%')
    axes[1, 0].set_title('Reward Distribution')
    eff = rm['reward_efficiency'] * 100
    axes[1, 1].barh(['Efficiency'], [eff], color='#9b59b6')
    axes[1, 1].barh(['Efficiency'], [100-eff], left=[eff], color='lightgray')
    axes[1, 1].set_xlim(0, 100)
    axes[1, 1].set_xlabel('Efficiency (%)')
    axes[1, 1].set_title(f'Reward Efficiency: {eff:.1f}%')
    plt.tight_layout()
    (output_dir / "reward_analysis").mkdir(exist_ok=True)
    plt.savefig(output_dir / "reward_analysis" / "reward_system_analysis.png", dpi=150, bbox_inches='tight')
    plt.close()

def generate_report(data, output_dir):
    print("📝 Generating report...")
    r = data['results']
    rm = r['reward_metrics']
    report = f"""# WebGuard Experiential Learning Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

| Metric | Value |
|--------|-------|
| Total Samples | {r['total_samples_processed']:,} |
| Patterns Learned | {r['patterns_learned']} |
| Final Accuracy | {r['final_accuracy']*100:.1f}% |
| Final Precision | {r['final_precision']*100:.1f}% |
| Final Recall | {r['final_recall']*100:.1f}% |
| Final F1 | {r['final_f1_score']:.3f} |

## Attack Detection

| Attack Type | Detected | Missed | Rate |
|-------------|----------|--------|------|
"""
    for a in r['threat_samples_by_type']:
        report += f"| {a['attack_type']} | {a['detected']} | {a['missed']} | {a['detection_rate']*100:.0f}% |\n"
    report += f"""
## Multipass Learning

| Pass | F1 Score | Improvement |
|------|----------|-------------|
"""
    for m in r['multipass_results']:
        report += f"| {m['pass_number']} | {m['f1_score']:.3f} | {m['improvement_from_previous']:+.3f} |\n"
    report += f"""
## Reward System

| Metric | Value |
|--------|-------|
| Total Reward | {rm['total_rewards']:.2f} |
| Positive | {rm['positive_rewards']} |
| Negative | {rm['negative_rewards']} |
| Efficiency | {rm['reward_efficiency']*100:.1f}% |
"""
    with open(output_dir / "WebGuard_Experiential_Learning_Report.md", 'w') as f:
        f.write(report)

def main():
    results_dir = Path("../results")
    output_dir = Path("../results")
    print("╔════════════════════════════════════════════════════╗")
    print("║  WebGuard Visualization Generator                  ║")
    print("╚════════════════════════════════════════════════════╝")
    data = load_data(results_dir)
    generate_dashboard(data, output_dir)
    generate_attack_chart(data, output_dir)
    generate_multipass(data, output_dir)
    generate_reward(data, output_dir)
    generate_report(data, output_dir)
    print("\n✅ All visualizations generated!")
    print(f"📁 Output: {output_dir.resolve()}")

if __name__ == "__main__":
    main()
