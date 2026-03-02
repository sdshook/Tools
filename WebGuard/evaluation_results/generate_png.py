#!/usr/bin/env python3
"""Generate PNG visualization of WebGuard evaluation results."""

import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

def load_data():
    """Load evaluation data from JSON file."""
    with open(Path(__file__).parent / 'webguard_evaluation.json', 'r') as f:
        return json.load(f)

def create_evaluation_png(data):
    """Create a comprehensive PNG visualization."""
    
    # Extract multipass learning data
    passes = data['multipass_learning']
    pass_nums = [p['pass'] for p in passes]
    accuracy = [p['accuracy'] * 100 for p in passes]
    f1_scores = [p['f1_score'] * 100 for p in passes]
    fnr = [p['false_negative_rate'] * 100 for p in passes]
    fpr = [p['false_positive_rate'] * 100 for p in passes]
    
    # Create figure with subplots
    fig = plt.figure(figsize=(14, 10), facecolor='#1a1a2e')
    fig.suptitle('WebGuard Self-Learning EDR - Evaluation Results', 
                 fontsize=18, fontweight='bold', color='white', y=0.98)
    
    # Color scheme
    colors = {
        'accuracy': '#00d4aa',
        'f1': '#00a8e8',
        'fnr': '#ff6b6b',
        'fpr': '#ffd93d',
        'bg': '#1a1a2e',
        'grid': '#2d2d44',
        'text': '#ffffff'
    }
    
    # Panel 1: Learning Curve (Accuracy & F1)
    ax1 = fig.add_subplot(2, 2, 1, facecolor=colors['bg'])
    ax1.plot(pass_nums, accuracy, 'o-', color=colors['accuracy'], linewidth=2.5, 
             markersize=8, label='Accuracy')
    ax1.plot(pass_nums, f1_scores, 's-', color=colors['f1'], linewidth=2.5, 
             markersize=8, label='F1 Score')
    ax1.set_xlabel('Learning Pass', color=colors['text'], fontsize=11)
    ax1.set_ylabel('Score (%)', color=colors['text'], fontsize=11)
    ax1.set_title('Learning Curve', color=colors['text'], fontsize=13, fontweight='bold')
    ax1.legend(loc='lower right', facecolor=colors['bg'], labelcolor=colors['text'])
    ax1.set_ylim(0, 105)
    ax1.grid(True, alpha=0.3, color=colors['grid'])
    ax1.tick_params(colors=colors['text'])
    ax1.spines['bottom'].set_color(colors['grid'])
    ax1.spines['top'].set_color(colors['grid'])
    ax1.spines['left'].set_color(colors['grid'])
    ax1.spines['right'].set_color(colors['grid'])
    
    # Add annotations for key points
    ax1.annotate(f'{accuracy[0]:.1f}%', (pass_nums[0], accuracy[0]), 
                 textcoords="offset points", xytext=(0,10), ha='center', 
                 color=colors['accuracy'], fontsize=9)
    ax1.annotate(f'{accuracy[-1]:.1f}%', (pass_nums[-1], accuracy[-1]), 
                 textcoords="offset points", xytext=(0,10), ha='center', 
                 color=colors['accuracy'], fontsize=9)
    
    # Panel 2: Error Rates
    ax2 = fig.add_subplot(2, 2, 2, facecolor=colors['bg'])
    ax2.fill_between(pass_nums, fnr, alpha=0.3, color=colors['fnr'])
    ax2.fill_between(pass_nums, fpr, alpha=0.3, color=colors['fpr'])
    ax2.plot(pass_nums, fnr, 'o-', color=colors['fnr'], linewidth=2.5, 
             markersize=8, label='False Negative Rate')
    ax2.plot(pass_nums, fpr, 's-', color=colors['fpr'], linewidth=2.5, 
             markersize=8, label='False Positive Rate')
    ax2.set_xlabel('Learning Pass', color=colors['text'], fontsize=11)
    ax2.set_ylabel('Error Rate (%)', color=colors['text'], fontsize=11)
    ax2.set_title('Error Rate Reduction', color=colors['text'], fontsize=13, fontweight='bold')
    ax2.legend(loc='upper right', facecolor=colors['bg'], labelcolor=colors['text'])
    ax2.set_ylim(0, max(max(fnr), max(fpr)) * 1.1 + 5)
    ax2.grid(True, alpha=0.3, color=colors['grid'])
    ax2.tick_params(colors=colors['text'])
    ax2.spines['bottom'].set_color(colors['grid'])
    ax2.spines['top'].set_color(colors['grid'])
    ax2.spines['left'].set_color(colors['grid'])
    ax2.spines['right'].set_color(colors['grid'])
    
    # Add annotations
    ax2.annotate(f'{fnr[0]:.1f}%', (pass_nums[0], fnr[0]), 
                 textcoords="offset points", xytext=(10,0), ha='left', 
                 color=colors['fnr'], fontsize=9)
    ax2.annotate(f'{fnr[-1]:.1f}%', (pass_nums[-1], fnr[-1]), 
                 textcoords="offset points", xytext=(0,5), ha='center', 
                 color=colors['fnr'], fontsize=9)
    
    # Panel 3: Final Metrics (Bar Chart)
    ax3 = fig.add_subplot(2, 2, 3, facecolor=colors['bg'])
    final = passes[-1]
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
    values = [final['accuracy']*100, final['precision']*100, 
              final['recall']*100, final['f1_score']*100]
    bar_colors = [colors['accuracy'], colors['f1'], '#a855f7', '#22c55e']
    
    bars = ax3.bar(metrics, values, color=bar_colors, edgecolor='white', linewidth=1.5)
    ax3.set_ylabel('Score (%)', color=colors['text'], fontsize=11)
    ax3.set_title('Final Performance (Pass 9)', color=colors['text'], fontsize=13, fontweight='bold')
    ax3.set_ylim(0, 110)
    ax3.tick_params(colors=colors['text'])
    ax3.spines['bottom'].set_color(colors['grid'])
    ax3.spines['top'].set_color(colors['grid'])
    ax3.spines['left'].set_color(colors['grid'])
    ax3.spines['right'].set_color(colors['grid'])
    
    # Add value labels on bars
    for bar, val in zip(bars, values):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, 
                f'{val:.1f}%', ha='center', va='bottom', color=colors['text'], 
                fontsize=11, fontweight='bold')
    
    # Panel 4: Collective Immunity
    ax4 = fig.add_subplot(2, 2, 4, facecolor=colors['bg'])
    immunity = data['collective_immunity']
    servers = ['IIS', 'Apache', 'nginx', 'Node.js']
    immunity_accuracy = [
        immunity['iis_eval']['accuracy'] * 100,
        immunity['apache_eval']['accuracy'] * 100,
        immunity['nginx_eval']['accuracy'] * 100,
        immunity['node_eval']['accuracy'] * 100
    ]
    
    bars = ax4.bar(servers, immunity_accuracy, color='#8b5cf6', edgecolor='white', linewidth=1.5)
    ax4.set_ylabel('Threat Detection (%)', color=colors['text'], fontsize=11)
    ax4.set_title('Collective Immunity (Cross-Service)', color=colors['text'], fontsize=13, fontweight='bold')
    ax4.set_ylim(0, 110)
    ax4.tick_params(colors=colors['text'])
    ax4.spines['bottom'].set_color(colors['grid'])
    ax4.spines['top'].set_color(colors['grid'])
    ax4.spines['left'].set_color(colors['grid'])
    ax4.spines['right'].set_color(colors['grid'])
    
    # Add value labels
    for bar, val in zip(bars, immunity_accuracy):
        ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, 
                f'{val:.0f}%', ha='center', va='bottom', color=colors['text'], 
                fontsize=11, fontweight='bold')
    
    # Add summary text box
    summary_text = (
        f"Self-Learning Summary:\n"
        f"• Initial → Final Accuracy: {accuracy[0]:.1f}% → {accuracy[-1]:.1f}%\n"
        f"• FNR Reduction: {fnr[0]:.1f}% → {fnr[-1]:.1f}%\n"
        f"• Perfect Detection (100%) achieved at Pass 6\n"
        f"• 138 samples/pass × 10 passes = 1,380 total samples"
    )
    
    fig.text(0.5, 0.02, summary_text, ha='center', va='bottom', fontsize=10,
             color=colors['text'], family='monospace',
             bbox=dict(boxstyle='round', facecolor='#2d2d44', edgecolor='#4a4a6a', alpha=0.9))
    
    plt.tight_layout(rect=[0, 0.08, 1, 0.95])
    
    # Save PNG
    output_path = Path(__file__).parent / 'webguard_evaluation.png'
    plt.savefig(output_path, dpi=150, facecolor=colors['bg'], edgecolor='none',
                bbox_inches='tight', pad_inches=0.3)
    plt.close()
    
    print(f"PNG saved to: {output_path}")
    return output_path

if __name__ == '__main__':
    data = load_data()
    create_evaluation_png(data)
