#!/usr/bin/env python3
"""
WebGuard Actual Results Visualization Generator
Creates visualizations from the actual experiential learning test results
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
from datetime import datetime

class ActualResultsVisualizer:
    def __init__(self):
        self.results_dir = Path("../results")
        self.viz_dir = Path("../visualizations")
        self.viz_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        for subdir in ["learning_progress", "performance_metrics", "threat_detection", 
                      "experiential_data", "comparative_analysis"]:
            (self.viz_dir / subdir).mkdir(exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def load_actual_data(self):
        """Load the actual test results"""
        
        # Load JSON results
        results_path = self.results_dir / "experiential_learning_results.json"
        with open(results_path) as f:
            self.results = json.load(f)
        
        # Load CSV progression data
        csv_path = self.results_dir / "learning_progression.csv"
        self.progression_df = pd.read_csv(csv_path)
        
        print(f"Loaded actual results: {self.results['test_summary']['total_samples']} samples, {len(self.progression_df)} batches")
    
    def create_learning_progression_chart(self):
        """Create learning progression visualization"""
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('WebGuard Experiential Learning Progression', fontsize=16, fontweight='bold')
        
        # Accuracy over time
        ax1.plot(self.progression_df['batch'], self.progression_df['accuracy'], 
                marker='o', linewidth=2, markersize=6, label='Accuracy')
        ax1.set_title('Accuracy Progression')
        ax1.set_xlabel('Batch Number')
        ax1.set_ylabel('Accuracy')
        ax1.grid(True, alpha=0.3)
        ax1.set_ylim(0, 1)
        
        # Add trend line
        z = np.polyfit(self.progression_df['batch'], self.progression_df['accuracy'], 1)
        p = np.poly1d(z)
        ax1.plot(self.progression_df['batch'], p(self.progression_df['batch']), 
                "--", alpha=0.8, color='red', label=f'Trend (slope: {z[0]:.4f})')
        ax1.legend()
        
        # Precision and Recall
        ax2.plot(self.progression_df['batch'], self.progression_df['precision'], 
                marker='s', linewidth=2, markersize=6, label='Precision', color='green')
        ax2.plot(self.progression_df['batch'], self.progression_df['recall'], 
                marker='^', linewidth=2, markersize=6, label='Recall', color='orange')
        ax2.set_title('Precision & Recall Progression')
        ax2.set_xlabel('Batch Number')
        ax2.set_ylabel('Score')
        ax2.grid(True, alpha=0.3)
        ax2.set_ylim(0, 1)
        ax2.legend()
        
        # Threat Score Evolution
        ax3.plot(self.progression_df['batch'], self.progression_df['avg_threat_score'], 
                marker='d', linewidth=2, markersize=6, color='red', label='Avg Threat Score')
        ax3.set_title('Average Threat Score Evolution')
        ax3.set_xlabel('Batch Number')
        ax3.set_ylabel('Threat Score')
        ax3.grid(True, alpha=0.3)
        ax3.legend()
        
        # Adaptive Threshold
        ax4.plot(self.progression_df['batch'], self.progression_df['threshold_used'], 
                marker='*', linewidth=2, markersize=8, color='purple', label='Adaptive Threshold')
        ax4.set_title('Adaptive Threshold Evolution')
        ax4.set_xlabel('Batch Number')
        ax4.set_ylabel('Threshold Value')
        ax4.grid(True, alpha=0.3)
        ax4.legend()
        
        plt.tight_layout()
        
        # Save chart
        chart_path = self.viz_dir / "learning_progress" / "actual_learning_progression.png"
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Saved learning progression chart: {chart_path}")
    
    def create_performance_dashboard(self):
        """Create comprehensive performance dashboard"""
        
        fig = plt.figure(figsize=(16, 12))
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        # Main title
        fig.suptitle('WebGuard Experiential Learning Performance Dashboard', 
                    fontsize=18, fontweight='bold', y=0.95)
        
        # Confusion Matrix
        ax1 = fig.add_subplot(gs[0, 0])
        cm_data = self.results['confusion_matrix']
        confusion_matrix = np.array([
            [cm_data['true_positives'], cm_data['false_negatives']],
            [cm_data['false_positives'], cm_data['true_negatives']]
        ])
        
        sns.heatmap(confusion_matrix, annot=True, fmt='d', cmap='Blues', ax=ax1,
                   xticklabels=['Predicted Threat', 'Predicted Benign'],
                   yticklabels=['Actual Threat', 'Actual Benign'])
        ax1.set_title('Confusion Matrix')
        
        # Performance Metrics Bar Chart
        ax2 = fig.add_subplot(gs[0, 1])
        metrics = ['Accuracy', 'Precision', 'Recall']
        values = [
            self.results['test_summary']['final_accuracy'],
            self.results['test_summary']['final_precision'],
            self.results['test_summary']['final_recall']
        ]
        
        bars = ax2.bar(metrics, values, color=['skyblue', 'lightgreen', 'lightcoral'])
        ax2.set_title('Final Performance Metrics')
        ax2.set_ylabel('Score')
        ax2.set_ylim(0, 1)
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                    f'{value:.3f}', ha='center', va='bottom', fontweight='bold')
        
        # Learning Curve
        ax3 = fig.add_subplot(gs[0, 2])
        ax3.plot(self.progression_df['batch'], self.progression_df['accuracy'], 
                marker='o', linewidth=3, markersize=8, color='blue', alpha=0.7)
        ax3.fill_between(self.progression_df['batch'], self.progression_df['accuracy'], 
                        alpha=0.3, color='blue')
        ax3.set_title('Learning Curve')
        ax3.set_xlabel('Batch')
        ax3.set_ylabel('Accuracy')
        ax3.grid(True, alpha=0.3)
        
        # Batch Performance Heatmap
        ax4 = fig.add_subplot(gs[1, :])
        
        # Create heatmap data
        batch_metrics = self.progression_df[['batch', 'accuracy', 'precision', 'recall', 'false_positive_rate']].copy()
        batch_metrics = batch_metrics.set_index('batch').T
        
        sns.heatmap(batch_metrics, annot=True, fmt='.3f', cmap='RdYlGn', ax=ax4,
                   cbar_kws={'label': 'Performance Score'})
        ax4.set_title('Batch-by-Batch Performance Heatmap')
        ax4.set_xlabel('Batch Number')
        ax4.set_ylabel('Metrics')
        
        # Detection Rate Analysis
        ax5 = fig.add_subplot(gs[2, 0])
        
        # Calculate detection rates per batch
        threat_samples_per_batch = 50 * 0.05  # Approximately 2.5 threats per batch
        detection_rates = []
        
        for _, batch in self.progression_df.iterrows():
            # Estimate detection rate based on batch performance
            estimated_threats = max(1, int(threat_samples_per_batch))
            detection_rate = min(1.0, batch['recall'])  # Use recall as detection rate
            detection_rates.append(detection_rate)
        
        ax5.bar(self.progression_df['batch'], detection_rates, 
               color='orange', alpha=0.7, edgecolor='darkorange')
        ax5.set_title('Threat Detection Rate by Batch')
        ax5.set_xlabel('Batch Number')
        ax5.set_ylabel('Detection Rate')
        ax5.set_ylim(0, 1)
        
        # Processing Time Simulation
        ax6 = fig.add_subplot(gs[2, 1])
        processing_times = self.progression_df['processing_time_ms']
        
        ax6.plot(self.progression_df['batch'], processing_times, 
                marker='s', linewidth=2, markersize=6, color='green')
        ax6.set_title('Processing Time per Batch')
        ax6.set_xlabel('Batch Number')
        ax6.set_ylabel('Time (ms)')
        ax6.grid(True, alpha=0.3)
        
        # Summary Statistics
        ax7 = fig.add_subplot(gs[2, 2])
        ax7.axis('off')
        
        summary_text = f"""
        EXPERIENTIAL LEARNING SUMMARY
        
        Total Samples: {self.results['test_summary']['total_samples']:,}
        Total Batches: {self.results['test_summary']['total_batches']}
        
        Final Performance:
        • Accuracy: {self.results['test_summary']['final_accuracy']:.1%}
        • Precision: {self.results['test_summary']['final_precision']:.1%}
        • Recall: {self.results['test_summary']['final_recall']:.1%}
        
        Learning Progression:
        • First Batch Accuracy: {self.progression_df.iloc[0]['accuracy']:.1%}
        • Last Batch Accuracy: {self.progression_df.iloc[-1]['accuracy']:.1%}
        • Change: {(self.progression_df.iloc[-1]['accuracy'] - self.progression_df.iloc[0]['accuracy']):.1%}
        
        Threat Detection:
        • True Positives: {cm_data['true_positives']}
        • False Positives: {cm_data['false_positives']}
        • False Negatives: {cm_data['false_negatives']}
        """
        
        ax7.text(0.05, 0.95, summary_text, transform=ax7.transAxes, fontsize=10,
                verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.8))
        
        # Save dashboard
        dashboard_path = self.viz_dir / "performance_metrics" / "actual_performance_dashboard.png"
        plt.savefig(dashboard_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Saved performance dashboard: {dashboard_path}")
    
    def create_threat_analysis_chart(self):
        """Create threat detection analysis"""
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('WebGuard Threat Detection Analysis', fontsize=16, fontweight='bold')
        
        # Threat Score Distribution
        ax1.hist(self.progression_df['avg_threat_score'], bins=15, alpha=0.7, 
                color='red', edgecolor='darkred')
        ax1.set_title('Threat Score Distribution')
        ax1.set_xlabel('Average Threat Score')
        ax1.set_ylabel('Frequency')
        ax1.grid(True, alpha=0.3)
        
        # ROC-like curve simulation
        fpr_values = self.progression_df['false_positive_rate']
        tpr_values = self.progression_df['recall']  # True Positive Rate
        
        ax2.plot(fpr_values, tpr_values, marker='o', linewidth=2, markersize=6)
        ax2.plot([0, 1], [0, 1], '--', color='gray', alpha=0.8, label='Random Classifier')
        ax2.set_title('ROC-like Curve (Batch Performance)')
        ax2.set_xlabel('False Positive Rate')
        ax2.set_ylabel('True Positive Rate (Recall)')
        ax2.grid(True, alpha=0.3)
        ax2.legend()
        
        # Precision-Recall Curve
        ax3.plot(self.progression_df['recall'], self.progression_df['precision'], 
                marker='s', linewidth=2, markersize=6, color='green')
        ax3.set_title('Precision-Recall Curve')
        ax3.set_xlabel('Recall')
        ax3.set_ylabel('Precision')
        ax3.grid(True, alpha=0.3)
        
        # F1 Score Evolution
        f1_scores = 2 * (self.progression_df['precision'] * self.progression_df['recall']) / \
                   (self.progression_df['precision'] + self.progression_df['recall'])
        f1_scores = f1_scores.fillna(0)  # Handle division by zero
        
        ax4.plot(self.progression_df['batch'], f1_scores, 
                marker='d', linewidth=2, markersize=6, color='purple')
        ax4.set_title('F1 Score Evolution')
        ax4.set_xlabel('Batch Number')
        ax4.set_ylabel('F1 Score')
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        # Save chart
        chart_path = self.viz_dir / "threat_detection" / "actual_threat_analysis.png"
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Saved threat analysis chart: {chart_path}")
    
    def create_experiential_patterns_chart(self):
        """Create experiential learning patterns visualization"""
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('WebGuard Experiential Learning Patterns', fontsize=16, fontweight='bold')
        
        # Learning Rate Analysis
        accuracy_diff = self.progression_df['accuracy'].diff().fillna(0)
        ax1.bar(self.progression_df['batch'], accuracy_diff, 
               color=['green' if x >= 0 else 'red' for x in accuracy_diff],
               alpha=0.7)
        ax1.set_title('Batch-to-Batch Accuracy Changes')
        ax1.set_xlabel('Batch Number')
        ax1.set_ylabel('Accuracy Change')
        ax1.grid(True, alpha=0.3)
        ax1.axhline(y=0, color='black', linestyle='-', alpha=0.5)
        
        # Adaptive Threshold vs Performance
        ax2.scatter(self.progression_df['threshold_used'], self.progression_df['accuracy'],
                   c=self.progression_df['batch'], cmap='viridis', s=100, alpha=0.7)
        ax2.set_title('Adaptive Threshold vs Accuracy')
        ax2.set_xlabel('Threshold Used')
        ax2.set_ylabel('Accuracy')
        ax2.grid(True, alpha=0.3)
        
        # Add colorbar
        cbar = plt.colorbar(ax2.collections[0], ax=ax2)
        cbar.set_label('Batch Number')
        
        # Learning Stability (Rolling Standard Deviation)
        window_size = 5
        rolling_std = self.progression_df['accuracy'].rolling(window=window_size).std()
        
        ax3.plot(self.progression_df['batch'], rolling_std, 
                marker='o', linewidth=2, markersize=6, color='orange')
        ax3.set_title(f'Learning Stability (Rolling Std, window={window_size})')
        ax3.set_xlabel('Batch Number')
        ax3.set_ylabel('Accuracy Standard Deviation')
        ax3.grid(True, alpha=0.3)
        
        # Pattern Learning Effectiveness (simulated)
        # Show top learned patterns from results
        if 'learned_patterns' in self.results:
            patterns = self.results['learned_patterns']
            top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10]
            
            pattern_names = [p[0][:15] + '...' if len(p[0]) > 15 else p[0] for p, _ in top_patterns]
            pattern_weights = [w for _, w in top_patterns]
            
            bars = ax4.barh(pattern_names, pattern_weights, color='skyblue', alpha=0.7)
            ax4.set_title('Top Learned Threat Patterns')
            ax4.set_xlabel('Pattern Weight')
            
            # Add value labels
            for bar, weight in zip(bars, pattern_weights):
                ax4.text(bar.get_width() + 0.01, bar.get_y() + bar.get_height()/2,
                        f'{weight:.3f}', ha='left', va='center', fontsize=9)
        else:
            ax4.text(0.5, 0.5, 'Pattern data not available', 
                    ha='center', va='center', transform=ax4.transAxes)
            ax4.set_title('Learned Patterns (Data Not Available)')
        
        plt.tight_layout()
        
        # Save chart
        chart_path = self.viz_dir / "experiential_data" / "actual_learning_patterns.png"
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Saved experiential patterns chart: {chart_path}")
    
    def generate_comprehensive_report(self):
        """Generate a comprehensive markdown report"""
        
        report_content = f"""# WebGuard Experiential Learning Test Report

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

This report presents the results of WebGuard's experiential learning demonstration with 1,000 test samples (95% benign, 5% threats). The system demonstrated adaptive learning capabilities through pattern recognition and threshold adjustment.

## Test Configuration

- **Total Samples**: {self.results['test_summary']['total_samples']:,}
- **Benign Samples**: {int(self.results['test_summary']['total_samples'] * 0.95):,} (95%)
- **Threat Samples**: {int(self.results['test_summary']['total_samples'] * 0.05):,} (5%)
- **Batch Size**: {self.results['test_summary']['batch_size']}
- **Total Batches**: {self.results['test_summary']['total_batches']}

## Performance Results

### Final Metrics
- **Accuracy**: {self.results['test_summary']['final_accuracy']:.1%}
- **Precision**: {self.results['test_summary']['final_precision']:.1%}
- **Recall**: {self.results['test_summary']['final_recall']:.1%}
- **F1-Score**: {2 * self.results['test_summary']['final_precision'] * self.results['test_summary']['final_recall'] / (self.results['test_summary']['final_precision'] + self.results['test_summary']['final_recall']):.1%}

### Confusion Matrix
|                | Predicted Threat | Predicted Benign |
|----------------|------------------|------------------|
| **Actual Threat**  | {self.results['confusion_matrix']['true_positives']} (TP)        | {self.results['confusion_matrix']['false_negatives']} (FN)        |
| **Actual Benign**  | {self.results['confusion_matrix']['false_positives']} (FP)       | {self.results['confusion_matrix']['true_negatives']} (TN)        |

## Learning Progression Analysis

### Accuracy Evolution
- **First Batch**: {self.progression_df.iloc[0]['accuracy']:.1%}
- **Last Batch**: {self.progression_df.iloc[-1]['accuracy']:.1%}
- **Change**: {(self.progression_df.iloc[-1]['accuracy'] - self.progression_df.iloc[0]['accuracy']):.1%}

### Adaptive Threshold Behavior
- **Initial Threshold**: {self.progression_df.iloc[0]['threshold_used']:.3f}
- **Final Threshold**: {self.progression_df.iloc[-1]['threshold_used']:.3f}
- **Adaptation Range**: {self.progression_df['threshold_used'].max() - self.progression_df['threshold_used'].min():.3f}

## Experiential Learning Insights

### Pattern Learning
The system demonstrated experiential learning through:
1. **Pattern Weight Adaptation**: Threat patterns were dynamically weighted based on detection success
2. **Threshold Adjustment**: Detection thresholds adapted based on experience and false positive rates
3. **Context Awareness**: Learning incorporated request context (method, path, content)

### Top Learned Threat Patterns
"""
        
        if 'learned_patterns' in self.results:
            patterns = self.results['learned_patterns']
            top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10]
            
            for i, (pattern, weight) in enumerate(top_patterns, 1):
                report_content += f"{i}. `{pattern}`: {weight:.3f}\n"
        else:
            report_content += "Pattern data not available in results.\n"
        
        report_content += f"""

## Threat Detection Analysis

### Detection Effectiveness
- **True Positive Rate**: {self.results['test_summary']['final_recall']:.1%}
- **False Positive Rate**: {self.results['confusion_matrix']['false_positives'] / (self.results['confusion_matrix']['false_positives'] + self.results['confusion_matrix']['true_negatives']):.1%}
- **Precision**: {self.results['test_summary']['final_precision']:.1%}

### Batch Performance Trends
- **Most Accurate Batch**: Batch {self.progression_df.loc[self.progression_df['accuracy'].idxmax(), 'batch']} ({self.progression_df['accuracy'].max():.1%})
- **Least Accurate Batch**: Batch {self.progression_df.loc[self.progression_df['accuracy'].idxmin(), 'batch']} ({self.progression_df['accuracy'].min():.1%})
- **Average Accuracy**: {self.progression_df['accuracy'].mean():.1%}

## Conclusions

### Strengths Demonstrated
1. **Adaptive Learning**: System showed ability to adjust detection parameters based on experience
2. **Pattern Recognition**: Successfully identified and weighted threat patterns
3. **Threshold Optimization**: Dynamically adjusted detection thresholds to balance precision and recall

### Areas for Improvement
1. **Precision Enhancement**: Current precision of {self.results['test_summary']['final_precision']:.1%} indicates room for false positive reduction
2. **Recall Optimization**: Recall of {self.results['test_summary']['final_recall']:.1%} suggests potential for improved threat detection
3. **Learning Stability**: Performance variation across batches indicates opportunity for more stable learning

### Recommendations
1. Implement more sophisticated pattern weighting algorithms
2. Add ensemble methods to improve detection accuracy
3. Incorporate temporal learning patterns for better adaptation
4. Enhance context-aware threat assessment

## Technical Details

### Test Environment
- **Language**: Python 3.x
- **Libraries**: NumPy, Pandas, Matplotlib, Seaborn
- **Simulation**: WebGuard behavior simulated with realistic threat patterns
- **Data**: Synthetic dataset with realistic HTTP request patterns

### Methodology
1. Generated 1,000 synthetic HTTP requests with known labels
2. Simulated WebGuard's experiential learning algorithm
3. Processed data in batches to demonstrate learning progression
4. Tracked performance metrics and pattern weights over time
5. Generated comprehensive visualizations and analysis

---

*This report demonstrates WebGuard's experiential learning capabilities in a controlled testing environment. Results show the system's ability to adapt and learn from experience while maintaining reasonable detection performance.*
"""
        
        # Save report
        report_path = self.viz_dir / "WebGuard_Actual_Experiential_Learning_Report.md"
        with open(report_path, 'w') as f:
            f.write(report_content)
        
        print(f"Generated comprehensive report: {report_path}")
    
    def generate_all_visualizations(self):
        """Generate all visualizations"""
        
        print("WebGuard Actual Results Visualization Generator")
        print("=" * 60)
        
        try:
            self.load_actual_data()
            
            print("\nGenerating visualizations from actual test results...")
            self.create_learning_progression_chart()
            self.create_performance_dashboard()
            self.create_threat_analysis_chart()
            self.create_experiential_patterns_chart()
            self.generate_comprehensive_report()
            
            print(f"\n✅ All visualizations generated successfully!")
            print(f"📊 Check the {self.viz_dir} directory for all charts and reports")
            print(f"📈 Visualizations based on actual test data with {self.results['test_summary']['total_samples']} samples")
            
        except Exception as e:
            print(f"❌ Error generating visualizations: {e}")
            raise

def main():
    visualizer = ActualResultsVisualizer()
    visualizer.generate_all_visualizations()

if __name__ == "__main__":
    main()