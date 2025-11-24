#!/usr/bin/env python3
"""
WebGuard Comprehensive Visualization Generator
Creates detailed visualizations for experiential learning test results
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Set style for better-looking plots
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

class WebGuardVisualizer:
    def __init__(self, results_dir="tests/results", viz_dir="tests/visualizations"):
        self.results_dir = Path(results_dir)
        self.viz_dir = Path(viz_dir)
        self.viz_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        for subdir in ["learning_progress", "performance_metrics", "threat_detection", 
                      "experiential_data", "comparative_analysis"]:
            (self.viz_dir / subdir).mkdir(exist_ok=True)
    
    def load_data(self):
        """Load test results and progression data"""
        try:
            # Load main results
            results_path = self.results_dir / "experiential_learning_results.json"
            if results_path.exists():
                with open(results_path) as f:
                    self.results = json.load(f)
            else:
                print(f"Warning: {results_path} not found, using sample data")
                self.results = self.generate_sample_results()
            
            # Load progression data
            progression_path = self.results_dir / "learning_progression.csv"
            if progression_path.exists():
                self.progression_df = pd.read_csv(progression_path)
            else:
                print(f"Warning: {progression_path} not found, generating sample data")
                self.progression_df = self.generate_sample_progression()
                
            print(f"Loaded data: {len(self.progression_df)} batches, {self.results['total_samples']} total samples")
            
        except Exception as e:
            print(f"Error loading data: {e}")
            print("Generating sample data for demonstration...")
            self.results = self.generate_sample_results()
            self.progression_df = self.generate_sample_progression()
    
    def generate_sample_results(self):
        """Generate sample results for demonstration"""
        return {
            "total_samples": 1000,
            "benign_samples": 950,
            "threat_samples": 50,
            "true_positives": 42,
            "false_positives": 28,
            "true_negatives": 922,
            "false_negatives": 8,
            "accuracy": 0.964,
            "precision": 0.6,
            "recall": 0.84,
            "f1_score": 0.7,
            "processing_time_ms": 15420,
            "threat_type_performance": {
                "sql_injection": {"total_samples": 21, "detected": 18, "detection_rate": 0.857, "avg_confidence": 0.78},
                "xss": {"total_samples": 2, "detected": 2, "detection_rate": 1.0, "avg_confidence": 0.92},
                "command_injection": {"total_samples": 14, "detected": 12, "detection_rate": 0.857, "avg_confidence": 0.71},
                "path_traversal": {"total_samples": 6, "detected": 5, "detection_rate": 0.833, "avg_confidence": 0.68},
                "ssrf": {"total_samples": 6, "detected": 4, "detection_rate": 0.667, "avg_confidence": 0.65},
                "ldap_injection": {"total_samples": 1, "detected": 1, "detection_rate": 1.0, "avg_confidence": 0.89}
            }
        }
    
    def generate_sample_progression(self):
        """Generate sample learning progression data"""
        batches = 20
        data = []
        
        # Simulate learning progression with some noise
        base_accuracy = 0.85
        base_precision = 0.55
        base_recall = 0.70
        
        for i in range(1, batches + 1):
            # Add learning improvement with some randomness
            improvement = (i - 1) * 0.01 + np.random.normal(0, 0.02)
            noise = np.random.normal(0, 0.01)
            
            accuracy = min(0.98, base_accuracy + improvement + noise)
            precision = min(0.95, base_precision + improvement * 1.2 + noise)
            recall = min(0.95, base_recall + improvement * 0.8 + noise)
            fpr = max(0.01, 0.05 - improvement * 0.5 + abs(noise))
            
            data.append({
                "batch": i,
                "samples_processed": i * 50,
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "false_positive_rate": fpr,
                "processing_time_ms": np.random.randint(200, 800)
            })
        
        return pd.DataFrame(data)
    
    def create_learning_progression_charts(self):
        """Create charts showing learning progression over time"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('WebGuard Experiential Learning Progression', fontsize=16, fontweight='bold')
        
        # Accuracy progression
        axes[0, 0].plot(self.progression_df['batch'], self.progression_df['accuracy'] * 100, 
                       marker='o', linewidth=2, markersize=4)
        axes[0, 0].set_title('Accuracy Improvement Over Time')
        axes[0, 0].set_xlabel('Batch Number')
        axes[0, 0].set_ylabel('Accuracy (%)')
        axes[0, 0].grid(True, alpha=0.3)
        axes[0, 0].set_ylim(80, 100)
        
        # Precision and Recall
        axes[0, 1].plot(self.progression_df['batch'], self.progression_df['precision'] * 100, 
                       marker='s', label='Precision', linewidth=2, markersize=4)
        axes[0, 1].plot(self.progression_df['batch'], self.progression_df['recall'] * 100, 
                       marker='^', label='Recall', linewidth=2, markersize=4)
        axes[0, 1].set_title('Precision vs Recall Progression')
        axes[0, 1].set_xlabel('Batch Number')
        axes[0, 1].set_ylabel('Percentage (%)')
        axes[0, 1].legend()
        axes[0, 1].grid(True, alpha=0.3)
        
        # False Positive Rate
        axes[1, 0].plot(self.progression_df['batch'], self.progression_df['false_positive_rate'] * 100, 
                       marker='d', color='red', linewidth=2, markersize=4)
        axes[1, 0].set_title('False Positive Rate Reduction')
        axes[1, 0].set_xlabel('Batch Number')
        axes[1, 0].set_ylabel('False Positive Rate (%)')
        axes[1, 0].grid(True, alpha=0.3)
        
        # Processing Time
        axes[1, 1].bar(self.progression_df['batch'], self.progression_df['processing_time_ms'], 
                      alpha=0.7, color='green')
        axes[1, 1].set_title('Processing Time per Batch')
        axes[1, 1].set_xlabel('Batch Number')
        axes[1, 1].set_ylabel('Processing Time (ms)')
        axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        # Save the plot
        save_path = self.viz_dir / "learning_progress" / "learning_progression_overview.png"
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.svg'), bbox_inches='tight')
        print(f"Saved learning progression chart: {save_path}")
        plt.close()
    
    def create_performance_metrics_dashboard(self):
        """Create comprehensive performance metrics dashboard"""
        fig = plt.figure(figsize=(16, 12))
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        # Confusion Matrix
        ax1 = fig.add_subplot(gs[0, 0])
        confusion_matrix = np.array([
            [self.results['true_negatives'], self.results['false_positives']],
            [self.results['false_negatives'], self.results['true_positives']]
        ])
        sns.heatmap(confusion_matrix, annot=True, fmt='d', cmap='Blues', ax=ax1,
                   xticklabels=['Predicted Benign', 'Predicted Threat'],
                   yticklabels=['Actual Benign', 'Actual Threat'])
        ax1.set_title('Confusion Matrix')
        
        # Performance Metrics Bar Chart
        ax2 = fig.add_subplot(gs[0, 1])
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        values = [self.results['accuracy'], self.results['precision'], 
                 self.results['recall'], self.results['f1_score']]
        bars = ax2.bar(metrics, [v * 100 for v in values], color=['skyblue', 'lightgreen', 'lightcoral', 'gold'])
        ax2.set_title('Performance Metrics')
        ax2.set_ylabel('Percentage (%)')
        ax2.set_ylim(0, 100)
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
                    f'{value*100:.1f}%', ha='center', va='bottom')
        
        # Sample Distribution Pie Chart
        ax3 = fig.add_subplot(gs[0, 2])
        sizes = [self.results['benign_samples'], self.results['threat_samples']]
        labels = ['Benign (95%)', 'Threats (5%)']
        colors = ['lightblue', 'lightcoral']
        ax3.pie(sizes, labels=labels, colors=colors, autopct='%1.0f', startangle=90)
        ax3.set_title('Dataset Distribution')
        
        # Threat Type Performance
        ax4 = fig.add_subplot(gs[1, :])
        threat_types = list(self.results['threat_type_performance'].keys())
        detection_rates = [self.results['threat_type_performance'][t]['detection_rate'] * 100 
                          for t in threat_types]
        avg_confidences = [self.results['threat_type_performance'][t]['avg_confidence'] * 100 
                          for t in threat_types]
        
        x = np.arange(len(threat_types))
        width = 0.35
        
        bars1 = ax4.bar(x - width/2, detection_rates, width, label='Detection Rate (%)', alpha=0.8)
        bars2 = ax4.bar(x + width/2, avg_confidences, width, label='Avg Confidence (%)', alpha=0.8)
        
        ax4.set_xlabel('Threat Types')
        ax4.set_ylabel('Percentage (%)')
        ax4.set_title('Threat Type Detection Performance')
        ax4.set_xticks(x)
        ax4.set_xticklabels(threat_types, rotation=45, ha='right')
        ax4.legend()
        ax4.grid(True, alpha=0.3)
        
        # Learning Curve
        ax5 = fig.add_subplot(gs[2, :])
        ax5.plot(self.progression_df['samples_processed'], self.progression_df['accuracy'] * 100, 
                marker='o', label='Accuracy', linewidth=2)
        ax5.plot(self.progression_df['samples_processed'], self.progression_df['precision'] * 100, 
                marker='s', label='Precision', linewidth=2)
        ax5.plot(self.progression_df['samples_processed'], self.progression_df['recall'] * 100, 
                marker='^', label='Recall', linewidth=2)
        
        ax5.set_xlabel('Samples Processed')
        ax5.set_ylabel('Performance (%)')
        ax5.set_title('Learning Curve: Performance vs Experience')
        ax5.legend()
        ax5.grid(True, alpha=0.3)
        
        plt.suptitle('WebGuard Performance Dashboard', fontsize=16, fontweight='bold', y=0.98)
        
        # Save the dashboard
        save_path = self.viz_dir / "performance_metrics" / "performance_dashboard.png"
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.svg'), bbox_inches='tight')
        print(f"Saved performance dashboard: {save_path}")
        plt.close()
    
    def create_threat_detection_analysis(self):
        """Create detailed threat detection analysis"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Threat Detection Analysis', fontsize=16, fontweight='bold')
        
        # Threat type distribution
        threat_data = self.results['threat_type_performance']
        threat_types = list(threat_data.keys())
        total_samples = [threat_data[t]['total_samples'] for t in threat_types]
        
        axes[0, 0].pie(total_samples, labels=threat_types, autopct='%1.0f', startangle=90)
        axes[0, 0].set_title('Threat Type Distribution in Dataset')
        
        # Detection success rate by threat type
        detection_rates = [threat_data[t]['detection_rate'] * 100 for t in threat_types]
        bars = axes[0, 1].bar(threat_types, detection_rates, color='lightcoral', alpha=0.7)
        axes[0, 1].set_title('Detection Rate by Threat Type')
        axes[0, 1].set_ylabel('Detection Rate (%)')
        axes[0, 1].tick_params(axis='x', rotation=45)
        
        # Add value labels
        for bar, rate in zip(bars, detection_rates):
            axes[0, 1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
                           f'{rate:.1f}%', ha='center', va='bottom')
        
        # Confidence distribution
        confidences = [threat_data[t]['avg_confidence'] for t in threat_types]
        axes[1, 0].scatter(detection_rates, [c * 100 for c in confidences], 
                          s=total_samples, alpha=0.6, c=range(len(threat_types)), cmap='viridis')
        axes[1, 0].set_xlabel('Detection Rate (%)')
        axes[1, 0].set_ylabel('Average Confidence (%)')
        axes[1, 0].set_title('Detection Rate vs Confidence\n(bubble size = sample count)')
        
        # Add labels for each point
        for i, threat_type in enumerate(threat_types):
            axes[1, 0].annotate(threat_type, (detection_rates[i], confidences[i] * 100),
                               xytext=(5, 5), textcoords='offset points', fontsize=8)
        
        # ROC-like curve simulation
        fpr_values = self.progression_df['false_positive_rate'].values
        tpr_values = self.progression_df['recall'].values
        
        axes[1, 1].plot(fpr_values, tpr_values, marker='o', linewidth=2, markersize=4)
        axes[1, 1].plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Random Classifier')
        axes[1, 1].set_xlabel('False Positive Rate')
        axes[1, 1].set_ylabel('True Positive Rate (Recall)')
        axes[1, 1].set_title('Learning Progression in ROC Space')
        axes[1, 1].legend()
        axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        save_path = self.viz_dir / "threat_detection" / "threat_analysis.png"
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.svg'), bbox_inches='tight')
        print(f"Saved threat detection analysis: {save_path}")
        plt.close()
    
    def create_experiential_learning_visualization(self):
        """Create visualizations specific to experiential learning patterns"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Experiential Learning Patterns', fontsize=16, fontweight='bold')
        
        # Learning velocity (rate of improvement)
        accuracy_diff = self.progression_df['accuracy'].diff().fillna(0)
        axes[0, 0].plot(self.progression_df['batch'], accuracy_diff * 100, 
                       marker='o', linewidth=2, color='green')
        axes[0, 0].axhline(y=0, color='black', linestyle='--', alpha=0.5)
        axes[0, 0].set_title('Learning Velocity (Accuracy Change)')
        axes[0, 0].set_xlabel('Batch Number')
        axes[0, 0].set_ylabel('Accuracy Change (%)')
        axes[0, 0].grid(True, alpha=0.3)
        
        # Cumulative learning effect
        cumulative_improvement = (self.progression_df['accuracy'] - self.progression_df['accuracy'].iloc[0]) * 100
        axes[0, 1].fill_between(self.progression_df['batch'], 0, cumulative_improvement, 
                               alpha=0.6, color='blue')
        axes[0, 1].plot(self.progression_df['batch'], cumulative_improvement, 
                       linewidth=2, color='darkblue')
        axes[0, 1].set_title('Cumulative Learning Improvement')
        axes[0, 1].set_xlabel('Batch Number')
        axes[0, 1].set_ylabel('Cumulative Accuracy Gain (%)')
        axes[0, 1].grid(True, alpha=0.3)
        
        # Learning stability (variance in performance)
        window_size = 5
        if len(self.progression_df) >= window_size:
            rolling_std = self.progression_df['accuracy'].rolling(window=window_size).std() * 100
            axes[1, 0].plot(self.progression_df['batch'], rolling_std, 
                           marker='s', linewidth=2, color='orange')
            axes[1, 0].set_title(f'Learning Stability (Rolling Std, window={window_size})')
            axes[1, 0].set_xlabel('Batch Number')
            axes[1, 0].set_ylabel('Accuracy Standard Deviation (%)')
            axes[1, 0].grid(True, alpha=0.3)
        
        # Performance vs Processing Time Trade-off
        axes[1, 1].scatter(self.progression_df['processing_time_ms'], 
                          self.progression_df['accuracy'] * 100,
                          c=self.progression_df['batch'], cmap='viridis', 
                          s=50, alpha=0.7)
        axes[1, 1].set_xlabel('Processing Time (ms)')
        axes[1, 1].set_ylabel('Accuracy (%)')
        axes[1, 1].set_title('Performance vs Processing Time\n(color = batch progression)')
        
        # Add colorbar
        cbar = plt.colorbar(axes[1, 1].collections[0], ax=axes[1, 1])
        cbar.set_label('Batch Number')
        
        plt.tight_layout()
        
        save_path = self.viz_dir / "experiential_data" / "learning_patterns.png"
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.svg'), bbox_inches='tight')
        print(f"Saved experiential learning patterns: {save_path}")
        plt.close()
    
    def create_comparative_analysis(self):
        """Create before/after and comparative analysis charts"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Comparative Analysis: Learning Impact', fontsize=16, fontweight='bold')
        
        # Before vs After comparison
        first_batch = self.progression_df.iloc[0]
        last_batch = self.progression_df.iloc[-1]
        
        metrics = ['Accuracy', 'Precision', 'Recall', 'FPR']
        before_values = [first_batch['accuracy'], first_batch['precision'], 
                        first_batch['recall'], first_batch['false_positive_rate']]
        after_values = [last_batch['accuracy'], last_batch['precision'], 
                       last_batch['recall'], last_batch['false_positive_rate']]
        
        x = np.arange(len(metrics))
        width = 0.35
        
        bars1 = axes[0, 0].bar(x - width/2, [v * 100 for v in before_values], width, 
                              label='Initial Performance', alpha=0.7)
        bars2 = axes[0, 0].bar(x + width/2, [v * 100 for v in after_values], width, 
                              label='Final Performance', alpha=0.7)
        
        axes[0, 0].set_xlabel('Metrics')
        axes[0, 0].set_ylabel('Percentage (%)')
        axes[0, 0].set_title('Before vs After Learning')
        axes[0, 0].set_xticks(x)
        axes[0, 0].set_xticklabels(metrics)
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        
        # Improvement percentages
        improvements = [(after - before) / before * 100 if before > 0 else 0 
                       for before, after in zip(before_values, after_values)]
        
        colors = ['green' if imp > 0 else 'red' for imp in improvements]
        bars = axes[0, 1].bar(metrics, improvements, color=colors, alpha=0.7)
        axes[0, 1].set_title('Relative Improvement (%)')
        axes[0, 1].set_ylabel('Improvement (%)')
        axes[0, 1].axhline(y=0, color='black', linestyle='-', alpha=0.5)
        axes[0, 1].grid(True, alpha=0.3)
        
        # Add value labels
        for bar, imp in zip(bars, improvements):
            axes[0, 1].text(bar.get_x() + bar.get_width()/2, 
                           bar.get_height() + (1 if imp > 0 else -3), 
                           f'{imp:.1f}%', ha='center', va='bottom' if imp > 0 else 'top')
        
        # Learning efficiency (improvement per batch)
        total_batches = len(self.progression_df)
        efficiency = [(after - before) / total_batches * 100 
                     for before, after in zip(before_values, after_values)]
        
        axes[1, 0].bar(metrics, efficiency, color='purple', alpha=0.7)
        axes[1, 0].set_title('Learning Efficiency (Improvement per Batch)')
        axes[1, 0].set_ylabel('Improvement per Batch (%)')
        axes[1, 0].grid(True, alpha=0.3)
        
        # Performance trend analysis
        for i, metric in enumerate(['accuracy', 'precision', 'recall']):
            if metric in self.progression_df.columns:
                # Fit a trend line
                x_vals = self.progression_df['batch'].values
                y_vals = self.progression_df[metric].values * 100
                z = np.polyfit(x_vals, y_vals, 1)
                p = np.poly1d(z)
                
                axes[1, 1].plot(x_vals, y_vals, 'o-', label=f'{metric.capitalize()}', alpha=0.7)
                axes[1, 1].plot(x_vals, p(x_vals), '--', alpha=0.5)
        
        axes[1, 1].set_xlabel('Batch Number')
        axes[1, 1].set_ylabel('Performance (%)')
        axes[1, 1].set_title('Performance Trends with Fitted Lines')
        axes[1, 1].legend()
        axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        save_path = self.viz_dir / "comparative_analysis" / "learning_impact.png"
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.savefig(save_path.with_suffix('.svg'), bbox_inches='tight')
        print(f"Saved comparative analysis: {save_path}")
        plt.close()
    
    def create_summary_report(self):
        """Create a comprehensive summary report"""
        report_path = self.viz_dir / "WebGuard_Experiential_Learning_Report.md"
        
        with open(report_path, 'w') as f:
            f.write("# WebGuard Experiential Learning Test Report\n\n")
            f.write(f"**Generated on:** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Executive Summary\n\n")
            f.write(f"- **Total Samples Tested:** {self.results['total_samples']:,}\n")
            f.write(f"- **Dataset Composition:** {self.results['benign_samples']} benign (95%), {self.results['threat_samples']} threats (5%)\n")
            f.write(f"- **Final Accuracy:** {self.results['accuracy']*100:.1f}%\n")
            f.write(f"- **Precision:** {self.results['precision']*100:.1f}%\n")
            f.write(f"- **Recall:** {self.results['recall']*100:.1f}%\n")
            f.write(f"- **F1-Score:** {self.results['f1_score']*100:.1f}%\n")
            f.write(f"- **Processing Time:** {self.results['processing_time_ms']/1000:.2f} seconds\n\n")
            
            f.write("## Learning Progression\n\n")
            first_acc = self.progression_df['accuracy'].iloc[0] * 100
            last_acc = self.progression_df['accuracy'].iloc[-1] * 100
            improvement = last_acc - first_acc
            f.write(f"- **Initial Accuracy:** {first_acc:.1f}%\n")
            f.write(f"- **Final Accuracy:** {last_acc:.1f}%\n")
            f.write(f"- **Total Improvement:** {improvement:+.1f}%\n")
            f.write(f"- **Learning Batches:** {len(self.progression_df)}\n\n")
            
            f.write("## Threat Detection Performance\n\n")
            f.write("| Threat Type | Samples | Detected | Detection Rate | Avg Confidence |\n")
            f.write("|-------------|---------|----------|----------------|----------------|\n")
            
            for threat_type, metrics in self.results['threat_type_performance'].items():
                f.write(f"| {threat_type} | {metrics['total_samples']} | {metrics['detected']} | "
                       f"{metrics['detection_rate']*100:.1f}% | {metrics['avg_confidence']:.3f} |\n")
            
            f.write("\n## Key Findings\n\n")
            f.write("1. **Experiential Learning Effectiveness:** ")
            if improvement > 0:
                f.write(f"The system showed {improvement:.1f}% improvement in accuracy through experiential learning.\n")
            else:
                f.write("The system maintained consistent performance throughout the learning process.\n")
            
            f.write("2. **Threat Detection Capabilities:** ")
            avg_detection_rate = np.mean([m['detection_rate'] for m in self.results['threat_type_performance'].values()])
            f.write(f"Average threat detection rate across all types: {avg_detection_rate*100:.1f}%\n")
            
            f.write("3. **False Positive Management:** ")
            final_fpr = self.progression_df['false_positive_rate'].iloc[-1] * 100
            f.write(f"Final false positive rate: {final_fpr:.1f}%\n")
            
            f.write("\n## Visualizations Generated\n\n")
            f.write("- Learning progression charts\n")
            f.write("- Performance metrics dashboard\n")
            f.write("- Threat detection analysis\n")
            f.write("- Experiential learning patterns\n")
            f.write("- Comparative analysis\n")
            
            f.write("\n## Recommendations\n\n")
            if self.results['precision'] < 0.8:
                f.write("- Consider adjusting confidence thresholds to reduce false positives\n")
            if self.results['recall'] < 0.8:
                f.write("- Enhance threat detection patterns to improve recall\n")
            if improvement < 5:
                f.write("- Increase learning rate or batch size for more pronounced learning effects\n")
            
            f.write("\n---\n*Report generated by WebGuard Experiential Learning Test Suite*\n")
        
        print(f"Generated comprehensive report: {report_path}")
    
    def generate_all_visualizations(self):
        """Generate all visualizations"""
        print("WebGuard Comprehensive Visualization Generator")
        print("=" * 50)
        
        self.load_data()
        
        print("\nGenerating visualizations...")
        self.create_learning_progression_charts()
        self.create_performance_metrics_dashboard()
        self.create_threat_detection_analysis()
        self.create_experiential_learning_visualization()
        self.create_comparative_analysis()
        self.create_summary_report()
        
        print(f"\n✅ All visualizations generated successfully!")
        print(f"📊 Check the {self.viz_dir} directory for all charts and reports")
        print(f"📈 Interactive visualizations saved in multiple formats (PNG, SVG)")

def main():
    """Main function"""
    visualizer = WebGuardVisualizer()
    visualizer.generate_all_visualizations()

if __name__ == "__main__":
    main()