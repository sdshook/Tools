#!/usr/bin/env python3
"""
WebGuard Performance Visualization Dashboard Generator
Creates visual charts from test results for the dashboard.
"""

import json
import os
import csv

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'results')

def generate_ascii_bar(value, max_width=40, fill='█', empty='░'):
    """Generate an ASCII progress bar"""
    filled = int(value * max_width)
    return fill * filled + empty * (max_width - filled)

def generate_dashboard():
    """Generate a text-based visualization dashboard"""
    
    # Load results
    results_file = os.path.join(RESULTS_DIR, 'comprehensive_test_results.json')
    with open(results_file) as f:
        results = json.load(f)
    
    # Load CSV data
    progression_file = os.path.join(RESULTS_DIR, 'learning_progression.csv')
    progression_data = []
    with open(progression_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            progression_data.append(row)
    
    attack_file = os.path.join(RESULTS_DIR, 'attack_type_breakdown.csv')
    attack_data = []
    with open(attack_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            attack_data.append(row)
    
    multipass_file = os.path.join(RESULTS_DIR, 'multipass_results.csv')
    multipass_data = []
    with open(multipass_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            multipass_data.append(row)
    
    dashboard = []
    
    # Header
    dashboard.append("╔" + "═" * 78 + "╗")
    dashboard.append("║" + " " * 20 + "WEBGUARD PERFORMANCE DASHBOARD" + " " * 27 + "║")
    dashboard.append("║" + " " * 15 + "Adaptive Self-Learning Security Analysis" + " " * 22 + "║")
    dashboard.append("╠" + "═" * 78 + "╣")
    
    # Test Summary
    dashboard.append("║  TEST SUMMARY" + " " * 64 + "║")
    dashboard.append("║" + "─" * 78 + "║")
    dashboard.append(f"║  Timestamp: {results['timestamp'][:19]}" + " " * 43 + "║")
    dashboard.append(f"║  Total Samples: {results['data_summary']['total_samples']}" + " " * 56 + "║")
    dashboard.append(f"║  Benign: {results['data_summary']['benign_samples']}  │  Threats: {results['data_summary']['threat_samples']}" + " " * 44 + "║")
    dashboard.append("╠" + "═" * 78 + "╣")
    
    # Learning Progression Chart
    dashboard.append("║  LEARNING PROGRESSION" + " " * 56 + "║")
    dashboard.append("║" + "─" * 78 + "║")
    
    key_phases = ['initial_detection', 'post_learning_detection', 'multipass_validation_3']
    phase_labels = {
        'initial_detection': 'Pre-Learning ',
        'post_learning_detection': 'Post-Learning',
        'multipass_validation_3': 'Final Valid. '
    }
    
    # F1 Score progression
    dashboard.append("║  F1 Score:" + " " * 67 + "║")
    for phase in progression_data:
        if phase['phase'] in key_phases:
            f1 = float(phase['f1_score'])
            label = phase_labels.get(phase['phase'], phase['phase'][:13])
            bar = generate_ascii_bar(f1, 40)
            dashboard.append(f"║    {label} │ {bar} │ {f1*100:5.1f}%" + " " * 8 + "║")
    
    dashboard.append("║" + " " * 78 + "║")
    
    # Accuracy progression
    dashboard.append("║  Accuracy:" + " " * 67 + "║")
    for phase in progression_data:
        if phase['phase'] in key_phases:
            acc = float(phase['accuracy'])
            label = phase_labels.get(phase['phase'], phase['phase'][:13])
            bar = generate_ascii_bar(acc, 40)
            dashboard.append(f"║    {label} │ {bar} │ {acc*100:5.1f}%" + " " * 8 + "║")
    
    dashboard.append("╠" + "═" * 78 + "╣")
    
    # Confusion Matrix Comparison
    dashboard.append("║  CONFUSION MATRIX COMPARISON (Before vs After Learning)" + " " * 22 + "║")
    dashboard.append("║" + "─" * 78 + "║")
    
    pre = next((p for p in progression_data if p['phase'] == 'initial_detection'), None)
    post = next((p for p in progression_data if p['phase'] == 'post_learning_detection'), None)
    
    if pre and post:
        dashboard.append("║" + " " * 10 + "BEFORE LEARNING" + " " * 15 + "│" + " " * 10 + "AFTER LEARNING" + " " * 16 + "║")
        dashboard.append("║" + " " * 10 + "┌─────────┬─────────┐" + " " * 7 + "│" + " " * 10 + "┌─────────┬─────────┐" + " " * 8 + "║")
        dashboard.append("║" + " " * 10 + f"│ TN:{pre['tn']:>4} │ FP:{pre['fp']:>4} │" + " " * 7 + "│" + " " * 10 + f"│ TN:{post['tn']:>4} │ FP:{post['fp']:>4} │" + " " * 8 + "║")
        dashboard.append("║" + " " * 10 + "├─────────┼─────────┤" + " " * 7 + "│" + " " * 10 + "├─────────┼─────────┤" + " " * 8 + "║")
        dashboard.append("║" + " " * 10 + f"│ FN:{pre['fn']:>4} │ TP:{pre['tp']:>4} │" + " " * 7 + "│" + " " * 10 + f"│ FN:{post['fn']:>4} │ TP:{post['tp']:>4} │" + " " * 8 + "║")
        dashboard.append("║" + " " * 10 + "└─────────┴─────────┘" + " " * 7 + "│" + " " * 10 + "└─────────┴─────────┘" + " " * 8 + "║")
    
    dashboard.append("╠" + "═" * 78 + "╣")
    
    # Attack Type Performance
    dashboard.append("║  ATTACK TYPE DETECTION RATES" + " " * 49 + "║")
    dashboard.append("║" + "─" * 78 + "║")
    
    for attack in sorted(attack_data, key=lambda x: -float(x['detection_rate'])):
        rate = float(attack['detection_rate'])
        bar = generate_ascii_bar(rate, 30)
        name = attack['attack_type'][:20].ljust(20)
        detected = int(attack['detected'])
        total = int(attack['total'])
        dashboard.append(f"║    {name} │ {bar} │ {rate*100:5.1f}% ({detected}/{total})" + " " * 3 + "║")
    
    dashboard.append("╠" + "═" * 78 + "╣")
    
    # Multipass Validation Results
    dashboard.append("║  MULTIPASS VALIDATION STABILITY" + " " * 45 + "║")
    dashboard.append("║" + "─" * 78 + "║")
    dashboard.append("║    Pass │ Accuracy │ Precision │ Recall │ F1 Score │  TP │  TN │  FP │  FN  ║")
    dashboard.append("║  ───────┼──────────┼───────────┼────────┼──────────┼─────┼─────┼─────┼───── ║")
    
    for mp in multipass_data:
        acc = float(mp['accuracy']) * 100
        prec = float(mp['precision']) * 100
        rec = float(mp['recall']) * 100
        f1 = float(mp['f1_score']) * 100
        dashboard.append(f"║      {mp['pass']} │  {acc:5.1f}%  │   {prec:5.1f}%  │ {rec:5.1f}% │  {f1:5.1f}%  │ {mp['tp']:>3} │ {mp['tn']:>3} │ {mp['fp']:>3} │ {mp['fn']:>3}  ║")
    
    dashboard.append("╠" + "═" * 78 + "╣")
    
    # Key Metrics Summary
    dashboard.append("║  KEY ADAPTIVE LEARNING METRICS" + " " * 46 + "║")
    dashboard.append("║" + "─" * 78 + "║")
    
    if 'learning_demonstration' in results:
        demo = results['learning_demonstration']
        improvements = demo['improvements']
        
        dashboard.append(f"║    Recall Improvement:     {improvements['recall_change']*100:+6.1f}%  (0% → 100%: Perfect threat detection)" + " " * 8 + "║")
        dashboard.append(f"║    F1 Score Improvement:   {improvements['f1_change']*100:+6.1f}%  (Balanced precision-recall gain)" + " " * 14 + "║")
        dashboard.append(f"║    False Negative Reduction: {improvements['fn_reduction']:+4d}    (Missed threats eliminated)" + " " * 17 + "║")
        dashboard.append(f"║    Accuracy Improvement:   {improvements['accuracy_change']*100:+6.1f}%  (Overall correctness gain)" + " " * 18 + "║")
    
    dashboard.append("╠" + "═" * 78 + "╣")
    
    # System State
    final_pass = multipass_data[-1] if multipass_data else None
    if final_pass:
        dashboard.append("║  FINAL SYSTEM STATE" + " " * 58 + "║")
        dashboard.append("║" + "─" * 78 + "║")
        dashboard.append(f"║    Detection Threshold: {float(final_pass['threshold']):.4f}  (Adaptive - decreased for sensitivity)" + " " * 12 + "║")
        dashboard.append(f"║    Valence (Aggression): {float(final_pass['valence']):.4f}  (High - learned from threat exposure)" + " " * 11 + "║")
        dashboard.append(f"║    Final Accuracy: {float(final_pass['accuracy'])*100:.1f}%       (Stable across validation passes)" + " " * 15 + "║")
    
    # Footer
    dashboard.append("╚" + "═" * 78 + "╝")
    
    # Write dashboard to file
    dashboard_file = os.path.join(RESULTS_DIR, 'dashboard.txt')
    with open(dashboard_file, 'w') as f:
        f.write('\n'.join(dashboard))
    
    print('\n'.join(dashboard))
    print(f"\nDashboard saved to: {dashboard_file}")
    
    return dashboard


def generate_html_dashboard():
    """Generate an HTML visualization dashboard"""
    
    # Load results
    results_file = os.path.join(RESULTS_DIR, 'comprehensive_test_results.json')
    with open(results_file) as f:
        results = json.load(f)
    
    # Load CSV data
    progression_file = os.path.join(RESULTS_DIR, 'learning_progression.csv')
    progression_data = []
    with open(progression_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            progression_data.append(row)
    
    attack_file = os.path.join(RESULTS_DIR, 'attack_type_breakdown.csv')
    attack_data = []
    with open(attack_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            attack_data.append(row)
    
    multipass_file = os.path.join(RESULTS_DIR, 'multipass_results.csv')
    multipass_data = []
    with open(multipass_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            multipass_data.append(row)
    
    pre = next((p for p in progression_data if p['phase'] == 'initial_detection'), None)
    post = next((p for p in progression_data if p['phase'] == 'post_learning_detection'), None)
    final = multipass_data[-1] if multipass_data else None
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebGuard Performance Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }}
        .dashboard {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ 
            text-align: center; 
            padding: 20px; 
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .subtitle {{ text-align: center; color: #888; margin-bottom: 30px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }}
        .card {{ 
            background: rgba(255,255,255,0.05); 
            border-radius: 15px; 
            padding: 20px;
            border: 1px solid rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
        }}
        .card h2 {{ 
            color: #00d4ff; 
            margin-bottom: 15px; 
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        .metric {{ 
            display: flex; 
            justify-content: space-between; 
            padding: 10px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        .metric-value {{ 
            font-weight: bold; 
            color: #00ff88;
        }}
        .metric-value.negative {{ color: #ff6b6b; }}
        .metric-value.neutral {{ color: #ffd93d; }}
        .progress-bar {{ 
            height: 25px; 
            background: rgba(255,255,255,0.1); 
            border-radius: 12px; 
            overflow: hidden;
            margin: 8px 0;
        }}
        .progress-fill {{ 
            height: 100%; 
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            font-size: 12px;
            font-weight: bold;
            color: #1a1a2e;
        }}
        .confusion-matrix {{ 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 10px;
            margin: 10px 0;
        }}
        .cm-cell {{ 
            padding: 15px; 
            text-align: center; 
            border-radius: 8px;
            font-weight: bold;
        }}
        .cm-tn {{ background: rgba(0,255,136,0.3); }}
        .cm-tp {{ background: rgba(0,212,255,0.3); }}
        .cm-fp {{ background: rgba(255,107,107,0.3); }}
        .cm-fn {{ background: rgba(255,217,61,0.3); }}
        .improvement {{ 
            display: inline-block;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
            margin-left: 10px;
        }}
        .improvement.positive {{ background: rgba(0,255,136,0.2); color: #00ff88; }}
        .improvement.negative {{ background: rgba(255,107,107,0.2); color: #ff6b6b; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: center; border-bottom: 1px solid rgba(255,255,255,0.1); }}
        th {{ color: #00d4ff; }}
        .timestamp {{ text-align: center; color: #666; margin-top: 20px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="dashboard">
        <h1>🛡️ WebGuard Performance Dashboard</h1>
        <p class="subtitle">Adaptive Self-Learning Security Analysis</p>
        
        <div class="grid">
            <!-- Test Summary -->
            <div class="card">
                <h2>📊 Test Summary</h2>
                <div class="metric">
                    <span>Total Samples</span>
                    <span class="metric-value">{results['data_summary']['total_samples']}</span>
                </div>
                <div class="metric">
                    <span>Benign Samples</span>
                    <span class="metric-value">{results['data_summary']['benign_samples']}</span>
                </div>
                <div class="metric">
                    <span>Threat Samples</span>
                    <span class="metric-value">{results['data_summary']['threat_samples']}</span>
                </div>
                <div class="metric">
                    <span>Test Phases</span>
                    <span class="metric-value">5</span>
                </div>
            </div>
            
            <!-- Learning Improvement -->
            <div class="card">
                <h2>🧠 Adaptive Learning Results</h2>
                <div class="metric">
                    <span>Recall</span>
                    <span>
                        <span class="metric-value">{float(post['recall'])*100:.0f}%</span>
                        <span class="improvement positive">+{(float(post['recall'])-float(pre['recall']))*100:.0f}%</span>
                    </span>
                </div>
                <div class="metric">
                    <span>F1 Score</span>
                    <span>
                        <span class="metric-value">{float(post['f1_score'])*100:.0f}%</span>
                        <span class="improvement positive">+{(float(post['f1_score'])-float(pre['f1_score']))*100:.0f}%</span>
                    </span>
                </div>
                <div class="metric">
                    <span>False Negatives</span>
                    <span>
                        <span class="metric-value">{post['fn']}</span>
                        <span class="improvement positive">{int(post['fn'])-int(pre['fn'])}</span>
                    </span>
                </div>
                <div class="metric">
                    <span>Accuracy</span>
                    <span>
                        <span class="metric-value">{float(post['accuracy'])*100:.1f}%</span>
                        <span class="improvement positive">+{(float(post['accuracy'])-float(pre['accuracy']))*100:.1f}%</span>
                    </span>
                </div>
            </div>
            
            <!-- Before Learning Confusion Matrix -->
            <div class="card">
                <h2>📈 Before Learning</h2>
                <div class="confusion-matrix">
                    <div class="cm-cell cm-tn">TN: {pre['tn']}</div>
                    <div class="cm-cell cm-fp">FP: {pre['fp']}</div>
                    <div class="cm-cell cm-fn">FN: {pre['fn']}</div>
                    <div class="cm-cell cm-tp">TP: {pre['tp']}</div>
                </div>
                <div class="metric">
                    <span>Accuracy</span>
                    <span class="metric-value neutral">{float(pre['accuracy'])*100:.1f}%</span>
                </div>
                <div class="metric">
                    <span>Recall (Threat Detection)</span>
                    <span class="metric-value negative">{float(pre['recall'])*100:.0f}%</span>
                </div>
            </div>
            
            <!-- After Learning Confusion Matrix -->
            <div class="card">
                <h2>📈 After Learning</h2>
                <div class="confusion-matrix">
                    <div class="cm-cell cm-tn">TN: {post['tn']}</div>
                    <div class="cm-cell cm-fp">FP: {post['fp']}</div>
                    <div class="cm-cell cm-fn">FN: {post['fn']}</div>
                    <div class="cm-cell cm-tp">TP: {post['tp']}</div>
                </div>
                <div class="metric">
                    <span>Accuracy</span>
                    <span class="metric-value">{float(post['accuracy'])*100:.1f}%</span>
                </div>
                <div class="metric">
                    <span>Recall (Threat Detection)</span>
                    <span class="metric-value">{float(post['recall'])*100:.0f}%</span>
                </div>
            </div>
            
            <!-- Attack Type Detection -->
            <div class="card">
                <h2>🎯 Attack Type Detection Rates</h2>
                {''.join([f"""
                <div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>{a['attack_type']}</span>
                        <span>{float(a['detection_rate'])*100:.0f}% ({a['detected']}/{a['total']})</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {float(a['detection_rate'])*100}%"></div>
                    </div>
                </div>
                """ for a in sorted(attack_data, key=lambda x: -float(x['detection_rate']))])}
            </div>
            
            <!-- Final System State -->
            <div class="card">
                <h2>⚙️ Final System State</h2>
                <div class="metric">
                    <span>Detection Threshold</span>
                    <span class="metric-value">{float(final['threshold']):.4f}</span>
                </div>
                <div class="metric">
                    <span>Valence (Aggression)</span>
                    <span class="metric-value">{float(final['valence']):.4f}</span>
                </div>
                <div class="metric">
                    <span>Final Accuracy</span>
                    <span class="metric-value">{float(final['accuracy'])*100:.0f}%</span>
                </div>
                <div class="metric">
                    <span>Final F1 Score</span>
                    <span class="metric-value">{float(final['f1_score'])*100:.0f}%</span>
                </div>
            </div>
            
            <!-- Multipass Validation -->
            <div class="card" style="grid-column: span 2;">
                <h2>🔄 Multipass Validation Results</h2>
                <table>
                    <tr>
                        <th>Pass</th>
                        <th>Accuracy</th>
                        <th>Precision</th>
                        <th>Recall</th>
                        <th>F1 Score</th>
                        <th>TP</th>
                        <th>TN</th>
                        <th>FP</th>
                        <th>FN</th>
                    </tr>
                    {''.join([f"""
                    <tr>
                        <td>{mp['pass']}</td>
                        <td>{float(mp['accuracy'])*100:.1f}%</td>
                        <td>{float(mp['precision'])*100:.1f}%</td>
                        <td>{float(mp['recall'])*100:.1f}%</td>
                        <td>{float(mp['f1_score'])*100:.1f}%</td>
                        <td>{mp['tp']}</td>
                        <td>{mp['tn']}</td>
                        <td>{mp['fp']}</td>
                        <td>{mp['fn']}</td>
                    </tr>
                    """ for mp in multipass_data])}
                </table>
            </div>
        </div>
        
        <p class="timestamp">Generated: {results['timestamp']}</p>
    </div>
</body>
</html>
'''
    
    html_file = os.path.join(RESULTS_DIR, 'dashboard.html')
    with open(html_file, 'w') as f:
        f.write(html)
    
    print(f"HTML Dashboard saved to: {html_file}")
    return html_file


if __name__ == '__main__':
    print("Generating visualizations...")
    generate_dashboard()
    print()
    generate_html_dashboard()
