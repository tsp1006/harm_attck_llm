import json
import matplotlib.pyplot as plt
from pathlib import Path
from collections import Counter, defaultdict
import pandas as pd

# Path configuration
BASE_DIR = Path(__file__).resolve().parent
RESULT_DIR = BASE_DIR / "result"
FIGURES_DIR = RESULT_DIR / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

def visualize_attack_classification():
    with open("./result/llm_analysis/final_llm_analysis.json", "r") as f:
        data = json.load(f)

    rows = []
    for path in data.get("attack_paths", []):
        for step in path.get("steps", []):
            # Flatten nested fields
            rows.append({
                "Attack Path": path.get("path_id"),
                "Step": step.get("step"),
                "Affected Host": step.get("affected_host"),
                "Primary CVE exploited": step.get("primary_cve"),
                "MITRE ATT&CK Tactics": ", ".join([t["name"] for t in step.get("tactics", [])]),
                "MITRE ATT&CK Techniques": ", ".join([tech["name"] for tech in step.get("techniques", [])]),
                "Other likely CVEs": ", ".join(
    cve["id"] if isinstance(cve, dict) else str(cve)
    for cve in step.get("other_likely_cves", [])
),

                "Procedure": step.get("procedure", ""),
                "Possible Defense": " | ".join(step.get("possible_defense", []))
            })

    # Convert to DataFrame
    df = pd.DataFrame(rows)

    # Save to Excel
    output_path = "./result/llm_analysis/final_llm_analysis.xlsx"
    df.to_excel(output_path, index=False)
    print(f"Final LLM analysis data successfully exported to Excel")

    return df

def visualize_metrics(metrics):
    """Create bar chart of technique frequency"""
    print("-" * 50)
    print("VISUALIZATION")
    print("-" * 50)

    freq = metrics.get("network_level", {}).get("technique_frequency", {})

    if not freq:
        print("No technique frequency data available")
        return

    # Sort by frequency
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    techniques = [item[0] for item in sorted_freq]
    frequencies = [item[1] for item in sorted_freq]

    plt.figure(figsize=(12, 6))
    bars = plt.bar(techniques, frequencies, color='steelblue', edgecolor='navy', alpha=0.7)
    plt.xticks(rotation=45, ha='right')
    plt.xlabel('MITRE ATT&CK Technique', fontsize=12, fontweight='bold')
    plt.ylabel('Total Count', fontsize=12, fontweight='bold')
    plt.title('Number of MITRE ATT&CK Techniques Identified', fontsize=14, fontweight='bold')

    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2., height,
                 f'{int(height)}', ha='center', va='bottom', fontsize=9)

    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()

    out_png = FIGURES_DIR / "technique_number.png"
    plt.savefig(out_png, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"Bar chart saved: {out_png}")


def plot_host_vulnerability(paths_data):
    # Collect host vulnerability data
    host_vulns = defaultdict(int)

    for path in paths_data:
        for vuln in path['vulnerabilities']:
            host_vulns[vuln['host']] += 1

    # Create horizontal bar chart
    hosts = list(host_vulns.keys())
    vuln_counts = [host_vulns[h] for h in hosts]

    fig, ax = plt.subplots(figsize=(10, max(6, len(hosts) * 0.5)))
    y_pos = range(len(hosts))
    bars = ax.barh(y_pos, vuln_counts, color='teal', edgecolor='darkslategray', alpha=0.7)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(hosts)
    ax.set_xlabel('Number of Vulnerabilities', fontsize=12, fontweight='bold')
    ax.set_ylabel('Host', fontsize=12, fontweight='bold')
    ax.set_title('Vulnerability Distribution Across Hosts',
                 fontsize=14, fontweight='bold', pad=20)

    # Add value labels
    for i, bar in enumerate(bars):
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height() / 2.,
                f' {int(width)}',
                ha='left', va='center', fontsize=10, fontweight='bold')

    ax.xaxis.grid(True, linestyle='--', alpha=0.3)
    ax.set_axisbelow(True)
    plt.tight_layout()

    output_file = FIGURES_DIR / "host_vulnerability_distribution.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Host vulnerability distribution saved: {output_file}")
    plt.close()

    return output_file


def visualize_path_success_probability():
    print("\n" + "=" * 60)
    print("VISUALIZING PATH SUCCESS PROBABILITY")
    print("=" * 60)

    # Your actual data
    path_data = {
        "Path 1": 0.21,
        "Path 2": 0.21,
        "Path 3": 0.21,
        "Path 4": 0.21
    }

    # Extract data
    path_names = list(path_data.keys())
    probabilities = list(path_data.values())

    # Create bar chart
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(path_names, probabilities, color='steelblue', edgecolor='navy', alpha=0.8, width=0.6)
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2., height,
                f'{height:.2f}',
                ha='center', va='bottom', fontweight='bold', fontsize=11)

    # Formatting
    ax.set_xlabel('Attack Path', fontsize=12, fontweight='bold')
    ax.set_ylabel('Success Probability', fontsize=12, fontweight='bold')
    ax.set_title('Probability of Attack Success on Paths',
                 fontsize=14, fontweight='bold')
    ax.set_ylim(0, max(probabilities) * 1.15)  # Give room for labels
    ax.grid(axis='y', linestyle='--', alpha=0.3)

    plt.tight_layout()

    # Save figure
    output_path = FIGURES_DIR / "path_success_probability.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"Path success probability chart saved: {output_path}")


def plot_host_risk_comparison():
    host_data = {
        "10.0.2.135": 10.0,
        "10.0.2.155": 9.8,
        "10.0.3.94": 2.1,
        "10.0.3.135": 2.1,
        "10.0.4.22": 7.5
    }

    # Extract data
    host_names = list(host_data.keys())
    host_risks = list(host_data.values())

    # Create figure
    fig, ax = plt.subplots(figsize=(10, 6))

    # Create bars
    bars = ax.bar(host_names, host_risks,
                  color='steelblue',
                  edgecolor='navy',
                  alpha=0.8,
                  width=0.6)

    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2., height,
                f'{height:.1f}',
                ha='center', va='bottom', fontweight='bold', fontsize=10)

    # Formatting
    ax.set_xlabel('Host IP Address', fontsize=12, fontweight='bold')
    ax.set_ylabel('Host Risk Score (CVSS)', fontsize=12, fontweight='bold')
    ax.set_title('Host Risk Score Comparison',
                 fontsize=14, fontweight='bold', pad=20)
    plt.xticks(rotation=45, ha='right')
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    ax.set_ylim(0, max(host_risks) * 1.15)
    ax.set_axisbelow(True)

    plt.tight_layout()

    # Save figure
    output_file = FIGURES_DIR / "host_risk_comparison.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"Host risk score chart saved: {output_file}")


def visualize_host_success_probability():
    print("\n" + "=" * 60)
    print("VISUALIZING HOST SUCCESS PROBABILITY")
    print("=" * 60)

    # Your actual data
    host_data = {
        "10.0.2.135": 1.0,
        "10.0.2.155": 1.0,
        "10.0.3.94": 0.21,
        "10.0.3.135": 0.21,
        "10.0.4.22": 1.0
    }

    # Extract data
    host_names = list(host_data.keys())
    probabilities = list(host_data.values())

    # Create bar chart
    fig, ax = plt.subplots(figsize=(12, 6))

    bars = ax.bar(host_names, probabilities, color='steelblue', edgecolor='navy', alpha=0.8, width=0.6)

    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2., height,
                f'{height:.2f}',
                ha='center', va='bottom', fontweight='bold', fontsize=10)

    # Formatting
    ax.set_xlabel('Host IP Address', fontsize=12, fontweight='bold')
    ax.set_ylabel('Success Probability', fontsize=12, fontweight='bold')
    ax.set_title('Probability of Attack Success on Hosts',
                 fontsize=14, fontweight='bold')
    plt.xticks(rotation=45, ha='right')
    ax.set_ylim(0, max(probabilities) * 1.15)  # Give room for labels
    ax.grid(axis='y', linestyle='--', alpha=0.3)

    plt.tight_layout()

    # Save figure
    output_path = FIGURES_DIR / "host_success_probability.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"Host success probability chart saved: {output_path}")

if __name__ == "__main__":

    # Load metrics
    with open(RESULT_DIR / "attack_metrics.json", 'r') as f:
        metrics = json.load(f)

    with open(RESULT_DIR / "attack_paths_metrics.json", 'r') as f:
        paths_data = json.load(f)

    # Generate visualizations
    visualize_attack_classification()
    visualize_metrics(metrics)
    # plot_tactics_distribution(metrics)
    plot_host_vulnerability(paths_data)
    visualize_path_success_probability()
    visualize_host_success_probability()
    plot_host_risk_comparison()
    print("VISUALIZATIONS COMPLETE")

