import json
import os
from pathlib import Path
from collections import Counter, defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

BASE_DIR = Path(__file__).resolve().parent
RESULT_DIR = BASE_DIR / "result"
LLM_DIR = RESULT_DIR / "llm_analysis"
BASE_DIR = Path(__file__).resolve().parent
FIGURES_DIR = RESULT_DIR / "figures"

def load_attack_mappings(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if "revised_analysis" in data:
        return data["revised_analysis"].get("attack_paths", [])
    elif "attack_paths" in data:
        return data["attack_paths"]
    else:
        print(f"[Warning] No attack_paths found in {file_path}")
        return []

def calculate_intra_model_consistency(file_paths):
    all_attack_paths = [load_attack_mappings(fp) for fp in file_paths]

    if not all_attack_paths or len(all_attack_paths) < 2:
        print("Need at least two runs for intra-model consistency")
        return None

    base_paths = all_attack_paths[0]

    total_steps = 0
    primary_cve_match_count = 0
    tactic_match_count = 0
    technique_match_count = 0
    exact_match_count = 0

    for idx_path, base_path in enumerate(base_paths):
        for step_idx, base_step in enumerate(base_path.get("steps", [])):
            total_steps += 1

            base_cve = base_step.get("primary_cve", {})
            base_cve_id = base_cve.get("id") if isinstance(base_cve, dict) else base_cve
            base_tactics = set(t.get("name") for t in base_cve.get("mitre_tactic", []) if isinstance(t, dict)) if isinstance(base_cve, dict) else set()
            base_techniques = set(t.get("name") for t in base_cve.get("mitre_technique", []) if isinstance(t, dict)) if isinstance(base_cve, dict) else set()

            matches_primary = True
            matches_tactic = True
            matches_technique = True
            matches_exact = True

            for other_paths in all_attack_paths[1:]:
                try:
                    other_step = other_paths[idx_path]["steps"][step_idx]
                except IndexError:
                    matches_primary = False
                    matches_tactic = False
                    matches_technique = False
                    matches_exact = False
                    break

                other_cve = other_step.get("primary_cve", {})
                other_cve_id = other_cve.get("id") if isinstance(other_cve, dict) else other_cve
                other_tactics = set(t.get("name") for t in other_cve.get("mitre_tactic", []) if isinstance(t, dict)) if isinstance(other_cve, dict) else set()
                other_techniques = set(t.get("name") for t in other_cve.get("mitre_technique", []) if isinstance(t, dict)) if isinstance(other_cve, dict) else set()

                if other_cve_id != base_cve_id:
                    matches_primary = False
                if other_tactics != base_tactics:
                    matches_tactic = False
                if other_techniques != base_techniques:
                    matches_technique = False
                if other_cve_id != base_cve_id or other_tactics != base_tactics or other_techniques != base_techniques:
                    matches_exact = False

            if matches_primary:
                primary_cve_match_count += 1
            if matches_tactic:
                tactic_match_count += 1
            if matches_technique:
                technique_match_count += 1
            if matches_exact:
                exact_match_count += 1

    primary_cve_consistency = (primary_cve_match_count / total_steps) * 100 if total_steps else 0
    tactic_consistency = (tactic_match_count / total_steps) * 100 if total_steps else 0
    technique_consistency = (technique_match_count / total_steps) * 100 if total_steps else 0
    exact_match_rate = (exact_match_count / total_steps) * 100 if total_steps else 0
    overall_score = (primary_cve_consistency + tactic_consistency + technique_consistency) / 3 if total_steps else 0

    results = {
        "Primary CVE Consistency": round(primary_cve_consistency, 2),
        "Tactic Consistency": round(tactic_consistency, 2),
        "Technique Consistency": round(technique_consistency, 2),
        "Exact Match Rate": round(exact_match_rate, 2),
        "Overall Consistency Score": round(overall_score, 2)
    }

    return results

def calculate_inter_model_agreement(file_path1, file_path2, model1_name, model2_name):
    """
    Calculate inter-model agreement metrics between two LLM outputs
    loaded from file_path1 and file_path2.

    Returns a dict of agreement percentages.
    """
    paths1 = load_attack_mappings(file_path1)
    paths2 = load_attack_mappings(file_path2)

    # Basic sanity check - must have same number of steps for proper alignment
    if not paths1 or not paths2:
        print("One or both files contain no attack paths.")
        return None

    base_steps = paths1[0].get("steps", [])
    compare_steps = paths2[0].get("steps", [])

    if len(base_steps) != len(compare_steps):
        print("Mismatch in number of steps between model outputs.")
        return None

    total_steps = len(base_steps)
    primary_cve_agree = 0
    tactic_agree = 0
    technique_agree = 0
    exact_match_count = 0

    for i in range(total_steps):
        step1 = base_steps[i]
        step2 = compare_steps[i]

        cve1 = step1.get("primary_cve", {})
        cve2 = step2.get("primary_cve", {})

        cve1_id = cve1.get("id") if isinstance(cve1, dict) else cve1
        cve2_id = cve2.get("id") if isinstance(cve2, dict) else cve2

        tactics1 = set(t.get("name") for t in cve1.get("mitre_tactic", []) if isinstance(t, dict)) if isinstance(cve1, dict) else set()
        tactics2 = set(t.get("name") for t in cve2.get("mitre_tactic", []) if isinstance(t, dict)) if isinstance(cve2, dict) else set()

        techniques1 = set(t.get("name") for t in cve1.get("mitre_technique", []) if isinstance(t, dict)) if isinstance(cve1, dict) else set()
        techniques2 = set(t.get("name") for t in cve2.get("mitre_technique", []) if isinstance(t, dict)) if isinstance(cve2, dict) else set()

        cve_match = (cve1_id == cve2_id)
        tactic_match = (tactics1 == tactics2)
        technique_match = (techniques1 == techniques2)

        if cve_match:
            primary_cve_agree += 1
        if tactic_match:
            tactic_agree += 1
        if technique_match:
            technique_agree += 1
        if cve_match and tactic_match and technique_match:
            exact_match_count += 1

    primary_cve_agreement = (primary_cve_agree / total_steps) * 100 if total_steps else 0
    tactic_agreement = (tactic_agree / total_steps) * 100 if total_steps else 0
    technique_agreement = (technique_agree / total_steps) * 100 if total_steps else 0
    exact_match_rate = (exact_match_count / total_steps) * 100 if total_steps else 0
    # overall_agreement_score = (primary_cve_agreement * 0.4) + (tactic_agreement * 0.3) + (technique_agreement * 0.3)
    overall_agreement_score = (primary_cve_agreement + tactic_agreement + technique_agreement) / 3 if total_steps else 0

    results = {
        f"{model1_name} vs {model2_name} Agreement Metrics:": "",
        "Primary CVE Agreement": round(primary_cve_agreement, 2),
        "Tactic Agreement": round(tactic_agreement, 2),
        "Technique Agreement": round(technique_agreement, 2),
        "Exact Match Rate": round(exact_match_rate, 2),
        "Overall Agreement Score": round(overall_agreement_score, 2)
    }

    return results

def run_full_evaluation():
    gpt4_runs = [
        str(LLM_DIR / "chatgpt_response.json"),
        str(LLM_DIR / "chatgpt_response2.json"),
        str(LLM_DIR / "chatgpt_response4.json")
    ]
    gemini_runs = [
        str(LLM_DIR / "gemini_response.json"),
        str(LLM_DIR / "gemini_response3.json"),
        str(LLM_DIR / "gemini_response5.json")
    ]

    gpt4_intra_results = calculate_intra_model_consistency(gpt4_runs)
    gemini_intra_results = calculate_intra_model_consistency(gemini_runs)

    inter_results = calculate_inter_model_agreement(
        str(LLM_DIR / "chatgpt_response4.json"),
        str(LLM_DIR / "gemini_response5.json"),
        "GPT-5",
        "Gemini"
    )

    print("GPT-5 Intra-Model Consistency:", gpt4_intra_results)
    print("Gemini Intra-Model Consistency:", gemini_intra_results)
    print("Inter-Model Agreement:", inter_results)

    return gpt4_intra_results, gemini_intra_results, inter_results


def visualize_consistency_metrics(metrics):
    """Create bar charts for intra-model consistency and inter-model agreement"""
    print("-" * 50)
    print("VISUALIZATION - CONSISTENCY METRICS")
    print("-" * 50)

    # Extract metrics
    gpt4_metrics = metrics.get("intra_model_consistency", {}).get("gpt4", {})
    gemini_metrics = metrics.get("intra_model_consistency", {}).get("gemini", {})
    inter_metrics = metrics.get("inter_model_agreement", {})

    # Check if data exists
    if not gpt4_metrics and not gemini_metrics:
        print("No intra-model consistency data available")
        return

    if not inter_metrics:
        print("No inter-model agreement data available")
        return

    # ========== CHART 1: INTRA-MODEL CONSISTENCY ==========
    plt.figure(figsize=(10, 6))

    # Metrics to display
    metric_names = ['Primary CVE\nConsistency', 'Tactic\nConsistency',
                    'Technique\nConsistency', 'Exact Match\nRate', 'Overall Score']

    # Extract values (convert to percentages)
    gpt4_values = [
        gpt4_metrics.get("Primary CVE Consistency", 0),
        gpt4_metrics.get("Tactic Consistency", 0),
        gpt4_metrics.get("Technique Consistency", 0),
        gpt4_metrics.get("Exact Match Rate", 0),
        gpt4_metrics.get("Overall Consistency Score", 0)
    ]

    gemini_values = [
        gemini_metrics.get("Primary CVE Consistency", 0),
        gemini_metrics.get("Tactic Consistency", 0),
        gemini_metrics.get("Technique Consistency", 0),
        gemini_metrics.get("Exact Match Rate", 0),
        gemini_metrics.get("Overall Consistency Score", 0)
    ]

    # Set bar positions
    x = range(len(metric_names))
    width = 0.35

    # Create bars
    bars1 = plt.bar([i - width / 2 for i in x], gpt4_values, width,
                    label='GPT-5', color='steelblue', edgecolor='navy', alpha=0.8)
    bars2 = plt.bar([i + width / 2 for i in x], gemini_values, width,
                    label='Gemini 2.5 Flash', color='coral', edgecolor='darkred', alpha=0.8)

    # Add value labels on bars
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2., height,
                     f'{height:.1f}%', ha='center', va='bottom', fontsize=9)

    # Formatting
    plt.xlabel('Consistency Metrics', fontsize=12, fontweight='bold')
    plt.ylabel('Percentage (%)', fontsize=12, fontweight='bold')
    plt.title('Intra-Model Consistency Comparison', fontsize=14, fontweight='bold')
    plt.xticks(x, metric_names, fontsize=10)
    plt.ylim(0, 110)  # Give room for labels
    plt.legend(loc='upper right', fontsize=10)
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()

    # Save chart
    out_png_intra = FIGURES_DIR / "intra_model_consistency.png"
    plt.savefig(out_png_intra, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Intra-model consistency chart saved: {out_png_intra}")

    # ========== CHART 2: INTER-MODEL AGREEMENT ==========
    plt.figure(figsize=(10, 6))

    # Extract inter-model values (convert to percentages)
    inter_values = [
        inter_metrics.get("Primary CVE Agreement", 0),
        inter_metrics.get("Tactic Agreement", 0),
        inter_metrics.get("Technique Agreement", 0),
        inter_metrics.get("Exact Match Rate", 0),
        inter_metrics.get("Overall Agreement Score", 0)
    ]

    # Create bars
    bars = plt.bar(x, inter_values, color='coral', edgecolor='darkred',  alpha=0.8, width=0.6)

    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2., height,
                 f'{height:.1f}%', ha='center', va='bottom', fontsize=10)

    # Formatting
    plt.xlabel('Agreement Metrics', fontsize=12, fontweight='bold')
    plt.ylabel('Percentage (%)', fontsize=12, fontweight='bold')
    plt.title('Inter-Model Agreement (GPT-5 vs Gemini 2.5 Flash)',
              fontsize=14, fontweight='bold')
    plt.xticks(x, metric_names, fontsize=10)
    plt.ylim(0, 110)  # Give room for labels
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()

    # Save chart
    out_png_inter = FIGURES_DIR / "inter_model_agreement.png"
    plt.savefig(out_png_inter, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Inter-model agreement chart saved: {out_png_inter}")

    print("\nAll consistency visualization charts generated successfully!")


if __name__ == "__main__":
    gpt4_results, gemini_results, inter_results = run_full_evaluation()
    metrics = {
        "intra_model_consistency": {
            "gpt4": gpt4_results,
            "gemini": gemini_results
        },
        "inter_model_agreement": inter_results
    }
    visualize_consistency_metrics(metrics)