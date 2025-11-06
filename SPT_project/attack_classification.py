import os
import json
from pathlib import Path
from collections import Counter, defaultdict
import pandas as pd
import matplotlib.pyplot as plt

#path configuration

BASE_DIR = Path(__file__).resolve().parent
RESULT_DIR = BASE_DIR / "result"
LLM_DIR = RESULT_DIR / "llm_analysis"
LLM_DIR.mkdir(parents=True, exist_ok=True)


def normalize_json_format(data):
    normalized = {"attack_paths": []}
    for path in data.get("attack_paths", []):
        norm_path = {"path_id": path.get("path_id"), "steps": []}
        for step in path.get("steps", []):
            norm_step = {
                "step": step.get("step"),
                "affected_host": step.get("affected_host", ""),
                "primary_cve": None,
                "other_likely_cves": [],
                "procedure": step.get("procedure", ""),
                "possible_defence": step.get("possible_defence", [])
            }

            # primary_cve structure with correct nesting
            primary_cve = step.get("primary_cve")
            if isinstance(primary_cve, dict):
                norm_step["primary_cve"] = {
                    "id": primary_cve.get("id"),
                    "mitre_tactic": primary_cve.get("mitre_tactic", []),
                    "mitre_technique": primary_cve.get("mitre_technique", [])
                }
            else:
                norm_step["primary_cve"] = {"id": primary_cve, "mitre_tactic": [], "mitre_technique": []}

            # Correctly normalize other_likely_cves
            other_cves = step.get("other_likely_cves", [])
            for cve in other_cves:
                if isinstance(cve, dict):
                    norm_step["other_likely_cves"].append({
                        "id": cve.get("id"),
                        "mitre_tactic": cve.get("mitre_tactic", []),
                        "mitre_technique": cve.get("mitre_technique", [])
                    })
                else:
                    norm_step["other_likely_cves"].append({"id": cve, "mitre_tactic": [], "mitre_technique": []})

            norm_path["steps"].append(norm_step)
        normalized["attack_paths"].append(norm_path)
    return normalized



# ========== MAIN ITERATION LOOP ==========

def run_iteration_loop(max_iterations=10):
    """Run iterative LLM loop until agreement"""
    print("LLM ATTACK CLASSIFICATION - ITERATION PHASE:")

    iteration = 1
    current_llm = "Gemini"

    # Step 1: Initial ChatGPT JSON
    # print("Step 1: Load initial ChatGPT analysis")
    # chatgpt initial response json
    chat_path = LLM_DIR / "chatgpt_response.json"
    with open(chat_path, "r", encoding="utf-8") as f:
        chat_data = json.load(f)
    latest_analysis = normalize_json_format(chat_data)
    # print(f"Found {len(latest_analysis['attack_paths'])} attack path(s)")

    # Iteration loop
    while iteration <= max_iterations:
        print(f"\nITERATION {iteration} - {current_llm} Review\n")
        if current_llm == "Gemini":
            previous_llm = "ChatGPT"
        else:
            previous_llm = "Gemini"

        # Generate review prompt
        prompt_file = LLM_DIR / f"iter{iteration}_prompt_for_{current_llm.lower()}.txt"

        if iteration == 1:
            with open(prompt_file, "w", encoding="utf-8") as f:
                f.write(f"ITERATION {iteration} - Review\n")
                f.write(
                    "You are a cybersecurity expert analyzing attack paths in a three-tier architecture on cloud by identifying the tactics, techniques, and procedures (TTPs) from the MITRE ATT&CK matrix, leveraging CVE descriptions from the NIST National Vulnerability Database (NVD).\n")
                prompt_template = LLM_DIR / "prompt_template.txt"
                with open(prompt_template, "r", encoding="utf-8") as template:
                    f.write(template.read())
                    f.write("\n")
                f.write(
                    f"\nReview the following attack path mapping produced by {previous_llm} and provide a revised attack path mapping.\n")
                f.write(json.dumps(latest_analysis, indent=2))
                f.write("\n\nRespond in JSON format:\n")
                f.write('''{
                  "agreement": true/false,
                  "confidence": 0.0-1.0,  // Your confidence in your assessment
                  "revised_analysis": {
                    "attack_paths": [
                {
                }
                ]
                  }
                }

                - If you agree, set "agreement": true and set  "revised_analysis": null
                - If you disagree, set "agreement": false, and provide your complete revised analysis.
                ''')
        else:

            with open(prompt_file, "w", encoding="utf-8") as f:
                f.write(f"ITERATION {iteration} - Review\n")
                f.write(f"Review the following attack path mapping produced by {previous_llm} and provide a revised attack path mapping.\n")
                f.write(json.dumps(latest_analysis, indent=2))
                f.write("\nRespond in JSON format:\n")
                f.write('''{
  "agreement": true/false,
  "confidence": 0.0-1.0,  // Your confidence in your assessment
  "revised_analysis": {
    "attack_paths": [
{
}
]
  }
}

- If you agree, set "agreement": true and set  "revised_analysis": null
- If you disagree, set "agreement": false, and provide your complete revised analysis.
''')

        print(f"Review prompt saved: {prompt_file}")
        print(f"Next steps: Copy the prompt, send it to {current_llm} and save response.\n")

        response_path = input(f"Enter path to {current_llm} JSON response: ").strip()

        if not os.path.exists(response_path):
            print(f"File not found: {response_path}")
            print("Please try again.\n")
            continue

        with open(response_path, "r", encoding="utf-8") as f:
            llm_data = json.load(f)

        # Check for agreement
        agreement = llm_data.get("agreement", False)
        print(f"\n{current_llm} Agreement: {agreement}")

        if agreement:
            print(f"{current_llm} agrees with the analysis.\n")
            print(f"\nAgreement reached after {iteration} iteration(s)!")

            final_file = LLM_DIR / "final_llm_analysis.json"
            with open(final_file, "w", encoding="utf-8") as f:
                json.dump(latest_analysis, f, indent=4)
            print(f"Final analysis saved: {final_file}")
            return final_file

        else:
            print(f"\n{current_llm} disagreed.")
            print(f"Continuing to next iteration {iteration + 1}...\n")

            # Get revised analysis
            revised = llm_data.get("revised_analysis")
            # if revised is not None:
            if not revised:
                print(f"WARNING: {current_llm} disagreed but didn't provide revised analysis.")
                print("Please ask the LLM to include 'revised_analysis' in the response.\n")
                continue

            latest_analysis  = normalize_json_format({"attack_paths": revised.get("attack_paths", [])})
            print(f"Using {current_llm}'s revised analysis for next iteration")

            #switch llm for next iteration
            if current_llm == "Gemini":
                current_llm = "ChatGPT"
            else:
                current_llm = "Gemini"

            iteration += 1

    # Max iterations reached
    print("\nMaximum iterations reached without full agreement")

    print("Saving latest analysis as final...")
    final_file = LLM_DIR / "final_llm_analysis.json"
    with open(final_file, "w", encoding="utf-8") as f:
        json.dump(latest_analysis, f, indent=4)
    print(f"Final analysis saved: {final_file}")
    return final_file


# ========== ATTACK CLASSIFICATION METRICS CALCULATION ==========

def calculate_attack_metrics(final_json_path):
    """Calculate MITRE ATT&CK classification metrics from final analysis"""
    print("\n" + "=" * 50)
    print("MITRE ATT&CK CLASSIFICATION METRICS")
    print("-" * 30 + "\n")

    with open(final_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    technique_counter = Counter()
    tactic_counter = Counter()
    path_techniques = defaultdict(list)
    path_tactics = defaultdict(list)

    for path in data.get("attack_paths", []):
        path_id = path.get("path_id")

        for step in path.get("steps", []):
            # Count techniques
            for t in step.get("primary_cve", {}).get("mitre_technique", []):
                t_name = t.get("name") if isinstance(t, dict) else t
                technique_counter[t_name] += 1
                path_techniques[path_id].append(t_name)
            for tac in step.get("primary_cve", {}).get("mitre_tactic", []):
                tac_name = tac.get("name") if isinstance(tac, dict) else tac
                tactic_counter[tac_name] += 1
                path_tactics[path_id].append(tac_name)
            # Other likely CVEs
            for cve in step.get("other_likely_cves", []):
                for t in cve.get("mitre_technique", []):
                    t_name = t.get("name") if isinstance(t, dict) else t
                    technique_counter[t_name] += 1
                    path_techniques[path_id].append(t_name)
                for tac in cve.get("mitre_tactic", []):
                    tac_name = tac.get("name") if isinstance(tac, dict) else tac
                    tactic_counter[tac_name] += 1
                    path_tactics[path_id].append(tac_name)
    # Calculate per-path metrics
    per_path_metrics = []
    for path_id in path_techniques.keys():
        unique_techniques = len(set(path_techniques[path_id]))
        unique_tactics = len(set(path_tactics[path_id]))
        per_path_metrics.append({
            "path_id": path_id,
            "num_techniques": unique_techniques,
            "num_tactics": unique_tactics
        })

    metrics = {
        "network_level": {
            "total_paths": len(data.get("attack_paths", [])),
            "total_technique_occurrences": sum(technique_counter.values()),
            "unique_techniques": len(technique_counter),
            "unique_tactics": len(tactic_counter),
            "technique_frequency": dict(technique_counter),
            "tactic_frequency": dict(tactic_counter)
        },
        "per_path": per_path_metrics
    }

    metrics_file = RESULT_DIR / "attack_metrics.json"
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

    print("Network-level metrics:")
    print(f"  Total attack paths: {metrics['network_level']['total_paths']}")
    print(f"  Unique techniques: {metrics['network_level']['unique_techniques']}")
    print(f"  Unique tactics: {metrics['network_level']['unique_tactics']}")
    print(f"\nPer-path metrics:")
    for pm in per_path_metrics:
        print(f"  Path {pm['path_id']}: {pm['num_techniques']} techniques, {pm['num_tactics']} tactics")
    print(f"\nMetrics saved: {metrics_file}")

    return metrics


# ========== VALIDATION TABLES ==========

def create_validation_table(final_json_path, actual_mapping=None):
    print("\n" + "=" * 50)
    print("VALIDATION TABLE")
    print("-" * 30 + "\n")

    with open(final_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []

    for path in data.get("attack_paths", []):
        for step in path.get("steps", []):
            cve = step.get("primary_cve")
            cve_id = cve.get("id") if isinstance(cve, dict) else cve

            # Predicted techniques
            predicted_techniques = [
                t.get("name") if isinstance(t, dict) else t
                for t in cve.get("mitre_technique", [])
            ] if isinstance(cve, dict) and "mitre_technique" in cve else []

            # Predicted tactics
            predicted_tactics = [
                tac.get("name") if isinstance(tac, dict) else tac
                for tac in cve.get("mitre_tactic", [])
            ] if isinstance(cve, dict) and "mitre_tactic" in cve else []

            # Actual mappings (if provided)
            if actual_mapping and cve_id in actual_mapping:
                actual_techniques = actual_mapping[cve_id].get("techniques", [])
                actual_tactics = actual_mapping[cve_id].get("tactics", [])
            else:
                actual_techniques = [""]
                actual_tactics = [""]

            rows.append({
                "CVE_ID": cve_id,
                "Predicted_Tactics": ", ".join(predicted_tactics),
                "Actual_Tactics": ", ".join(actual_tactics),
                "Predicted_Techniques": ", ".join(predicted_techniques),
                "Actual_Techniques": ", ".join(actual_techniques),
            })

    df = pd.DataFrame(rows)

    output_path  = LLM_DIR / "validation_table.xlsx"
    df.to_excel(output_path, index=False, engine='openpyxl')

    print(f"Validation table saved:")
    print(f"  Excel: {output_path}")
    print(f"\nNext step: Manually fill in 'Actual_Tactics' and 'Actual_Techniques' columns")

    return df



if __name__ == "__main__":
    print("=" * 50)
    print("ATTACK CLASSIFICATION")
    print("-" * 50)

    try:
        # Phase 1: Iterative LLM agreement
        final_json = run_iteration_loop(max_iterations=10)

        # Phase 2: Calculate metrics
        metrics = calculate_attack_metrics(final_json)

        # Phase 3: Create validation table (template)
        # Users will fill in actual mappings manually
        create_validation_table(final_json, actual_mapping=None)


        print(f"\nAll results saved in: {RESULT_DIR}/")
        print(f"LLM analysis files in: {LLM_DIR}/")
        print("Fill in validation_table.xlsx with actual ATT&CK mappings")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback

        traceback.print_exc()