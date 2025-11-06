import networkx
import json
from collections import defaultdict
import pandas as pd
from tabulate import tabulate


class SecurityEvaluator:
    def __init__(self, harm_model):
        """
        Initialize Security Evaluator with HARM model
        """
        self.harm_model = harm_model
        self.attack_paths = []
        self.metrics = {}
        self.all_cves = {}

    def save_network_metrics(self):
        'save network-based metrics'
        self.metrics['network'] = {
            'total_hosts': len(list(self.harm_model[0].hosts())),
            'total_risk': float(self.harm_model.risk),
            'number_of_paths': int(self.harm_model[0].number_of_attack_paths()),
            'shortest_path_length': int(self.harm_model[0].shortest_path_length()),
            'Attack_Success_Probability': float(self.harm_model[0].probability_attack_success())
        }

        # Save to JSON file
        with open('./result/harm_network_metrics.json', 'w') as f:
            json.dump(self.metrics['network'], f, indent=4)

        # Save to CSV
        df = pd.DataFrame([self.metrics['network']])
        df.to_csv('./result/network_metrics.csv', index=False)

        return self.metrics['network']

    def analyze_attack_paths(self):
        # Extract and analyze all attack paths from HARM model

        print("List of Attack Paths: ")

        source = self.harm_model[0].source
        target = self.harm_model[0].target

        # Extract all attack paths
        path_id = 0
        for path in networkx.all_simple_paths(self.harm_model[0], source, target):
            path_id += 1

            # Convert path to readable format
            route = []
            for node in path:
                if hasattr(node, 'name'):
                    # Proper full decoding of host IP strings
                    if isinstance(node.name, bytes):
                        try:
                            host_ip = node.name.decode('ascii')
                        except Exception:
                            host_ip = str(node.name)
                    else:
                        host_ip = str(node.name)
                    route.append(host_ip)
                else:
                    route.append('Attacker')

            path_info = {
                'path_id': path_id,
                'route': route,
                'raw_path': path
            }

            self.attack_paths.append(path_info)
            print(f"Path {path_id}: {' → '.join(route)}")

        print(f"Total attack paths extracted: {len(self.attack_paths)}")

        return self.attack_paths

    def analyze_each_path(self):
        # Analyze each attack path
        analyzed_paths = []

        for path_info in self.attack_paths:
            route_list = path_info['route']
            route_str = ' → '.join(route_list)
            path_risk = self.harm_model[0].path_risk(path_info['raw_path'])

            path_analysis = {
                'path_id': path_info['path_id'],
                'route': route_list,
                'route_str': route_str,
                'entry_point': route_list[1] if len(route_list) > 1 else 'None',
                'target': route_list[-1],
                'path_length': len(route_list) - 1,
                # 'total_risk_score': 0,
                'risk': float(path_risk),
                'vulnerability_count': 0,
                'vulnerabilities': []
            }

            # Analyze vulnerabilities for each host in path
            for node in path_info['raw_path'][1:]:  # Skip attacker node
                if hasattr(node, 'lower_layer') and node.lower_layer is not None:
                    host_ip = node.name.decode('ascii') if isinstance(node.name, bytes) else str(node.name)

                    try:
                        host_vulns = list(node.lower_layer.all_vulns())
                        for vuln in host_vulns:
                            cve_id = vuln.name if hasattr(vuln, 'name') else 'Unknown'
                            cvss_score = vuln.values.get('risk', 0) if hasattr(vuln, 'values') else 0
                            port = vuln.values.get('service', 'unknown') if hasattr(vuln, 'values') else 'unknown'

                            vuln_data = {
                                'host': host_ip,
                                'cve_id': cve_id,
                                'cvss_score': float(cvss_score),
                                'port': port
                            }

                            path_analysis['vulnerabilities'].append(vuln_data)
                            # path_analysis['total_risk_score'] += float(cvss_score)
                            path_analysis['vulnerability_count'] += 1
                    except Exception as e:
                        continue

            analyzed_paths.append(path_analysis)

            # Print path analysis
            print(f"\nPath {path_analysis['path_id']}: {path_analysis['route_str']}")
            print(f"  Entry Point: {path_analysis['entry_point']}")
            print(f"  Target: {path_analysis['target']}")
            print(f"  Path Length: {path_analysis['path_length']}")
            # print(f"  Total Risk Score: {path_analysis['total_risk_score']:.2f}")
            print(f"  Vulnerability Count: {path_analysis['vulnerability_count']}")
            print(f"  Risk: {path_analysis['risk']:.2f}")

        self.attack_paths = analyzed_paths

        # if self.attack_paths:
        #     critical_path = max(self.attack_paths, key=lambda p: p['total_risk_score'])
        #     self.attack_paths = [critical_path]  # Keep only one path
        #     print(f"\nSelected Critical Attack Path: {critical_path['path_id']} ")

        # Save detailed analysis
        with open('./result/attack_paths_metrics.json', 'w') as f:
            json.dump(analyzed_paths, f, indent=4)

        # Save to CSV
        df = pd.DataFrame(analyzed_paths)
        df.to_csv('./result/attack_paths_metrics.csv', index=False)

        return analyzed_paths

    def extract_all_cves(self):
        # Extract all CVE IDs from attack paths

        all_paths_data = []
        overall_cve_set = set()

        # Print CVEs per path
        for path in self.attack_paths:
            route_str = path['route_str']
            # print(f"\nCVE IDs from attack path {path['path_id']}: {route_str}")

            vulns_by_host = defaultdict(list)
            for vuln in path['vulnerabilities']:
                vulns_by_host[vuln['host']].append(vuln['cve_id'])

            for i, host in enumerate(path['route'][1:], start=1):  # Skip 'Attacker'
                unique_cves = sorted(set(vulns_by_host.get(host, [])))
                overall_cve_set.update(unique_cves)
                cve_list = ', '.join(unique_cves) if unique_cves else 'No CVEs'
                # print(f" {i}. Host {host} vulnerabilities: {cve_list}")

            all_paths_data.append({
                'route': path['route'],
                # 'total_risk_score': path['total_risk_score'],
                'risk': path['risk'],
                'vulns_by_host': dict(vulns_by_host)
            })

        unique_cves_overall = sorted(overall_cve_set)
        # print(f"\nTotal unique CVEs: {len(unique_cves_overall)}")

        # Prepare for LLM integration file
        llm_input_data = {
            'attack_paths': all_paths_data,
            'cve_list': unique_cves_overall,
            'detailed_cves': [],  # optionally fill with full vuln dicts if needed
            'llm_prompt_template': self.generate_llm_prompt_template()
        }

        # Save data for LLM
        with open('./result/cves_for_llm.json', 'w') as f:
            json.dump(llm_input_data, f, indent=4)

        self.all_cves = unique_cves_overall
        return llm_input_data

    def generate_llm_prompt_template(self):
        """Generate prompt template for LLM integration"""
        if not self.attack_paths:
            return ""


        #few shot examples
        prompt_template = """You are a cybersecurity expert analyzing attack paths in a three-tier architecture on cloud by identifying the tactics, techniques, and procedures (TTPs) from the MITRE ATT&CK matrix, leveraging CVE descriptions from the NIST National Vulnerability Database (NVD).

Here are examples of CVE to MITRE ATT&CK mappings:

Example 1:
CVE: CVE-2021-44228
Tactic: Initial Access, Execution
Technique: T1190 – Exploit Public-Facing Application, T1059 Command and Scripting Interpreter
Procedure: Attacker exploits vulnerable Apache Log4j server by sending crafted JNDI lookup strings to execute arbitrary code remotely
Defence: Update Log4j to patched version, implement Web Application Firewall rules, network segmentation

Example 2:
CVE: CVE-2017-0144
Tactic: Lateral Movement, Initial Access
Technique: T1210 – Exploitation of Remote Services, T1190 – Exploit Public-Facing Application
Procedure: Exploit SMB protocol vulnerability to execute code on remote systems and spread across network
Defence: Disable SMBv1, apply MS17-010 patch, implement network segmentation

Example 3:
CVE: CVE-2016-10158
Tactic: Impact
Technique: T1449 - Endpoint Denial of Service 
Procedure: Attacker crafts malicious image file with specially crafted EXIF data that triggers division-by-zero error in PHP's exif_convert_any_to_int function. When vulnerable PHP application processes the uploaded image, it causes application crash and denial of service against web applications handling user-uploaded images
Defence: Update PHP to patched versions, implement input validation and file sanitization, process uploads in sandboxed environments, implement rate limiting on file upload endpoints, strip EXIF data if not required, use Web Application Firewall with file upload protection
"""

        prompt_template += "\nConsider the following sequence of lateral movements across hosts:\n"

        if self.attack_paths:
            # critical_path = self.attack_paths[0]
            critical_path = max(self.attack_paths, key=lambda p: p['risk'])
            route_str = ' → '.join(critical_path['route'])
            prompt_template += f"Most Critical Attack Path: {route_str}\n"

            vulns_by_host = defaultdict(set)
            for vuln in critical_path['vulnerabilities']:
                vulns_by_host[vuln['host']].add(vuln['cve_id'])

            for i, host in enumerate(critical_path['route'][1:], start=1):  # Skip "Attacker"
                cve_list = ', '.join(sorted(vulns_by_host.get(host, {'No CVEs'})))
                prompt_template += f"- Host-{i} ({host}) has vulnerabilities: {cve_list}\n"
            print(f"\nMost Critical Attack Path (Attack Path {critical_path['path_id']}): {critical_path['route_str']}\n")
            prompt_template += f"""Show how a potential attacker can compromise the final target from the entry point to the targets using MITRE ATT&CK tactics and techniques.\n
"""
        prompt_template += """For each step in the attack path:
1. List only the CVEs associated with the specific host. Identify the primary CVE most likely to be exploited on the affected host and, list other likely CVEs on the same host that could also be exploited on the same host based on the host’s known vulnerabilities, if applicable.
2. Map each primary CVE and other likely CVE individually to one or more appropriate MITRE ATT&CK tactics and techniques.
3. Provide a procedure explaining how the technique is applied using the vulnerability in that step.
4. Provide possible defences relevant to each mapping to prevent or detect the attack.

Provide the output in exact JSON format shown below for all attack steps."""

        # Read JSON example from external file
        with open(r'C:\Users\Pei\PycharmProjects\harm_model\SPT_project\json_format.json', 'r',
                  encoding='utf-8') as json_file:
            json_example = json_file.read()

        prompt_template += "\nJSON format example:\n"
        prompt_template += json_example

        with open('./result/llm_analysis/prompt_for_llm.txt', 'w', encoding='utf-8') as f:
            f.write(prompt_template)

        # print(prompt_template)
        print(r"Prompt is generated and saved to: C:\Users\Pei\PycharmProjects\harm_model\SPT_project\result\llm_analysis\prompt_for_llm.txt")
        print("Copy the prompt and send it to ChatGPT.")

        return prompt_template
    def run_analysis(self):
        self.save_network_metrics()
        print()
        self.analyze_attack_paths()
        print()
        self.analyze_each_path()
        print()
        llm_data = self.extract_all_cves()
        # self.generate_llm_prompt_template()
        # print()

        return{
            'metrics': self.metrics,
            'attack_paths': self.attack_paths,
            'llm_data': llm_data
        }

def run_security_evaluation(harm_model):
    """
    Main function to run complete security evaluation
    """


    # Initialize evaluator
    evaluator = SecurityEvaluator(harm_model)
    results = evaluator.run_analysis()
    return evaluator, results


if __name__ == "__main__":
    from harm_construction import amazon_network_sim

    harm_model = amazon_network_sim()

    # Run security evaluation
    evaluator, results = run_security_evaluation(harm_model)