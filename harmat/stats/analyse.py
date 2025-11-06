from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

#from future import standard_library

#standard_library.install_aliases()
import harmat as hm
import copy
import itertools
import math
from networkx import number_of_nodes


def normalise_centrality_values(ag):
    """
    Normalise a given AttackGraph with respect to their centrality values
    :param list_to_normalise:
    """
    if not isinstance(ag, hm.AttackGraph):
        raise TypeError('Must be AttackGraph!')
    centrality_min = min(node.values['centrality'] for node in ag.hosts())
    centrality_max = max(node.values['centrality'] for node in ag.hosts())
    for node in ag.hosts():
        if centrality_max == centrality_min:
            node.centrality = 1
        node.values['centrality'] = (node.values['centrality'] - centrality_min) / (centrality_max - centrality_min)


def normalise_risk_values(ag):
    if not isinstance(ag, hm.AttackGraph):
        raise TypeError('Must be AttackGraph!')
    risk_min = min(node.risk for node in ag.hosts())
    risk_max = max(node.risk for node in ag.hosts())
    for node in ag.hosts():
        if risk_min == risk_max:
            node.values['risk'] = 1
        else:
            node.values['risk'] = (node.risk - risk_min) / (risk_max - risk_min)


def normalise_impact_values(ag):
    if not isinstance(ag, hm.AttackGraph):
        raise TypeError('Must be AttackGraph')
    impact_min = min(node.impact for node in ag.hosts())
    impact_max = max(node.impact for node in ag.hosts())
    for node in ag.hosts():
        if impact_max == impact_min:
           node.impact = 1
        node.impact = (node.impact - impact_min) / (impact_max - impact_min)


def psv_hybrid(h, percentage, alpha=0.5):
    """
    Prioritised Set of Vulnerabilities method of determining patch order
    :param h: Harm object
    :param percentage: top k percentage of vulnerabilities to choose (0 to 1)
    :param alpha: ratio between Top AG and Lower AT contribution ratio
    :return:
    """
    if not isinstance(h, hm.Harm):
        raise TypeError('Given object must be a HARM')
    harm = copy.deepcopy(h)
    harm.flowup()
    harm[0].initialise_centrality_measure()
    normalise_centrality_values(harm[0])
    normalise_risk_values(harm[0])
    list_of_vulns = []  # Host - Vuln 2-tuples
    for node in harm[0].hosts():
        vulns = [(node, vul) for vul in node.lower_layer.all_vulns()]
        for vuln_tuple in vulns:
            vuln_tuple[1].importance_measure = alpha * node.centrality + (1 - alpha) * vuln_tuple[1].risk
        list_of_vulns.extend(vulns)
    sorted_vulns = sorted(list_of_vulns, key=lambda x: x[1].importance_measure, reverse=True)
    psv = itertools.islice(sorted_vulns, math.ceil(percentage * len(list_of_vulns)))
    return psv

def patch_vul_from_harm(h, vul):
    """
    HARM in AG-AT.
    :param h: Harm
    :param vul: vul name to patch
    """
    for node in h[0].hosts():
        node.lower_layer.patch_vul(vul, is_name=True)
        h.flowup()
        h[0].find_paths()



def patch_psv(list_psv, h):
    for psvhost, vul in list_psv: #turple (hostname with vul)
        #vul_with_hostname = []
        for host in h[0].hosts():
            for host_vul in host.lower_layer.all_vulns():
                if psvhost.name == host.name and vul.name==host_vul.name:
                    our_vul=host_vul
                    our_host = host
                    #print (psvhost,our_vul, our_vul.risk)
                    if our_vul.name != "CVE":
                        our_host.lower_layer.patch_vul(our_vul)

def select_psv_to_improve_security(h):
    """
    Prioritised Set of Vulnerabilities method of determining patch order
    :param h: Harm object
    :param alpha: ratio between Top AG and Lower AT contribution ratio
    :return:
    """

    minimal_number_psv = {} #minimal to improve security
    psv = psv_hybrid(h, 1, alpha=0.5)
    metric = h[0].number_of_attack_paths()
    harm = copy.deepcopy(h)


    for node, vul in psv:  # turple (hostname with vul)
        for host in harm[0].hosts():
            for host_vul in host.lower_layer.all_vulns():
                if node.name == host.name and vul.name == host_vul.name:
                    our_vul = host_vul
                    our_host = host
                    minimal_number_psv[our_host]=our_vul
                    if our_vul.name != "CVE":
                        our_host.lower_layer.patch_vul(our_vul)

                    harm.flowup()
                    harm[0].find_paths()
                    new_metric = harm[0].number_of_attack_paths()
                    #print (new_metric)
                    if new_metric < metric:
                        return round((len(minimal_number_psv))/len(list(psv)),2)


def exhausive_cvss(harm, Number2patch): #sort and patch vul. based on cvss value
    harm.flowup()
    list_of_vulns = []  # Host - Vuln 2-tuples
    for node in harm[0].hosts():
        vulns = [(node, vul) for vul in node.lower_layer.all_vulns()]
        for vuln_tuple in vulns:
            list_of_vulns.append(vuln_tuple)

    sorted_vulns = sorted(list_of_vulns, key=lambda x: x[1].risk, reverse=True)
    ev = itertools.islice(sorted_vulns,Number2patch)
    #return pv
    #for v in ev:
        #print (v)

    for ev_host, vul in ev: #turple (hostname with vul)
        for host in harm[0].hosts():
            for host_vul in host.lower_layer.all_vulns():
                if ev_host.name == host.name and vul.name==host_vul.name:
                    our_vul=host_vul
                    our_host = host
                    #print (ev_host,our_vul, our_vul.risk)
                    our_host.lower_layer.patch_vul(our_vul)

#def getnode_value():


def prioritised_host(h, Number2patch, alpha, node_value):
    """
    Prioritised Set of Vulnerabilities method of determining patch order
    :param h: Harm object
    :param percentage: top k percentage of vulnerabilities to choose (0 to 1)
    :param alpha: ratio between Top AG and Lower AT contribution ratio
    :return:
    """
    if not isinstance(h, hm.Harm):
        raise TypeError('Given object must be a HARM')
    harm = copy.deepcopy(h)
    harm.flowup()
    normalise_risk_values(harm[0])
    list_of_vulns = []  # Host - Vuln 2-tuples
    for node in harm[0].hosts():
        vulns = [(node, vul) for vul in node.lower_layer.all_vulns()]
        for vuln_tuple in vulns:
            vuln_tuple[1].importance_measure = alpha * node_value + (1 - alpha) * vuln_tuple[1].risk
        list_of_vulns.extend(vulns)
        sorted_vulns = sorted(list_of_vulns, key=lambda x: x[1].importance_measure, reverse=True)
    psv_base_host = itertools.islice(sorted_vulns, Number2patch)
    #return psv_base_host

    for psvhost, vul in psv_base_host: #turple (hostname with vul)
        #vul_with_hostname = []
        for host in h[0].hosts():
            for host_vul in host.lower_layer.all_vulns():
                if psvhost.name == host.name and vul.name==host_vul.name:
                    our_vul=host_vul
                    our_host = host
                    print (psvhost,our_vul, our_vul.risk)
                    #if our_vul.name != "CVE":
                    our_host.lower_layer.patch_vul(our_vul)



def mean_cost_to_mitigate_vulnerabilities(h,person_hours, hourly_rate, other_costs):
    '''
    a metric for measuring the mean effort required to mitigate vul.
    return: $NZD per Vulnerabilities
    NEEDED for computation: vulname, person_hours, hourly_rate, other_costs
    '''
    array_of_vul_info=[]
    for v in psv_hybrid(h, 0.5, alpha=0.5):
        vul = {v[1] : [person_hours, hourly_rate, other_costs]}
        array_of_vul_info.append(vul)
    sum_mcmv=0
    for vul in array_of_vul_info:
        for vul_item in vul.items():
            sum_mcmv += ((vul_item[1][0] * vul_item[1][1]) + vul_item[1][2])
    mcmv = sum_mcmv / len(array_of_vul_info)
    return mcmv


def exhaustive(h):
    """
    Exhaustive Search Method for the Risk Metric
    :param h:  Harm
    :returns: generator of vuls in order to patch
    """
    assert isinstance(h, hm.Harm)
    h = copy.deepcopy(h)
    h.flowup()
    system_risk = h.risk
    while system_risk > 0:
        current_risk = system_risk
        solution = None
        # find all vulnerabilities in the network
        all_vulnerabilities = []
        for host in h[0].hosts():
            for vul in host.lower_layer.all_vulns():
                if vul not in all_vulnerabilities:
                    all_vulnerabilities.append(vul)
        for vul in all_vulnerabilities:
            h2 = copy.deepcopy(h)
            try:
                patch_vul_from_harm(h2, vul)
                h2.flowup()
                h2[0].find_paths()
                new_system_risk = h2.risk

            except ValueError:  # When there are no more attack paths
                new_system_risk = 0
            if new_system_risk < current_risk:
                current_risk = new_system_risk
                solution = vul
        h = h2
        system_risk = current_risk
        if solution is not None:
            all_vulnerabilities.remove(solution)
            yield solution


def mean_cost_to_mitigate(number_of_vuls, required_hours, hourly_rate, other_costs):
    return number_of_vuls * (required_hours * hourly_rate + other_costs) / number_of_vuls


def is_severe_host(host):
    for vul in host.lower_layer.all_vulns():
        if vul.risk >= 7:
            return True
    return False

def percentage_of_severe_systems(h):
    num_severe_systems = 0
    for host in h[0].hosts():
        if is_severe_host(host):
            num_severe_systems += 1
    return num_severe_systems / (number_of_nodes(h[0]) - 1)


if __name__ == '__main__':
    h = hm.generate_random_harm(14, 5, edge_prob=0.3)
    h.flowup()
    print(percentage_of_severe_systems(h))
    hm.HarmSummary(h).show()
