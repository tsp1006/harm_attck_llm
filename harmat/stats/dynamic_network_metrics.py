
import harmat as hm
import sys
import math
import networkx as nx
import random
import numpy as np
import time
from operator import mul
from random import randint
from harmat.stats.analysis_mtd import *
from harmat.stats.time_independent_harm import time_independent_harm

def change_an_attack_path_to_a_set(path):
    an_attack_path_as_a_set = set(x for x in path)
    return frozenset(an_attack_path_as_a_set)

def get_the_set_of_attack_paths(network):
    paths = list(set(change_an_attack_path_to_a_set(path) for path in nx.all_simple_paths(network[0], network[0].source, network[0].target)))
    return paths

def get_the_list_of_attack_paths(network):
    cur = list(set(path) for path in nx.all_simple_paths(network[0], network[0].source, network[0].target))
    sol = []
    for item in cur:
        if item not in sol:
            sol.append(item)
    return sol

def get_attack_paths_name_var(network):
    cur = list(path for path in nx.all_simple_paths(network[0], network[0].source, network[0].target))
    sol = []
    for path in cur:
        h = []
        for host in path:
            if host is not network[0].source:
                h.append(host.name + ' ' + host.variant)
        sol.append(h)
    return sol

'''-------------------------------------------------BEGIN ATTACK EFFORT METRIC------------------------------------------------------------------------------------------------------    '''



'''---------------------------------------------    '''
'''             Attack Effort - ATTACK PATH NUMBER            '''
'''----------------------------------------------   '''
def attack_path_number(list_of_networks):
    APN_solutions = 0
    for i in range(1, len(list_of_networks)):
        previous_state = get_the_set_of_attack_paths(list_of_networks[i-1])
        current_state = get_the_set_of_attack_paths(list_of_networks[i])
        #previous_state = get_attack_paths_name_var(list_of_networks[i-1])
        #current_state = get_attack_paths_name_var(list_of_networks[i])
        ap = len(current_state) - len(previous_state)
        APN = 1 - (max(ap, 0) / float(len(current_state)))
        APN_solutions += APN
    #print 'APN', APN_solutions / (len(list_of_networks) - 1)
    return  APN_solutions / (len(list_of_networks) - 1)




'''---------------------------------------------    '''
'''            Attack Effort - ATTACK PATH EXPOSURE            '''
'''----------------------------------------------   '''

def assign_time(list_of_networks):
    for netobj in list_of_networks:
        #netobj.time = randint(1, 5)
        netobj.time = 2

def attack_path_exposure(list_of_networks):
    numerator = 0
    AP = []
    total_duration = 0
    #assign_time((list_of_networks))
    for i in range(len(list_of_networks)):
        current_state = get_the_set_of_attack_paths(list_of_networks[i])
        #current_state = get_attack_paths_name_var(list_of_networks[i])
        numerator += len(current_state) * list_of_networks[i].time #adding the time for each attack paths in the state
        for path in current_state:
            if path not in AP:
                AP.append(path)
        total_duration += list_of_networks[i].time
    #print 'APE', 1-(float(numerator) / (len(AP) * total_duration))
    #print 'APE', 1- (float(numerator) / (len(AP) * total_duration))
    #print 'APE', float(numerator) / (len(AP) * total_duration)
    return float(numerator) / (len(AP) * total_duration)




'''---------------------------------------------    '''
'''       Attack Effort - ATTACK COST EXPLOITABILITY'''
'''----------------------------------------------   '''
def attack_cost_exploitability(list_of_networks):
    ACE =0
    for network in list_of_networks:
        result = 1
        ep = (path_attack_cost_exploitability(path[1:]) for path in nx.all_simple_paths(network[0], network[0].source, network[0].target))
        for num in ep:
            result *= (1 - num)
        #product_Ep = reduce((lambda x, y: x + (1 - y)), )
        product_Ep = result
        #print 'ep', product_Ep
        ACE += (product_Ep)
    #print 'ACE', 1-ACE/(len(list_of_networks))
    #print  'ACE', ACE/(len(list_of_networks))
    return ACE/(len(list_of_networks))


def path_attack_cost_exploitability(path):
    ace = 1
    for host in path:
        #print 'exp', exploit
        if host.exploitability == 0:
            return 0
        ace *= host.exploitability
    return ace


'''---------------------------------------------    '''
'''          Attack Cost Time Taken                 '''
'''----------------------------------------------   '''
def get_time_of_variant(host):
    items = host.split()
    host_variant = items[-1]
    value = 0
    if host_variant is '1':
        value = 2
    if host_variant is '2':
        value = 1.5
    if host_variant is '3':
        value = 1
    if host_variant is '4':
        value = 2.5
    if host_variant is '5':
        value = 2
    if host_variant is '6':
        value = 1.5
    if host_variant is '7':
        value = 1
    return value

def attack_cost_time_taken(list_networks):
    ACTT=0
    ans = 0
    for current in list_networks:
        currentpath = get_attack_paths_name_var(current)
        mincost = 9999999
        maxcost = 0
        for path in currentpath:
            pathcost = 0
            for node in path:
                pathcost += get_time_of_variant(node)
            if pathcost > maxcost:
                maxcost = pathcost
            if pathcost < mincost:
                mincost = pathcost
        ans += float(mincost)/maxcost
    #print 'ACTT', ans/len(list_networks)
    #print 'ACD', ans/len(list_networks)
    return ans/len(list_networks)


'''-------------------------------------------------END ATTACK EFFORT METRIC------------------------------------------------------------------------------------------------------    '''




'''****************************************************************BEGIN DEFENCE EFFORT METRIC****************************************************************************************'''
'''---------------------------------------------    '''
'''           Defense Efforts metrics           '''
'''----------------------------------------------   '''


'''---------------------------------------------    '''
'''                 Node Variant Cost               '''
'''----------------------------------------------   '''
def ZZZZZZZZZZZget_cost_of_variant(host):
    host_variant = host.variant
    if host.type== 'web server':
        value = 10
    if host.type== 'app server':
        value = 5
    if host.type== 'db server':
        value = 15
    if host.type == 'user':
        value = 3
    return value


def ZZZZZZZZZZnode_variant_cost(list_networks):
    NVC=0
    numerator=0

    numeratorlist = []
    #prev_network = list_networks[0]
    max_cost = 0
    for current in list_networks:
        cost = 0
        for host in current[0].hosts():
            for vul in host.lower_layer.all_vulns():
                cost = vul.defense_cost
                numeratorlist.append(cost)
    NVC = sum(numeratorlist)
    #print 'NC', NVC
    return NVC


def get_cost_of_variant(host):
    host_variant = host.variant
    value = 1
    if host_variant is '1':
        value = 2.0
    if host_variant is '2':
        value = 3.0
    if host_variant is '3':
        value = 4.0
    return value

def node_variant_cost(list_networks):
    NVC=0
    numerator=0

    numeratorlist = []
    hostlist = []
    denominator = len(list_networks) - 1
    prev_network = list_networks[0]
    max_cost = 0
    for current in list_networks[1:]:
        cost = 0
        prev_host = prev_network[0].hosts()
        curr_host = current[0].hosts()
        hostlist.append(len(curr_host))

        for chost in curr_host:
            for phost in prev_host:
                if chost.name == phost.name and chost.variant != phost.variant:
                    cost += get_cost_of_variant(chost)

                if get_cost_of_variant(chost) > max_cost:
                    max_cost = get_cost_of_variant(chost)
        numeratorlist.append(cost)
        prev_network = current #it was pre_network = current BUT I have changed i

    solution = 0
    for i in range(len(numeratorlist)):
        solution += float(numeratorlist[i]) / (hostlist[i] * max_cost)
    NVC = solution / (len(list_networks) - 1)
    #print 'NVC', NVC
    return 1 - NVC

'''---------------------------------------------    '''
'''             Node Variant Downtime               '''
'''----------------------------------------------   '''
def ZZZZZZZZZZget_downtime_of_variant(host):
    host_variant = host.type
    value = 0
    if host_variant == 'web server':
        value = 2
    if host_variant =='app server':
        value = 1.5
    if host_variant == 'db server':
        value = 1
    if host_variant == 'user':
        value = 2.5
    return value

def ZZZZZZZZZZZnode_variant_downtime(list_networks):
    NVDT=0
    numerator=0

    numeratorlist = []
    #prev_network = list_networks[0]
    max_donwtime = 0
    for current in list_networks:
        downtime_cost = 0
        for host in current[0].hosts():
            #for vul in host.lower_layer.all_vulns():
            downtime_cost = max(get_downtime_of_variant(host), downtime_cost)
            if get_downtime_of_variant(host) > max_donwtime:
                max_donwtime = get_downtime_of_variant(host)
        numeratorlist.append(downtime_cost)
    #NVDT = float(sum(numeratorlist)) / ((len(list_networks) - 1) * max_cost)
    NVDT = float(sum(numeratorlist))/ (len(list_networks))
    #print 'NVDT', NVDT
    print ('NDT'), NVDT

def get_downtime_of_variant(host):
    host_variant = host.variant
    value = 0
    if host_variant is '1':
        value = 2
    if host_variant is '2':
        value = 1.5
    if host_variant is '3':
        value = 1
    if host_variant is '4':
        value = 2.5
    if host_variant is '5':
        value = 2
    if host_variant is '6':
        value = 1.5
    if host_variant is '7':
        value = 1
        return value

def node_variant_downtime(list_networks):
    NVDT=0
    numerator=0

    numeratorlist = []
    prev_network = list_networks[0]
    max_cost = 1
    for current in list_networks[1:]:
        cost = 0
        prev_host = prev_network[0].hosts()
        curr_host = current[0].hosts()

        for chost in curr_host:
            for phost in prev_host:
                if chost.name == phost.name and chost.variant != phost.variant:
                    cost = max(get_downtime_of_variant(chost), cost)
                if get_downtime_of_variant(chost) > max_cost:
                    max_cost = get_downtime_of_variant(chost)
        numeratorlist.append(cost)
        prev_network = current

        NVDT = float(sum(numeratorlist))/((len(list_networks) - 1) * max_cost)
    #print 'NVDT', NVDT
    return 1 - NVDT

'''---------------------------------------------    '''
'''             Edge Variation Cost                 '''
'''----------------------------------------------   '''

def get_edgeset(network):
    edgeset = set()
    for (s, d) in network[0].edges():
        edgeset.add(str(s) + str(d))

    return edgeset

def edge_variation_cost(list_networks):
    EVC=0
    sol = 0
    prev_network = list_networks[0]
    for current in list_networks[1:]:
        prev_edge = get_edgeset(prev_network)
        curr_edge = get_edgeset(current)
        sol += float(len(prev_edge - curr_edge) + len(curr_edge - prev_edge)) / len(prev_edge.union(curr_edge))
        #print 'a', float(len(prev_edge - curr_edge) + len(curr_edge - prev_edge))
        prev_network = current
    EVC = sol / (len(list_networks) - 1)
    #print 'EVC', EVC
    return 1 - EVC


'''---------------------------------------------    '''
'''             Edge Variation Time                 '''
'''----------------------------------------------   '''

def populate_edges(network):
    edge_dict = {}
    for (s, d) in network[0].edges():
        edge_dict[str(s.name)] = edge_dict.get(str(s.name), set())
        edge_dict[str(s.name)].add(str(d.name))
    return edge_dict

def edge_variation_time(list_networks):
    EVT=0
    sol = 0
    prev_network = list_networks[0]
    total_diff = 0
    for current in list_networks[1:]:
        prev_dict = populate_edges(prev_network)
        curr_dict = populate_edges(current)

        max_diff = 0
        for (k, v) in curr_dict.items():
            max_diff = max(max_diff, len(v - prev_dict.get(k, set())) + len(prev_dict.get(k, set()) - v))
        if total_diff < max_diff:
            total_diff = max_diff
        #print 'diff', max_diff
        sol += max_diff
        #print 'a', float(len(prev_edge - curr_edge) + len(curr_edge - prev_edge))
        prev_network = current
    if total_diff == 0:
        EVT = 0
    else:
        EVT = float(sol) / (total_diff * (len(list_networks) - 1))
    #print 'EVT', 1- EVT
    return 1 - EVT

'''****************************************************************END DEFENCE EFFORT METRIC****************************************************************************************'''



'''--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------    '''
'''         Stateless           '''
'''--------------------------------------------------------------------------------------------------------------------------------------------------------------------------   '''


'''---------------------------------------------    '''
'''         Stateless - Attack Number (unique)             '''
'''----------------------------------------------   '''

def stateless_attack_path_number(list_of_networks):
    all_path=[]
    #t_p = []
    all_ap=[]
    for network in list_of_networks:
        list_path = []
        for path in nx.all_simple_paths(network[0], network[0].source, network[0].target):
            p = (path)
            all_ap.append(p)
            if p not in all_path:
                all_path.append(p)
    #print 'APN-stateless', float(len(all_path))
    return float(len(all_path))
    #print 'APN', float(len(all_path))/float(len(all_ap)) #normalise



'''---------------------------------------------    '''
'''         Attack Number (persistent)             '''
'''----------------------------------------------   '''
def persistent_attack_path_number(list_of_networks):
    S =''
    T = ''
    for harm in list_of_networks:
        harm.time=1
        harm.flowup()
        harm[0].find_paths()
        S = harm[0].source
        T = harm[0].target

    tim = time_independent_harm(list_of_networks, 100.0, 100.0)

    list_path=[]
    for path in nx.all_simple_paths(tim[0], S, T):
        list_path.append(path)


    all_path = []
    for network in list_of_networks:
        for path in nx.all_simple_paths(network[0], network[0].source, network[0].target):
            p = (path)
            if p not in all_path:
                all_path.append(p)
    #print 'PPN', len(list_path)
    return len(list_path)
    #print 'PPN',float(len(list_path))/float(len(all_path))

    '''---------------------------------------------    '''
    '''         OR  (i.e., for the attack number persistent)             '''
    '''----------------------------------------------   '''

def get_list_path(network):
    list_path = set()
    for path in nx.all_simple_paths(network[0], network[0].source, network[0].target):
        list_path.add(change_an_attack_path_to_a_set(path))
    return list_path
def ppn(list_of_networks):
    setlist = []
    for network in list_of_networks:
        print (get_list_path(network))
        x = get_list_path(network)
        setlist.append(x)
        # cur =get_the_set_of_attack_paths(harm)
        # setlist.append(paths)
    # print setlist
    #print set.intersection(*setlist)
    return set.intersection(*setlist)



'''---------------------------------------------    '''
'''         Visibility Approach - Stateless Risk    '''
'''----------------------------------------------   '''
def stateless_risk_VA(list_of_networks):
    Source = ""
    Target = ""
    for harm in list_of_networks:
        harm.time=1
        harm.flowup()
        harm[0].find_paths()
        Source = harm[0].source
        Target = harm[0].target

    ''' AGGREGATE '''
    aggregate_harm = time_independent_harm(list_of_networks, 0.0, 0.0)
    aggregate_harm[0].source = Source
    aggregate_harm[0].target = Target
    aggregate_harm[0].find_paths()
    aggregate_harm.flowup()

    aggregate_risk = aggregate_harm.risk
    #print 'VA:SR',aggregate_risk
    return aggregate_risk


'''---------------------------------------------    '''
'''         Weighted approach - Stateless Risk      '''
'''----------------------------------------------   '''
def caculate_weight(list_network, net):
    count_net = float(list_network.count(net))
    net.weight= count_net/len(list_network)
    weighted_risk = net.risk *net.weight
    #weighted_risk[net] = weight
    return weighted_risk

def sum_weighted_risk_all_state_WA(list_network):
    'stateless risk WA'
    sumation_weighted_risk = 0
    for net in list_network:
        sumation_weighted_risk += caculate_weight(list_network, net)
    return sumation_weighted_risk
    #print 'WA:SR',sumation_weighted_risk




























