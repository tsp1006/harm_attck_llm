
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


'''---------------------------------------------    '''
'''            ATTACK PATH VARIATION                '''
'''----------------------------------------------   '''
def attack_path_variation(list_of_networks):
    APV_solutions = 0
    for i in range(1,len(list_of_networks)):
        previous_state = get_attack_paths_name_var(list_of_networks[i-1])
        #print (i, previous_state)
        #print "pstate", len(previous_state), previous_state
        current_state =get_attack_paths_name_var(list_of_networks[i])
        #print (i, current_state)
        ap = []
        for node in current_state:
            if node not in previous_state:
                ap.append(node)
        # ap = np.setdiff1d(current_state, previous_state)
        AP = float(len(ap)) / float(len(current_state))
        #print (i, float(len(ap)), float(len(current_state)))
        APV_solutions += AP


        '''
        previous_state=  get_the_list_of_attack_paths(list_of_networks[i-1])
        current_state = get_the_list_of_attack_paths(list_of_networks[i])
        #print 'c', current_state
        ap = []
        for node in current_state:
            if node not in previous_state:
                ap.append(node)
        #ap = np.setdiff1d(current_state, previous_state)
        AP=float(len(ap))/float(len(current_state))
        APV_solutions += AP
        '''
    #print 'APV', APV_solutions/(len(list_of_networks) -1)

    return  APV_solutions/(len(list_of_networks) -1)
'''---------------END-------------------------    '''



'''---------------------------------------------    '''
'''             MTD - ATTACK PATH NUMBER            '''
'''----------------------------------------------   '''
def attack_path_number(list_of_networks):
    APN_solutions = 0
    for i in range(1, len(list_of_networks)):
        previous_state = get_attack_paths_name_var(list_of_networks[i-1])
        current_state = get_attack_paths_name_var(list_of_networks[i])
        ap = len(current_state) - len(previous_state)
        APN = 1 - (max(ap, 0) / float(len(current_state)))
        APN_solutions += APN
    #print 'APN', APN_solutions / (len(list_of_networks) - 1)
    return  APN_solutions / (len(list_of_networks) - 1)




'''---------------------------------------------    '''
'''         ATTACK COST EXPLOITABILITY              '''
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
        ACE += (1 -  product_Ep)
    #print 'ACE', 1-ACE/(len(list_of_networks))
    return  1- ACE/(len(list_of_networks))


def path_attack_cost_exploitability(path):
    ace = 1
    for host in path:
        #print 'exp', exploit
        if host.exploitability == 0:
            return 0
        ace *= host.exploitability
    return ace




'''---------------------------------------------    '''
'''           MTD - ATTACK PATH EXPOSURE            '''
'''----------------------------------------------   '''

def assign_time(list_of_networks):
    for netobj in list_of_networks:
        #netobj.time = randint(1, 50)
        netobj.time = 12

def attack_path_exposure(list_of_networks):
    numerator = 0
    AP = []
    total_duration = 0
    assign_time((list_of_networks))
    for i in range(len(list_of_networks)):
        current_state = get_attack_paths_name_var(list_of_networks[i])
        numerator += len(current_state) * list_of_networks[i].time #adding the time for each attack paths in the state
        for path in current_state:
            if path not in AP:
                AP.append(path)
        total_duration += list_of_networks[i].time
        #print ("state",i,  total_duration)
    #print ('APE', 1-(float(numerator) / (len(AP) * total_duration)))
    return 1- (float(numerator) / (len(AP) * total_duration))





'''---------------------------------------------    '''
'''          Attack Cost Time Taken                 '''
'''----------------------------------------------   '''
def get_time_of_variant(host):
    items = host.split()
    host_variant = items[-1]
    value = 0
    if host_variant == '1':
        value = 2
    if host_variant == '2':
        value = 1.5
    if host_variant == '3':
        value = 1
    if host_variant == '4':
        value = 2.5
    if host_variant == '5':
        value = 2
    if host_variant == '6':
        value = 1.5
    if host_variant == '7':
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
    return ans/len(list_networks)




'''---------------------------------------------    '''
'''           Defense Efforts metrics           '''
'''----------------------------------------------   '''



'''---------------------------------------------    '''
'''                 Node Variant Cost               '''
'''----------------------------------------------   '''
def get_cost_of_variant(host):
    host_variant = host.variant
    if host_variant is '1':
        value = 2
    if host_variant is '2':
        value = 3
    if host_variant is '3':
        value = 4
    if host_variant is '4':
        value = 5
    if host_variant is '5':
        value = 6
    if host_variant is '6':
        value = 7
    if host_variant is '7':
        value = 8
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
        #hostlist.append(len(curr_host))
        hostlist.append(len(list(curr_host)))

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
        if hostlist[i] != 0 and max_cost != 0:
            solution += float(numeratorlist[i]) / (hostlist[i] * max_cost)
        else:
            # Handle the zero case as needed (e.g., log a message or set a default value)
            if hostlist[i] == 0:
                print(f"Warning: hostlist[{i}] is zero, skipping this calculation.")
            if max_cost == 0:
                print("Warning: max_cost is zero, skipping this calculation.")

    #for i in range(len(numeratorlist)):
        #solution += float(numeratorlist[i]) / (hostlist[i] * max_cost)
    NVC = solution / (len(list_networks) - 1)
    #print 'NVC', NVC
    return 1 - NVC




'''---------------------------------------------    '''
'''             Node Variant Downtime               '''
'''----------------------------------------------   '''
def get_downtime_of_variant(host):
    host_variant = host.variant
    value = 0
    if host_variant == '1':
        value = 2
    if host_variant == '2':
        value = 1.5
    if host_variant == '3':
        value = 1
    if host_variant == '4':
        value = 2.5
    if host_variant == '5':
        value = 2
    if host_variant == '6':
        value = 1.5
    if host_variant == '7':
        value = 1
    return value

def node_variant_downtime(list_networks):
    NVDT=0
    numerator=0

    numeratorlist = []
    prev_network = list_networks[0]
    max_cost = 0
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
    #print 'EVT', EVT
    return 1 - EVT




