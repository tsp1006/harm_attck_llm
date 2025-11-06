
import harmat as hm
import sys
import math
import networkx as nx
import random
import numpy as np
import time
from harmat.stats.mtd_metrics import *

TRIAL = 10
TRIAL2 = 10


#set_of_variants = ['1', '2']
def powerset(seq):
    """
    Returns all the subsets of this set. This is a generator.
    """
    if len(seq) <= 1:
        yield seq
        yield []
    else:
        for item in powerset(seq[1:]):
            yield [seq[0]]+item
            yield item


def find_reachable_path_from_powerset(network, paths_variants):
    ''''
    Find reachable paths from the powerset of compromise hosts computed above - powerset(seq)
    For example, if variants a and b are compromised and
    the attacker can reach the target through a path consisting
    of only variants a and b. Then the path is used in the calculations
    '''
    list_variant = []
    for host in network[0].hosts():
        if host.variant not in list_variant:
            list_variant.append(host.variant)
    power_set_result = [x for x in powerset(list_variant)]
    power_set_result.remove([])

    variant_to_compute = []
    for a_set in power_set_result:
        for path in paths_variants:
            if set(path).issubset(set(a_set)):
                if a_set not in variant_to_compute:
                    variant_to_compute.append(a_set)
                    break
    #print 'var', variant_to_compute
    return  variant_to_compute, list_variant


def calculate_EPV(network):
    start = time.time()
    network.flowup()
    #check paths first and find var associated with each path
    paths = [path for path in nx.all_simple_paths(network[0], network[0].source, network[0].target)]
    paths_variants = []
    for path in paths:
        pathvariant = []
        for host in path:
            if host is not network[0].source:
                pathvariant.append(host.variant)
        paths_variants.append(pathvariant)

    vars_to_compute, possible_variant = find_reachable_path_from_powerset(network, paths_variants)
    compromise=[]
    'calculate compromise'

    #for a_set in network_variant_powerset(network): #to calculate EPV using eq. 2
    'we can make this more dynamic - the prob. values'
    #print 'compute', vars_to_compute
    #print 'possible', possible_variant
    total = 0
    for a_set in vars_to_compute:
        possible_set4compromise=[]
        for element in a_set:
            if element =='1':
                possible_set4compromise.append(0.1)
            if element =='2':
                possible_set4compromise.append(0.15)
            if element =='3':
                possible_set4compromise.append(0.2)
            if element =='4':
                possible_set4compromise.append(0.25)
            if element =='5':
                possible_set4compromise.append(0.3)
            if element =='6':
                possible_set4compromise.append(0.35)
            if element =='7':
                possible_set4compromise.append(0.4)
        'calculate not compromise'
        possible_set4notCompromise = []

        'we can make this more dynamic'
        for variant1 in possible_variant:
            if variant1 not in a_set:
                if variant1 == '1':
                    possible_set4notCompromise.append(1 - 0.1)
                if variant1 == '2':
                    possible_set4notCompromise.append(1 - 0.15)
                if variant1 == '3':
                    possible_set4notCompromise.append(1 - 0.2)
                if variant1 == '4':
                    possible_set4notCompromise.append(1 - 0.25)
                if variant1 == '5':
                    possible_set4notCompromise.append(1 - 0.3)
                if variant1 == '6':
                    possible_set4notCompromise.append(1 - 0.35)
                if variant1 == '7':
                    possible_set4notCompromise.append(1 - 0.4)
        probability_not_compromise = np.prod(np.array(possible_set4notCompromise))
        result = np.prod(np.array(possible_set4compromise)) * probability_not_compromise
        compromise.append(result)
        total = sum(compromise)
    EPV = 1 - total
    #print "time taken to calculate EPV: ", time.time() - start
    return EPV

def variant_based_shuffle(network):
    ''' To randomly select a host to shuffle provided it is not the target host and
        the node to connect to is not having thesame variant with the selected node
    '''
    paths = [path for path in nx.all_simple_paths(network[0], network[0].source, network[0].target)]
    #print 'paths', paths
    for i in range(TRIAL):
        randompath = random.choice(paths)
        while True: #randomly select a host provided it is not the target
            #print 'stuck 1'
            random_host1 = random.choice(randompath[1:])
            #if random_host1 is not network[0].target and len(network[0].neighbors(random_host1)) > 0: break
            if random_host1 is not network[0].target and len(list(network[0].neighbors(random_host1))) > 0:
                break

        #print '1',random_host1, random_host1.variant

        'check if the random_host have thesame variant with host(s) it is currently connecting to'
        list_connecting_nodes = network[0].neighbors(random_host1)  # the list of host(s) that the selected random host is connecting to.
        #print 'l', len(list_connecting_nodes)
        'checking is perform here'
        #for host in list_connecting_nodes:
        for host in list(list_connecting_nodes):  # Create a copy of the keys
            if host.variant == random_host1.variant:
                #print 'edge removed:','(',random_host1, ',',host,')'
                network[0].remove_edge(random_host1, host)  # remove the edge
                'selected another host provided it is not random host selected earlier and it also not the target'
                while True:
                    #print 'stuck2'
                    #random_host2 = random.choice(network[0].hosts())
                    random_host2 = random.choice(list(network[0].hosts()))
                    #print '2', random_host2, random_host2.variant
                    if random_host2 is not network[0].target and random_host2.variant != random_host1.variant: break
                'add new edge'
                #print 'edge edded:', '(',random_host1, ',', random_host2,')'
                network[0].add_edge_between(random_host1, random_host2)  # in order to connect the selected node to another host having different variant
                #print 'happened'
                if nx.has_path(network[0], network[0].source, network[0].target) is False:
                    network[0].add_edge_between(random_host1, host)
                    network[0].remove_edge(random_host1, random_host2)
                    #print 'not happened'
            #else:
                #print 'the randomly selected node has different variant with:',host.name,'hence pass to next'
    EPV = calculate_EPV(network)
    return EPV



'To check if list of items are the same'
def all_same(items):
   return all(x == items[0] for x in items)

def variant_based_diversity(network,set_of_variants):
    #print 'diversity EPV', calculate_EPV(network)
    paths = [path for path in nx.all_simple_paths(network[0], network[0].source, network[0].target)]
    for i in range(TRIAL2):
        made_change = False
        max_try = 0
        while not made_change and max_try < TRIAL2:
            #print 'stuck', i, max_try
            max_try += 1
            for path in paths:
                if len(path) > 3:
                    #print(path)
                    path = path[1:-1]
                    ind = random.randint(0, len(path) - 2)
                    if path[ind].variant == path[ind+1].variant:
                        variant_val = random.choice(set_of_variants)
                        while variant_val == path[ind].variant:
                            variant_val = random.choice(set_of_variants)
                        path[ind].variant = variant_val
                        made_change = True
                        break

                '''
                'check if path have the same variant'
                if all_same(a_path_with_variant)== True:
                    num_to_select=1 #i.e., the number of host to change their variant value on an attack path having thesame variant

                    'select certain number of hosts to change their variant value'
                    while True:
                        path_list_of_random_hosts = random.sample(path[1:], num_to_select)
                        if network[0].target  not in path_list_of_random_hosts: break

                if len(path_list_of_random_hosts) > 0:
                    print 'a path variant values', a_path_with_variant
                    print 'host to change variant:', path_list_of_random_hosts

                for host1 in network[0].hosts():
                    for host2 in path_list_of_random_hosts:
                        if host1.name ==host2.name:
                            variant_val = random.choice(set_of_variants)
                            while variant_val == host2.variant:
                                variant_val = random.choice(set_of_variants)
                            host1.variant = variant_val
                            network.flowup()
                '''
        #network.flowup()
    EPV = calculate_EPV(network)
    return EPV


