import harmat as hm
import random
from harmat.stats.analysis_mtd import *
from harmat.stats.mtd_metrics import *
from random import randint
import copy


'''
Paper title: Optimal Network Reconfiguration for Software Defined Networks using Shuffle-based Online MTD.
Testing the example in the paper here
'''

def snapshot_1():
    list_network=[]
    network1 = hm.Harm()
    network2 = hm.Harm()
    network3 = hm.Harm()

    network1.top_layer = hm.AttackGraph()
    network2.top_layer = hm.AttackGraph()
    network3.top_layer = hm.AttackGraph()
    # create some nodes
    Attacker = hm.Attacker()  # attacker
    WS1 = hm.Host("WS1")
    WS2 = hm.Host("WS2")
    WS3 = hm.Host("WS3")
    AS1 = hm.Host("AS1")
    AS2 = hm.Host("AS2")
    AS3 = hm.Host("AS3")
    DS = hm.Host("DS")  # target


    WS1.variant = "2"
    WS2.variant = "1"
    WS3.variant = "2"
    AS1.variant = "2"
    AS2.variant = "2"
    AS3.variant = "1"
    DS.variant = "3"


    #'''
    'Fig. a'
    network1[0].add_edge_between(Attacker, [WS1, WS2, WS3])
    #network1[0].add_edge_between(WS1, [WS2, AS1])
    network1[0].add_edge_between(AS1, AS2)
    network1[0].add_edge_between(AS2, DS)
    network1[0].add_edge_between(WS2, AS3)
    network1[0].add_edge_between(AS3, DS)
    network1[0].add_edge_between(WS3, AS3)

    for host in network1[0].hosts():
        host.lower_layer = hm.AttackTree()
        vul1 = hm.Vulnerability("CVE-2014-5270", 'port:80', values={'risk': 2.1, 'cost': 7.9, 'probability': 0.21, 'exploitability': 0.2,'impact': 2, 'defense_cost': 10})  # app vul
        'add vulnerabilities to host nodes'
        host.lower_layer.basic_at([vul1])

    list_network.append(network1)


    'Fig. a'
    '''network2[0].add_edge_between(Attacker, [WS1, WS2, WS3])
    network2[0].add_edge_between(WS1, [WS2, AS1])
    network2[0].add_edge_between(AS1, AS2)
    network2[0].add_edge_between(AS2, DS)
    network2[0].add_edge_between(WS2, AS3)
    network2[0].add_edge_between(AS3, DS)
    network2[0].add_edge_between(WS3, AS3)'''


    network2[0].add_edge_between(Attacker, [WS1, WS2, WS3])
    network2[0].add_edge_between(WS1, AS1)
    network2[0].add_edge_between(WS1, WS2)
    network2[0].add_edge_between(WS3, AS3)
    network2[0].add_edge_between(AS3, DS)
    network2[0].add_edge_between(AS2, DS)
    network2[0].add_edge_between(WS2, AS2)
    network2[0].add_edge_between(AS1, AS3)




    for host in network2[0].hosts():
        host.lower_layer = hm.AttackTree()
        vul1 = hm.Vulnerability("CVE-2014-5270", 'port:80', values={'risk': 2.1, 'cost': 7.9, 'probability': 0.21, 'exploitability': 0.2,'impact': 2, 'defense_cost': 10})  # app vul
        'add vulnerabilities to host nodes'
        host.lower_layer.basic_at([vul1])

    list_network.append(network2)

    network3[0].add_edge_between(Attacker, [WS1, WS2, WS3])
    network3[0].add_edge_between(WS1, [WS2, AS1])
    network3[0].add_edge_between(WS3, AS3)
    network3[0].add_edge_between(AS3, DS)
    network3[0].add_edge_between(AS2, DS)
    network3[0].add_edge_between(WS2, AS3)
    network3[0].add_edge_between(AS1, AS2)

    for host in network3[0].hosts():
        host.lower_layer = hm.AttackTree()
        vul1 = hm.Vulnerability("CVE-2014-5270", 'port:80',
                                values={'risk': 2.1, 'cost': 7.9, 'probability': 0.21, 'exploitability': 0.2,
                                        'impact': 2, 'defense_cost': 10})  # app vul
        'add vulnerabilities to host nodes'
        host.lower_layer.basic_at([vul1])

    list_network.append(network3)

    network1[0].source = Attacker
    network1[0].target = DS
    network1[0].find_paths()
    network1.flowup()

    network2[0].source = Attacker
    network2[0].target = DS
    network2[0].find_paths()
    network2.flowup()

    network3[0].source = Attacker
    network3[0].target = DS
    network3[0].find_paths()
    network3.flowup()

    return list_network


def simulation():
    list_network = snapshot_1()

    #node_variant_cost(list_network)
    print ("APV", attack_path_variation(list_network))

    print ("APN",attack_path_number(list_network))

    print ("ACE",attack_cost_exploitability(list_network))

    print( attack_path_exposure(list_network))
    print (attack_cost_time_taken(list_network))
    print (node_variant_downtime(list_network))
    print (edge_variation_cost(list_network))
    print( edge_variation_time(list_network))
    '''
    print '...............'
    for network in list_network:
        for path in nx.all_simple_paths(network[0], network[0].source, network[0].target):
            print path
        print '...............'
    '''


import time
start = time.time()
simulation()
print ('finished time:', time.time() - start)
