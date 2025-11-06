import harmat as hm
import random
from harmat.stats.mtd_metrics import *
from random import randint
import copy

def enterprise_network():

    network = hm.Harm()

    network.top_layer = hm.AttackGraph()

    # create some nodes
    Attacker = hm.Attacker()  # attacker

    "create hosts"
    h1 = hm.Host("128.91.80.1")
    h2 = hm.Host("128.91.80.2")
    h3 = hm.Host("128.91.80.3")
    h4 = hm.Host("128.91.80.4")
    h6 = hm.Host("128.91.80.6")
    h5 = hm.Host("128.91.80.5")  # target

    "create connection netween the hosts (computer)"
    #'''
    'Fig. a'
    network.top_layer.add_edge_between(Attacker, [h1, h2])
    network.top_layer.add_edge_between(h2, h4)
    network.top_layer.add_edge_between(h1, h3)
    network.top_layer.add_edge_between(h4, h5)
    network.top_layer.add_edge_between(h4, h6)
    network.top_layer.add_edge_between(h6, h5)
    network.top_layer.add_edge_between(h3, h5)


    "add vulnerabilities"
    for host in network.top_layer.hosts():
        host.lower_layer = hm.AttackTree()
        v1 = hm.Vulnerability("CVE-", 'port:80', values={'risk': 2.1, 'cost': 7.9, 'probability': 0.21, 'exploitability': 0.2,'impact': 2, 'defense_cost': 10})  # app vul


        'add vulnerabilities to host nodes'
        host.lower_layer.basic_at([v1])



    network.top_layer.source = Attacker
    network.top_layer.target = h5
    network.top_layer.find_paths()
    network.flowup()

    return network


def simulation():
    net= enterprise_network()

    print ("risk - ", net.risk)
    #print(net.top_layer.cost)
    #print(net.top_layer.number_of_nodes())
    #print("Attack path number - ", net.top_layer.number_of_attack_paths())
    #print(net.top_layer.mode_path_length())
    #print(net.top_layer.mode_path_length())
    #print(net.top_layer.shortest_path_length())






simulation()
