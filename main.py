import harmat as hm
# if __name__ == "__main__":
# initialise the harm
#from future.moves import sys
import networkx
from harmat.stats.analyse import *
from harmat import *
#from retrieve_from_HARM import *
#from Attack_planner import *


def enterprise_network():
    Total_Num_node1 = 1
    enterprise = hm.Harm()

    # create the top layer of the harm
    enterprise.top_layer = hm.AttackGraph()

    A = hm.Attacker()  # attacker
    goal1 = hm.Host("goal 1")
    goal2= hm.Host("goal 2")
    goal3 = hm.Host("goal 3")
    goal4 = hm.Host("goal 4")
    goal5 = hm.Host("goal 5")

    # create some nodes
    # target

    #h1.portNumber = 'port:1080', 'port:80','port:53','port:6660'

    # then we will make a basic attack tree for host
    goal1.lower_layer = hm.AttackTree()
    goal2.lower_layer = hm.AttackTree()
    goal3.lower_layer = hm.AttackTree()
    goal4.lower_layer = hm.AttackTree()
    goal5.lower_layer = hm.AttackTree()



    cargo_v = hm.Vulnerability("CVE-2017-3222",'port:80', values={'risk': 10.0, 'cost': 1.0, 'probability': 1.0, 'exploitability': 0.55,'impact': 5.5, 'defense_cost': 15})
    engine_v1 = hm.Vulnerability("CVE-2018-5400",'port:1080', values={'risk': 6.4, 'cost': 3.6, 'probability': 0.64, 'exploitability': 0.29,'impact': 2.9, 'defense_cost': 15})
    engine_v2 = hm.Vulnerability("CVE-2019-6560",'port:6660',values={'risk': 6.4, 'cost': 3.6, 'probability': 0.64, 'exploitability': 0.55, 'impact': 5.5, 'defense_cost': 15})
    app_v1 = hm.Vulnerability("CVE-2018-5267",'port:53',values={'risk': 7.5, 'cost': 2.5, 'probability': 0.75, 'exploitability': 0.29,'impact': 2.9, 'defense_cost': 15})
    app_v2 = hm.Vulnerability("CVE-2018-5267", 'port:53',values={'risk': 7.5, 'cost': 2.5, 'probability': 0.75, 'exploitability': 0.29,'impact': 2.9, 'defense_cost': 15})
    admin_v = hm.Vulnerability("CVE-2016-5817",'port:8080',values={'risk': 7.5, 'cost': 2.5, 'probability': 0.75, 'exploitability': 0.55,'impact': 5.5, 'defense_cost': 18})
    nav_v1 = hm.Vulnerability("CVE-2017-0143",'',values={'risk': 9.3, 'cost': 1.0, 'probability': 1.0, 'exploitability': 0.64,'impact': 6.4, 'defense_cost': 18})
    navANDbridge_v2 = hm.Vulnerability("CVE-2016-9361",'port:8080',values={'risk': 7.5, 'cost': 2.5, 'probability': 0.75, 'exploitability': 0.64,'impact': 6.4, 'defense_cost': 18})

    nav = hm.Vulnerability("CVE-2017-0143", '',values={'risk': 16.8, 'cost': 1.0, 'probability': 1.0, 'exploitability': 0.64,'impact': 6.4, 'defense_cost': 18})


    and1 = hm.LogicGate('and')

    'Admin system'
    goal1.lower_layer.basic_at(and1)
    vv = [admin_v,app_v1]
    goal1.lower_layer.at_add_node( vv[0], and1)
    goal1.lower_layer.at_add_node(vv[1], and1)


    'Cargo'
    v = [cargo_v, app_v1]
    goal2.lower_layer.basic_at(and1)
    goal2.lower_layer.at_add_node(v[0], and1)
    goal2.lower_layer.at_add_node(v[1], and1)

    'Engine'
    v3 = [engine_v2, app_v1]
    goal3.lower_layer.basic_at(and1)
    goal3.lower_layer.at_add_node(v3[0], and1)
    goal3.lower_layer.at_add_node(v3[1], and1)

    'Navigator'
    v4 = [nav, app_v1]
    goal4.lower_layer.basic_at(and1)
    goal4.lower_layer.at_add_node(v4[0], and1)
    goal4.lower_layer.at_add_node(v4[1], and1)


    'Bridge controller'
    v5 = [navANDbridge_v2, app_v1]
    goal5.lower_layer.basic_at(and1)
    goal5.lower_layer.at_add_node(v5[0], and1)
    goal5.lower_layer.at_add_node(v5[1], and1)




    enterprise[0].add_edge_between(A, [goal1,goal2,goal3,goal4,goal5])

    enterprise.flowup()
    print (goal1.risk)
    print (goal2.risk)
    print (goal3.risk)
    print (goal4.risk)
    print (goal5.risk)

    return enterprise




"""
------------------------------------------------------------------------------------------
Part: RUN SIMULATION
------------------------------------------------------------------------------------------
"""

enterprise_network()
