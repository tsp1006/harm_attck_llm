import harmat as hm
# if __name__ == "__main__":
# initialise the harm
#from future.moves import sys
import networkx
from harmat.stats.analyse import *
from harmat import *
import xlrd
import random
import json
from Attack_planner import *
import time



def amazon_network_sim():
    startphase2 = time.time()
    amazon_net = hm.Harm()

    'create the top layer of the harm'
    amazon_net.top_layer = hm.AttackGraph()

    'creating attacker'
    attacker = hm.Attacker()  # attacker


    phase1Start = time.time()

    workbook = xlrd.open_workbook(r'C:\Users\Pei\PycharmProjects\harm_model\SPT_project\open_vas_Report\Report1.xls', on_demand=True)

    #workbook = xlrd.open_workbook('C:\Users\Enochson\PycharmProjects\harmat_sim\ADD_project\open_vas_Report\Report1.xls', on_demand=True)
    worksheet = workbook.sheet_by_index(0)

    'Extracting the relevant data  from the Excel imported - IP address'
    list_host = []
    for row in range(worksheet.nrows - 1):
        if row < worksheet.nrows:
            host_IP = worksheet.cell_value(row + 1, 0)
            list_host.append(host_IP.encode('ascii', 'ignore'))
    myhosts = list(dict.fromkeys(list_host))

    time2processPhase1 = time.time() - phase1Start

    'nodes in upper layer'
    'Adding node in the hosts/machines in the upper layer of the model'
    harm_nodes=[]
    for host in myhosts:
        harm_nodes.append(hm.Host(host))
    print ("Total number of hosts added- ", len(harm_nodes))

    #Metaexploit_vuls=["CVE-2011-3556", "CVE-2004-2687", "CVE-2010-2075", "CVE-2017-0143"]

    random_number = round(random.random(), 2)
    'create lower layer for the nodes'
    for node in harm_nodes:
        node.lower_layer = hm.AttackTree()

    'search for IP address and return vulname and CVSS BS'
    for rowidx in range(worksheet.nrows - 1):
        row = worksheet.row(rowidx)

        for colidx, cell in enumerate(row):
            for node in harm_nodes:

                cell_value=cell.value

                # Decode byte strings to plain strings if needed
                if isinstance(cell_value, bytes):
                    cell_value = cell_value.decode('ascii', 'ignore')

                if isinstance(cell_value, str):
                    if cell_value.encode('ascii', 'ignore') == node.name:
                        host_ip = worksheet.cell_value(rowidx, 0)
                        port_num = worksheet.cell_value(rowidx, 2)
                        vul_name = worksheet.cell_value(rowidx, 7)
                        vul_id = worksheet.cell_value(rowidx, 11)
                        cvss_bs = worksheet.cell_value(rowidx, 4)

                        # Edecoding vul_id if it contains unwanted byte formatting
                        if isinstance(vul_id, bytes):
                            vul_id = vul_id.decode('ascii', 'ignore')

                        if worksheet.cell(rowidx, 7).value != xlrd.empty_cell.value:
                            #if vul_id == 'NOCVE':
                                #no_cve.append(vul_id)
                            #if vul_id !='NOCVE':
                                #with_cve.append(vul_id)

                            '''Get vulnerabilities with CVE ID only and connect with the respectivie 
                            hosts, if you want to considr all vulnerabities then remove the if statement'''
                            if vul_id != 'NOCVE':
                                # convert to the list
                                v_id = vul_id.encode('ascii', 'ignore').decode('ascii')
                                con_list = v_id.split(",")
                                for v in con_list:
                                    vul = hm.Vulnerability( v , port_num, values={'risk': cvss_bs, 'cost': (11-cvss_bs),'probability': (cvss_bs/10),'exploitability': random_number,'impact': cvss_bs,'defense_cost': 10})
                                    node.lower_layer.basic_at(vul)

    'Importing connections rules from the security groups - Json file'
    the_file = open(r'C:\Users\Pei\PycharmProjects\harm_model\SPT_project\security_groups\sg_net_sp.json', 'r')
    # returns JSON object as
    security_groups = eval(json.dumps(json.load(the_file)))
    # Closing file
    the_file.close()

    sg1 = []
    sg2 = []
    sg3 = []
    for sg in security_groups:
        # Extracting specific keys from dictionary
        extract_group_with_hosts = dict((k, sg[k]) for k in ['group', 'hosts'] if k in sg)
        # print extract_group_with_hosts
        hosts_and_sgName = list(extract_group_with_hosts.values())

        subnet_name = hosts_and_sgName[0]
        hosts_in_subnet = hosts_and_sgName[1]

        '''' Check name of security and put them as a subnet'''''
        if subnet_name == 'Web-SG':
            sg1 = hosts_in_subnet
        if subnet_name == 'App-SG':
            sg2 = hosts_in_subnet
        if subnet_name == 'DB-SG':
            sg3 = hosts_in_subnet


    'link node name with node obj'
    subnet1 = []
    subnet2 = []
    subnet3 = []
    for node in harm_nodes:
        strNode = node.name
        if isinstance(strNode, bytes):
            strNode = strNode.decode('utf-8')  # or use 'ascii' if you're sure it's ASCII

        for node1 in sg1:
            if strNode == node1:
                subnet1.append(node)

        for node1 in sg2:
            if strNode == node1:
                subnet2.append(node)
        for node1 in sg3:
            if strNode == node1:
                subnet3.append(node)

    'connection'
    'Attacker entry points'
    for node in subnet1:
        amazon_net[0].add_edge_between(attacker, node)

    'host connection'
    for node1 in subnet1:
        for node2 in subnet2:
            amazon_net[0].add_edge_between(node1, node2)
    for node1 in subnet2:
        for node2 in subnet3:
            amazon_net[0].add_edge_between(node1, node2)






    'set attacker and target'
    #amazon_net[0].source = attacker
    Target = ""
    for node in harm_nodes:
        strNode = node.name
        if isinstance(strNode, bytes):
            strNode = strNode.decode('utf-8')

        #print node.name, node.lower_layer.all_vulns()
        if strNode == '10.50.18.99': #from subnet 3
        #if node.name == '10.50.17.117':  # from subnet 2
        #if node.name == '10.50.16.77': #from subnet 1
            Target = node


    #print len(amazon_net[0].hosts())

    amazon_net[0].source = attacker
    amazon_net[0].target = Target

    print ('density', networkx.density(amazon_net[0]))

    time2processPhase2withphase1 = time.time() - startphase2

    time2processPhase2only = time2processPhase2withphase1 - time2processPhase1
    print ('time - phase2:', time2processPhase2only)


    amazon_net[0].find_paths()
    amazon_net.flowup()

    print ('risk:', amazon_net.risk)
    print ('NAP:', amazon_net[0].number_of_attack_paths())
    print ('ROA:', amazon_net[0].return_on_attack())
    print ('before defense:', 'percentages: high, ,medium, low:', amazon_net[0].percentage_severe_vulnerabilities())

    #for path in networkx.all_simple_paths(amazon_net[0], amazon_net[0].source, amazon_net[0].target):
        #print path

    # phase3 = []
    # for k in range(100):
    # phase3Start = time.time()

    'Metrics'
    sp = amazon_net[0].shortest_path_length()
    print ('shortest attack path -', sp)
    #print (amazon_net.risk)
    #print amazon_net.cost

    #print amazon_net[0].number_of_attack_paths()

    'Visualize'
    #hm.write_to_file(hm.convert_to_xml(amazon_net), "C:\Python stuff\h\safeview\data\ADD_project\Amazon_net1.xml")

    #Result_metrics = open("C:\Output\\Attack_plan_ShortestPath_subnet3.txt", 'w')
    #Result_metrics = open("C:\Output\\Attack_plan_AttackCost_subnet3.txt", 'w')
    #Result_metrics = open("C:\Output\\Composite_subnet3.txt", 'w')
    #sys.stdout = Result_metrics


    #attack_path = shortest_paths_based_approach(amazon_net)
    #attack_path = atomic_metric_cost_based(amazon_net)  # incremental learning with target
    #attack_path = composite_metric_based(amazon_net) #composite



    #generate_AG_like_paths(attack_path)

    # time2processPhase3 = time.time() - phase3Start
    # print 'phase3:', time2processPhase3
    # phase3.append(time2processPhase3)

    # print phase3
    # print 'average phase3:', sum(phase3)/len(phase3)


    return amazon_net


"""
------------------------------------------------------------------------------------------
Part: RUN SIMULATION
------------------------------------------------------------------------------------------
"""

amazon_network_sim()
