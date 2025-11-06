import harmat as hm
from harmat.stats.analyse import *


def get_edges(list_item):
    '''e.g.,'''
    new_list_with_unique_item = []
    for item in list_item:
        if item not in new_list_with_unique_item:
            new_list_with_unique_item.append(item)
    return new_list_with_unique_item


def unique_hosts(list_item):
    '''get unique hosts'''
    #print 'No of hosts', len(list_item)
    new_list_with_unique_item = []
    for item in list_item:
        if item not in new_list_with_unique_item:
            new_list_with_unique_item.append(item)
    return new_list_with_unique_item


def get_all_list_hosts(list_networks):
    list_all_host = [] #all network states -hosts are here. e.g., host A and B in state 1 and hosts A, B, C in states 2. list_all_host = [A, B, A, B, C]
    list_host_with_edges_turple = []  # the host with edges e.g., [(A, B), (A, C), (B,C)]
    for each_network in list_networks:
        for node in each_network[0].nodes():
            list_host_with_edges_turple.append(each_network[0].edges([node]))
            if node is not each_network[0].source:
                list_all_host.append(node.name)
    return list_all_host, list_host_with_edges_turple


def compute_weights_hosts(list_networks, list_all_hosts):#the weight value is the frequency of apperance
    '''
        :param list_networks: an array of networks (harm obj)
        :param list_all_hosts: list of hosts in an array (list can contain multiple same items). list_all_hosts can be nodes or edges
        :return: return a dictionary of item with its percentage of appearance
        '''
    '''calculate Time window '''
    time_window=0
    for net in list_networks:
        time_window += net.time

    get_distinct_host= unique_hosts(list_all_hosts)


    '''calculate duration for each component'''
    hostname_and_durations={}
    for host_name in get_distinct_host:
        duration = 0
        for net in list_networks:
            for host in net[0].hosts():
                name_host=host.name
                if host_name==name_host:
                    duration += net.time
        hostname_and_durations[host_name] = duration
    #print hostname_and_durations

    '''calculate percentage/percentage of appearance'''
    hostname_with_count = {}
    for item in get_distinct_host:
        count = float(list_all_hosts.count(item))
        #count_weight = (count / len(list_networks)) * 100.0
        hostname_with_count[item] = count
        #hostname_with_count[item] = count_weight


    hostname_with_weights = {}
    for key1, value1 in hostname_with_count.items():
        for key2, value2 in hostname_and_durations.items():
            if key1 ==key2:
                overall_weight=((value1/len(list_networks))*(value2/time_window))*100
                hostname_with_weights[key1] = overall_weight

    return hostname_with_weights
    #return hostname_with_count

def compute_weights_edges1llllllll(list_networks, list_all_edges):#the weight value is the frequency of apperance
    '''
        :param list_networks: an array of networks
        :param list_all_hosts: list of hosts in an array (list can contain multiple same items). list_all_hosts can be nodes or edges
        :return: return a dictionary of item with its percentage of appearance
        '''
    get_distinct_host= get_edges(list_all_edges)

    '''calculate percentage/percentage of appearance'''
    item_with_weights = {}
    for item in get_distinct_host:
        count = float(list_all_edges.count(item))
        weight = (count / len(list_networks)) * 100.0
        item_with_weights[item] = weight

    return item_with_weights

def compute_weights_edges(list_networks, list_all_edges):#the weight value is the frequency of apperance
    '''
        :param list_networks: an array of networks
        :param list_all_hosts: list of hosts in an array (list can contain multiple same items). list_all_hosts can be nodes or edges
        :return: return a dictionary of item with its percentage of appearance
        '''

    '''calculate Time window '''
    time_window = 0
    for net in list_networks:
        time_window += net.time


    array_edge_names=[]
    for edge_turple in list_all_edges:
        edge =[]
        for host in edge_turple:
            edge.append(host.name)
        array_edge_names.append(edge)



    get_distinct_host_edges = get_edges(list_all_edges)

    '''calculate duration for each component -edge'''
    edges_and_durations = {}

    for edges in get_distinct_host_edges:
        duration = 0
        for network in list_networks:
            if edges in network[0].edges():
                duration += network.time
        edges_and_durations[edges] = duration
    #print edges_and_durations


    edges_with_counts = {}
    for each_edge in get_distinct_host_edges:
        converted_edge_string = []
        for host in each_edge:
            converted_edge_string.append(host.name)
        count = float(array_edge_names.count(converted_edge_string))
        #print converted_edge_string, count
        #weight = (count / len(list_networks)) * 100.0
        #edges_with_counts[each_edge] = weight
        edges_with_counts[each_edge] = count


    edge_with_weights = {}
    for key1, value1 in edges_and_durations.items():
        for key2, value2 in edges_with_counts.items():
            if key1 == key2:
                overall_weight = ((value1 / len(list_networks)) * (value2 / time_window)) * 100
                edge_with_weights[key1] = overall_weight

    return edge_with_weights
    #return edges_with_counts


'TIME INDEPENDENT MODEL'
'Which takes a list of network states over time then build a new model called Time independent HARM'
def time_independent_harm(list_networks, hosts_percentage, edges_percentage):
    '''
    :param list_net: an array of networks over time t
    :param hosts_percentage: user's should enter numeric value (0.0 - 100.0)
            for the perecentage of hosts apperance over time. e.g.,
            0.0 percentage will include all hosts that appears
            and 100 percentage will include only hosts that appear all the time in the network states.
    :param edges_percentage: user's should enter numeric value (0.0 - 100.0) for the percentage of
            edge apperance over time they wish to compute.
    :return: return a dictionary of item with its percentage of appearance
    '''
    ti_harm = hm.Harm()
    ti_harm.top_layer = hm.AttackGraph()
    list_all_host, list_host_with_edges_turple = get_all_list_hosts(list_networks)
    # all edges
    list_edges = []  # the host with edges w.r.t. paths
    for each_network in list_networks:
        for each_edge in each_network[0].edges():

            list_edges.append(each_edge)
    for edges_bunch in list_host_with_edges_turple:
        ti_harm.top_layer.add_edges_from(edges_bunch)


    'COMPUTE FOR EDGES'
    #print '-------------weights for edges------------------'
    for key, value in compute_weights_edges(list_networks, list_edges).items():

        'where key is edge and value is the percentage of host apperance for all states'
        if value >= edges_percentage:
            #print key, value
            pass
        else:

            ti_harm[0].remove_edge(*key)
    'COMPUTE for Host'
    #print '-------------weights for hosts------------------'
    for key, value in compute_weights_hosts(list_networks, list_all_host).items():

        'where key is host name and value is the percentage of host apperance for all snapshots'
        if value >= hosts_percentage:
            #print key, value
            pass
        else:
            if ti_harm[0].has_node(key):
                ti_harm[0].remove_node(key)
    return ti_harm


def calculate_metrics(network):
    network[0].find_paths()
    network.flowup()
    print 'NAP', network[0].number_of_attack_paths()
    print 'Risk',network.risk
    print 'Pr', network[0].probability_attack_success()
    print 'ROA', network[0].return_on_attack()
    #print percentage_of_severe_systems(network)


def patch_critical(network):
    for node in network[0].hosts():
        if node is not network[0].target:
            list_vul = []
            for vul in node.lower_layer.all_vulns():
                if vul.risk >= 7.0:
                    list_vul.append(vul)
                    #print node.name, vul.name, vul.risk
                    patch_vul_from_harm(network, vul.name)
            calculate_metrics(network)
            for vul in list_vul:
                node.lower_layer.basic_at([vul])


def drop_outbound_traffic(network):
    for node in network[0].hosts():
        node_out_edges_turple=[]
        if node is not network[0].target:
            if node.risk >= 7.0:
                print '--------begin------', node.name, '--------------'
                list_out_edges = network[0].out_edges([node])#all host connected to the node
                node_out_edges_turple.extend(list_out_edges)
                network[0].remove_edges_from(list_out_edges)
                calculate_metrics(network)
                print '--------end ------',node.name,'--------------'
                network[0].add_edges_from(node_out_edges_turple)
                network[0].find_paths()



def isolate_vulnerable_service(network): #this isolate the host
    for node in network[0].hosts():
        node_out_in_edges_turple = []
        if node is not network[0].target:
            if node.risk >= 7.0:
                print '--------begin------', node.name, '--------------'
                in_and_out_edges=[]
                in_and_out_edges.extend(network[0].in_edges(node))#incoming edges
                in_and_out_edges.extend(network[0].out_edges(node))#outgoing edges
                #print 'hhhhh', in_and_out_edges
                node_out_in_edges_turple.extend(in_and_out_edges)
                network[0].remove_edges_from(in_and_out_edges)
                calculate_metrics(network)
                print '--------end ------', node.name, '--------------'
                network[0].add_edges_from(node_out_in_edges_turple )
                network[0].find_paths()

def traffic_redirection(network): #redirrect traffic coming to a host
    for node in network[0].hosts():
        incoming_hosts2node=[]
        if node.risk >= 7.0:
            description = node.type
            print description
            for host in network[0].hosts():
                if host.type == description:
                    if host is not node:
                        if host.risk < node.risk:
                            for edge_turple in network[0].in_edges(node):
                                for host_belonging in edge_turple:
                                    if host_belonging is not node:
                                        incoming_hosts2node.append(host_belonging)
                            network[0].remove_edges_from(network[0].in_edges(node))
                            #print incoming_hosts2node
                            for host_connecting_to_node in  incoming_hosts2node:
                                network[0].add_edge_between(host_connecting_to_node, host)
                            calculate_metrics(network)


'''GET critical network states'''

def cross_network_critical_states(list_network, weight_host, weight_edge):
    #ctitical state based on 'Ti-HARM'
    tim = time_independent_harm(list_network, weight_host, weight_edge)
    list_hosts_TIHARM = []
    for host in tim[0].hosts():
        list_hosts_TIHARM.append(host.name)
    print list_hosts_TIHARM
    return list_hosts_TIHARM

def patch_critical_state_hosts(list_network, weight_host, weight_edge):
    critical_hosts = cross_network_critical_states(list_network, weight_host, weight_edge)

    after_set_risk = []
    before_set_risk = []
    for network in list_network:
        before_set_risk.append(network.risk)
        net = copy.deepcopy(network)
        for host1 in net[0].hosts():
            for host2 in critical_hosts:
                if host1.name == host2:
                    #print host1.name, host2
                    for vul in host1.lower_layer.all_vulns():
                        if vul.risk>7.0:
                            patch_vul_from_harm(net, vul.name)

        #net.flowup()
        #net[0].find_paths()
        after_set_risk.append(net.risk)

    print before_set_risk
    print after_set_risk








def ccidentify_critical_state(list_network, weight_host, weight_edge):
    #ctitical state based on 'Ti-HARM'
    tim = time_independent_harm(list_network, weight_host, weight_edge)
    list_hosts_TIHARM = []
    for host in tim[0].hosts():
        list_hosts_TIHARM.append(host)

    print list_hosts_TIHARM
    for net in list_network:
        #print net[0].hosts()
        #set(tim.hosts()).intersection(net.hosts())

        '''    
            check if list_hosts_TIHARM contains all elements in net[0].hosts()
        '''
        result = all(elem in list_hosts_TIHARM for elem in  net[0].hosts())

        if result:
            print("Yes")
        else:
            print("No")




def identify_critical_state_RISKbased(list_state):
    risk = 0
    for net in list_state:

        max_risk=net.risk
        if max_risk>risk:
            risk = max_risk
            get_index = list_state.index(net)

    return get_index, risk



