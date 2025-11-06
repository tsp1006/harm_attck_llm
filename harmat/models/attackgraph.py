"""
Attack Graph class implementation
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

#from builtins import next
from functools import reduce

#from future import standard_library

##standard_library.install_aliases()
import networkx
import warnings
from collections import OrderedDict
import statistics
import harmat as hm
from harmat.stats.analyse import psv_hybrid


class HarmNotFullyDefinedError(Exception): pass


class NoAttackPathExists(Exception): pass


class AttackGraph(networkx.DiGraph):
    """
    Attack Graph class.
    An Attack graph is a way to model the security of a network.
    This class inherits from networkx directed graph class so that we can use
    all of its functions which are relevant
    """

    def __init__(self):
        networkx.DiGraph.__init__(self)
        self.source, self.target = None, None
        self.all_paths = None
        self.values = OrderedDict()

    def __repr__(self):
        return self.__class__.__name__

    def find_paths(self):
        """
        Finds all paths between the source (Attacker) and all other nodes.
        This function is *very* expensive.
        If target is specified, it will find all paths between the attacker and the target node
        :param target: Specified target node
        """
        if self.source is None:
            raise HarmNotFullyDefinedError('Source is not set')
        if self.target is None:
            all_other_nodes = list(self.nodes())
            all_other_nodes.remove(self.source)  # need to remove the attacker from nodes
        else:
            all_other_nodes = [self.target]
        flatten = lambda l: [item for sublist in l for item in sublist]
        self.all_paths = flatten([list(_all_simple_paths_graph(self, self.source, tg)) for tg in all_other_nodes])

    def flowup(self):
        for node in self.hosts():
            if node.lower_layer is not None:
                node.flowup()

    @property
    def risk(self):
        """
        Calculate the risk of this AttackGraph

        The high level algorithm is as follows:
            1. Find all possible paths from one node to another. However, we
            ignore paths which contain loops.
            2. Sum up the risk of all paths.
                i. To calculate the risk of a path, sum up the individual risk
                values of all nodes in that path.
        Args:
            source: the source node. Usually should be the Attacker
            target: the designated target node

        Returns:
            The total risk calculated.

        """
        if self.all_paths is None:
            self.find_paths()
        #return sum(self.path_risk(path) for path in self.all_paths)
        return max(self.path_risk(path) for path in self.all_paths)


    def path_risk(self, path):
        """
        Calculate the risk of a path

        Args:
            path: this is a list (or generator) containing a path between two nodes
            E.g.
            [0, 2, 1, 3]
            where 0..3 are the nodes in the path.
        Returns:
            The risk value calculated

        """
        path_risk_sum = 0
        for node in path[1:]:
            if hasattr(node, 'impact'):
                node_risk = node.impact * node.probability
            else:
                node_risk = node.risk
            path_risk_sum += node_risk
        #print (path, path_risk_sum)
        return path_risk_sum

    @property
    def cost(self):
        """
        Calculate the cost of this Attack Grpah

        This is is minimum value of the path cost values of all attack paths
        between a source node and target node

        Args:
            source: the originating node. Usually the attacker.

            target: targetted node.
        Returns:
            The cost of an attack
        """
        if not self.all_paths:
            self.find_paths()
        return min(self.path_cost(path) for path in self.all_paths)



    def path_cost(self, path):
        """
        Calculate the cost of an attack for a single path

        Args:
            path : this is a list (or generator) containing a path =between two
            nodes

        Returns:
            The calculated cost value
        """
        return sum(node.cost for node in path[1:])


    def return_on_attack(self):
        """
        Calculate the return on an attack.
        It is calculated by:
        Return = (Probabiliy * Impact) / Cost
        The maximum value from all attack paths are selected.
        Args:
            source : Node object. The source node. Usually the attacker.

            target : Node object. The target node.
        Returns:
            Numeric
        """
        if self.all_paths is None:
            self.find_paths()
        return max(self.path_return(path) for path in self.all_paths)
        #return sum(self.path_return(path) for path in self.all_paths)

    def path_return(self, path):
        """
        probability, impact and cost attributes must be set for all nodes
        """
        path_return = 0
        for node in path[1:]:
            if hasattr(node, 'impact'):
                node_return = ((node.probability*node.impact) / node.cost)
            else:
                node_return = node.risk /node.cost
            path_return += node_return
        return path_return

    def mean_path_length(self):
        """
        Calculate the Mean of Path Metric
        Args:
            source:
            target:
        Returns:
            Numerical
        """
        if self.all_paths is None:
            self.find_paths()
        path_len_generator = (len(path) - 1 for path in self.all_paths)
        return statistics.mean(path_len_generator)

    def mode_path_length(self):
        """
        Calculate the Mode of Path Length Metric
        """
        if self.all_paths is None:
            self.find_paths()
        return max(len(path) for path in self.all_paths) - 1

    def stdev_path_length(self):
        """
        Calculate the standard deviation of path length
        """
        if self.all_paths is None:
            self.find_paths()
        path_len_generator = (len(path) - 1 for path in self.all_paths)
        try:
            return statistics.stdev(path_len_generator)
        except:
            return 0

    def shortest_path_length(self):
        shortest_path = networkx.shortest_path(self, self.source, self.target)
        return len(shortest_path) - 1

    def add_edge_between(self, node1, nodes, two_ways=False):
        """
        Add edges between a node (node1) and all other nodes in nodes

        Args:
            node1: Node object
            nodes: Either Node object or a iterable containing nodes
        """
        if isinstance(nodes, hm.Node):
            nodes = [nodes]

        for node in nodes:
            self.add_edge(node1, node)

        if two_ways is True:
            for node in nodes:
                self.add_edge(node, node1)

    def find_node(self, node_name):
        """
        Returns the object with the same name as node_name

        Args:
            node_name: String
        Returns:
            Node object
            or
            None: if no node with node_name is found
        """
        for node in self.nodes():
            if node.name == node_name:
                return node
        return None

    @property
    def betweenness_centrality(self):
        """
        Calculates the betweenness centrality
        Returns:
             A dictionary of nodes with values assigned to them
        """
        return networkx.betweenness_centrality(self)

    @property
    def closeness_centrality(self):
        return networkx.closeness_centrality(self)

    @property
    def degree_centrality(self):
        return networkx.degree_centrality(self)

    def initialise_centrality_measure(self):
        """
        Calculates the necessary metrics for visualisation or calculation
        Currently:
        Risk (top layer and lower layer), Centrality
        :return:
        """
        # initialise centrality measure
        betweenness = self.betweenness_centrality
        closeness = self.closeness_centrality
        degree = self.degree_centrality

        # initialise host nodes risk metrics and give value for centrality
        for node in self.nodes():
            node.values['centrality'] = (betweenness[node] + closeness[node] + degree[node]) / 3

    def number_of_attack_paths(self):
        if self.all_paths is None:
            raise Exception('Attack paths have not been calculated')
        return len(self.all_paths)

    def normalised_mean_path_length(self):
        num_paths = self.number_of_attack_paths()
        if num_paths == 0:
            raise ZeroDivisionError('No attack paths')
        return self.mean_path_length() / num_paths

    def probability_attack_success(self):
        if self.all_paths is None:
            self.find_paths()
        return max(self.path_probability(path[1:]) for path in self.all_paths)

    def path_probability(self, path):
        # return reduce(lambda x, y: x * y, (host.lower_layer.values['probability'] for host in path[1:]))
        p = 1
        for host in path[1:]:
            prob = host.probability
            if prob == 0:
                return 0
            p *= prob
        return p

    def number_of_known_vulnerabilities(self):
        list_of_vulns = []
        for node in self.hosts():
            vulns = [(vul) for vul in node.lower_layer.all_vulns()]
            list_of_vulns.extend(vulns)
        return len(list_of_vulns)

    def impact(self):
        if not self.all_paths:
            self.find_paths()
        return max(self.path_impact(path) for path in self.all_paths)

    def path_impact(self, path):
        return sum(node.impact for node in path[1:])


    def all_vulns(self):
        """
        :return: A set of all (unique) vulnerabilities
        """
        return {vul for vul in (node.lower_layer.all_vulns() for node in self.nodes())}

    def hosts(self):
        return filter(lambda x: not isinstance(x, hm.Attacker), self.nodes())

    def num_vulnerable_hosts(self):
        return len(filter_ignorables(list(self.hosts())))

    '''---------------------------------------------    '''
    '''             ECONOMIC METRICS                    '''
    '''----------------------------------------------   '''

    def single_loss_expectancy(self):
        if not self.all_paths:
            self.find_paths()
        return sum(self.path_single_loss_expectancy(path) for path in self.all_paths)

    def path_single_loss_expectancy(self, path):
        return sum((node.asset_value*node.exposure_factor) for node in path[1:])
        '''
        path_SLE = 0
        for node in path[1:]:
            if hasattr(node, 'impact'):
                node_SLE = node.asset_value * node.exposure_factor
            else:
                node_SLE = node.asset_value * node.exposure_factor
            path_SLE += node_SLE
        return path_SLE
        '''


    def annual_loss_expectancy(self): # I call this periodic loss expectancy
        if self.all_paths is None:
            self.find_paths()
        return sum(self.path_annual_loss_expectancy(path) for path in self.all_paths)



    def path_annual_loss_expectancy(self, path):
        #NOTE:# ALE=SLE*ARO
        return sum(((node.asset_value*node.exposure_factor)* (node.probability)) for node in path[1:])

    def percentage_severe_vulnerabilities(self):
        high = 0
        medium = 0
        low = 0
        unique_vulnerabilities = set()

        # Collect all unique vulnerabilities
        for host in self.hosts():
            for vul in host.lower_layer.all_vulns():
                unique_vulnerabilities.add(vul)

        total = len(unique_vulnerabilities)

        # Classify vulnerabilities
        for vul in unique_vulnerabilities:
            if vul.risk > 7.0:
                high += 1
            elif vul.risk > 5.0:
                medium += 1
            else:
                low += 1

        # Avoid division by zero
        if total == 0:
            return {'high': 0.0, 'medium': 0.0, 'low': 0.0}

        # Calculate percentages
        return {
            'high': round((high / total) * 100, 2),
            'medium': round((medium / total) * 100, 2),
            'low': round((low / total) * 100, 2)
        }





'''' FOR TEMPORAL NETWORK ONLY (networks with more than one snapshots)'''

'''' BENEFIT OF SECURITY'''
def benefit_of_security(array_of_ALE_solutions):
    solutions = []
    i = 0
    while (i<(len(array_of_ALE_solutions)-1)):
        #print ("compute", array_of_ALE_solutions[i], array_of_ALE_solutions[i+1], array_of_ALE_solutions[i]-array_of_ALE_solutions[i+1])
        bs = array_of_ALE_solutions[i]-array_of_ALE_solutions[i+1]
        i += 1
        solutions.append(bs)
    return solutions
'''' ------end------------'''


'''' RETURN on INVESTMENT'''
def return_on_investment(array_of_ALE_solutions,cost_security):

    BS = benefit_of_security(array_of_ALE_solutions)
    #print ("here",BS)
    #cost_security=[]
    solutions = []
    i = 0
    while (i < (len(BS))):
        ROI = (BS[i] - cost_security[i]) / cost_security[i]
        #ROI = ((array_of_ALE_solutions[i]-array_of_ALE_solutions[i+1]) - cost_security[i])/cost_security[i]
        i += 1
        solutions.append(ROI)
    return solutions
'''' ------end------------'''
'''' END TEMPORAL NETWORK'''




def filter_ignorables(path):
    return [node for node in path if node.ignorable is False]

def _all_simple_paths_graph(G, source, target, cutoff=None):
    """
    Modified version of NetworkX _all_simple_paths_graph
    but for attack graphs.
    Notably, this ignores hosts with no vulnerabilities
    and ignores ignorable set hosts.

    :param G:
    :param source:
    :param target:
    :param cutoff:
    :return:
    """

    if cutoff is None:
        cutoff = len(G) - 1

    if cutoff < 1:
        return
    visited = [source]
    stack = [iter(G[source])]
    while stack:
        children = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            visited.pop()
        elif len(visited) < cutoff:
            if child == target:
                yield filter_ignorables(visited + [target])
            elif child not in visited and (child.ignorable is True or child.lower_layer.is_vulnerable()):
                # must check that there are vulnerabilities
                visited.append(child)
                stack.append(iter(G[child]))
        else:  # len(visited) == cutoff:
            if child == target or target in children:
                yield filter_ignorables(visited + [target])
            stack.pop()
            visited.pop()




'''--------------------------------------------------------------------
                THREAT GUIDED  RISK CALCULATIONS
----------------------------------------------------------------------'''
'''---------------------------------------------------------------------'
Note: In the simulations, you need to define the following
 * threat class for each vulnerability  e.g., vul.threat_class = "S"
 * threat impact weight e.g.,  vul.values['threat_impact'] = 20
----------------------------------------------------------------------'''

'''a node impact from cvss '''
def impact_of_host(node):
    node_impact_sum = 0
    for vul in node.lower_layer.all_vulns():
        node_impact_sum += vul.impact
    return node_impact_sum


#threat impact for node
def all_threat_node_risk(node):
    i=0
    threat_impact_sum = sum(list(node.threat_impact.values()))
    node_risk = impact_of_host(node) * node.probability*threat_impact_sum
    return  node_risk

def sub_threat_node_risk(node,sub_stride):
    'sub_stride is an array of string belong to STRIDE'
    threat_impact_sum =0
    for threat in sub_stride:
        threat_impact_sum += node.threat_impact[threat]
    node_risk= impact_of_host(node) * node.probability * threat_impact_sum
    return node_risk


'''System Risk for all Threats'''
def system_risk(harm):
    system_risk = 0
    for node in harm[0].hosts():
        system_risk += all_threat_node_risk(node)
    return system_risk


'''Some threat System Risk'''
def sub_system_risk(harm, sub_stride):
    system_risk = 0
    for node in harm[0].hosts():
        system_risk += sub_threat_node_risk(node,sub_stride)
    return system_risk

'''SUB_SYSTEM RISK'''
'''All threats - System Risk'''
def sub_component_risk(harm, some_nodes):
    system_risk = 0
    for node in some_nodes:
        host = harm[0].find_node(node)
        system_risk += all_threat_node_risk(host)
    return system_risk


'''Some threat System Risk'''
def sub_component_and_sub_thread_risk(harm, sub_stride, some_nodes):
    system_risk = 0
    for node in some_nodes:
        host = harm[0].find_node(node)
        system_risk += sub_threat_node_risk(host,sub_stride)
    return system_risk
'''END ........'''


'''--------PATH RISK-------------------'''
def path_all_threat_risk(harm):
    if not harm[0].all_paths:
        harm[0].find_paths()
    #for path in harm[0].all_paths:
        #print (threat_path_risk(path))
    return sum(threat_path_risk(path) for path in harm[0].all_paths)

def threat_path_risk(path):
    return sum((all_threat_node_risk(node)) for node in path[1:])



'''Some Threats - Path RISK'''
def path_sub_threat_risk(harm, sub_stride):
    if not harm[0].all_paths:
        harm[0].find_paths()
    #for path in harm[0].all_paths:
        #print (sub_threat_path_risk(path,sub_stride))
        #sub_threat_path_risk(path, sub_stride)
    return sum(sub_threat_path_risk(path,sub_stride) for path in harm[0].all_paths)
def sub_threat_path_risk(path, sub_stride):
    sub_threat_risk=0
    for node in path[1:]:
        sub_threat_risk += sub_threat_node_risk(node,sub_stride)
    return sub_threat_risk


def print_host_level_threat_metric(harm, sub_stride):
    for host in harm[0].hosts():
        print ('hostname:', host.name)
        print ('impact:',impact_of_host(host))
        print ('threat impact:', all_threat_node_risk(host))
        print ('sub threat impact:', sub_threat_node_risk(host, sub_stride))
        print('_________________________________')
    print ('................................................')
def print_metrics_system_risk(harm, sub_stride):
    print ('overall system risk:', system_risk(harm))
    print ('sub_system risk-',sub_stride,':', sub_system_risk(harm, sub_stride))
    print('................................................')

def print_metrics_sub_system_risk(harm, sub_stride, some_nodes):
    print ('sub component risk:', sub_component_risk(harm, some_nodes))
    print ('sub component and sub threat risk:', sub_component_and_sub_thread_risk(harm, sub_stride, some_nodes))
    print('................................................')

def print_metrics_path_threat_risk(harm, sub_stride):
    print ('path risks')
    path_all_threat_risk(harm)
    path_sub_threat_risk(harm, sub_stride)
    print('................................................')

