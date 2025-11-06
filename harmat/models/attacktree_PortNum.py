"""
Tree class
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

#from builtins import filter
#from builtins import map
from functools import reduce

from future import standard_library

#standard_library.install_aliases()
from .treeFor_PN import PNoTree
from .node_portNum import *
from collections import OrderedDict

# Some helper functions for ignoring None values
# Useful when Harm is not fully defined

def ignore_none_func(func, iterable):
    return func(filter(lambda x: x is not None, iterable))

def flowup_sum(iterable):
    return ignore_none_func(sum, iterable)


def flowup_max(iterable):
    return ignore_none_func(max, iterable)


def flowup_min(iterable):
    return ignore_none_func(min, iterable)


def flowup_or_prob(iterable):
    return 1 - reduce(lambda x, y: x * y, map(lambda x: 1 - x, iterable))


def flowup_and_prob(iterable):
    return reduce(lambda x, y: x * y, iterable)


'''******************'''

class Port_number_Tree(PNoTree):
    """
    Port number Tree class
    Must specify the rootnode variable before use
    """
    # Try to use OrderedDict so that the calculation order is deterministic
    flowup_calc_dict = OrderedDict({
        'or': OrderedDict({
            'pn_value': flowup_max,

        }),
        'and': OrderedDict({
            'risk': flowup_sum,
        }),
    })

    def __init__(self):
        PNoTree.__init__(self)

    def __repr__(self):
        return self.__class__.__name__



    @property
    def values(self):
        return self.rootnode.values


    def flowup_PN(self, current_node=None):
        if current_node is None:
            current_node = self.rootnode
        elif isinstance(current_node, LogicGate):
            children_nodes = list(self.neighbors(current_node))
            values = [self.flowup_PN(child) for child in children_nodes if child is not None]
            if len(values) != 0:
                for metric, function in self.flowup_calc_dict[current_node.gatetype].items():
                    current_node.values[metric] = function(value_dict.get(metric) for value_dict in values)
            return current_node.values
        else:
            raise TypeError("Weird type came in: {}".format(type(current_node)))

    def all_port_numbers(self):
        """
        Returns all port number objects in this Tree

        Returns:
            A generator containing all port numbers
        """
        return (port_num for port_num in self.nodes() if isinstance(port_num, PortNumber))

    def find_port_by_name(self, name):
        for portnum in self.all_port_numbers():
            if portnum.name == name:
                return portnum


    def portTree_add_node(self, node, logic_gate=None):
        """
        Add a port number to a logic gate.
        If logic_gate is not specified, this will default to adding to the rootnode
        """
        if logic_gate is None:
            logic_gate = self.rootnode
        self.add_node(node)
        self.add_edge(logic_gate, node)

    def create_portnum_tree(self, portnums):
        """
        Creates a basic Attack tree which contains vulnerabilities in vulns like the following:

                root
                 |
                 OR
            -------------
            | | | | | | |
            v v v v v v v

        Args:
            vulns:  A list containing vulnerabilities/logic gate. Can be a single node.
        """
        if self.rootnode is None:  # if rootnode hasn't been created yet
            lg = LogicGate('or')
            self.rootnode = lg
            self.add_node(lg)
        else:
            lg = self.rootnode  # if rootnode already exists, just add nodes to that
        if not isinstance(portnums, list):
            portnums = [portnums]
        for portn in portnums:
            self.portTree_add_node(portn, lg)