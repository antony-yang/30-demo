class Cluster(object):

    id = None
    nodes = []

    def __init__(self, cluster_id=None):
        """
        Class constructor.
        """

        self.id = cluster_id
        self.nodes = []

    def add_node(self, node):
        """
        Add a node to the cluster.

        @type  node: pGRAPH Node
        @param node: Node to add to cluster
        """

        self.nodes.append(node)

        return self

    def del_node(self, node_id):
        """
        Remove a node from the cluster.

        @type  node_id: pGRAPH Node
        @param node_id: Node to remove from cluster
        """

        for node in self.nodes:
            if node.id == node_id:
                self.nodes.remove(node)
                break

        return self

    def find_node(self, attribute, value):
        """
        Find and return the node with the specified attribute / value pair.

        @type  attribute: str
        @param attribute: Attribute name we are looking for
        @type  value:     Mixed
        @param value:     Value of attribute we are looking for

        @rtype:  Mixed
        @return: Node, if attribute / value pair is matched. None otherwise.
        """

        for node in self.nodes:
            if hasattr(node, attribute):
                if getattr(node, attribute) == value:
                    return node

        return None

    def render(self):
        pass
