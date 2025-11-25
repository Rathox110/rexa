import networkx as nx
from collections import defaultdict

class CallGraphGenerator:
    """Generate call graphs from disassembly data"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.entry_points = []
        self.metrics = {}
    
    def build_from_functions(self, functions, xrefs):
        """
        Build call graph from function list and cross-references
        
        Args:
            functions: List of function dicts with address, name, size
            xrefs: List of cross-reference dicts with from_address, to_address, type
        """
        # Add all functions as nodes
        for func in functions:
            self.graph.add_node(
                func['address'],
                name=func['name'],
                size=func.get('size', 0),
                is_import=func.get('is_import', False)
            )
        
        # Add call edges from xrefs
        for xref in xrefs:
            if xref['xref_type'] == 'call':
                self.graph.add_edge(
                    xref['from_address'],
                    xref['to_address'],
                    type='call'
                )
        
        # Identify entry points
        self._identify_entry_points(functions)
        
        # Calculate metrics
        self._calculate_metrics()
        
        return self.graph
    
    def _identify_entry_points(self, functions):
        """Identify entry points (main, DllMain, exports)"""
        for func in functions:
            name = func['name'].lower()
            address = func['address']
            
            # Common entry point names
            if any(ep in name for ep in ['main', 'start', 'dllmain', 'winmain']):
                self.entry_points.append(address)
            
            # Functions with no callers are potential entry points
            elif self.graph.in_degree(address) == 0 and not func.get('is_import'):
                self.entry_points.append(address)
    
    def _calculate_metrics(self):
        """Calculate graph metrics"""
        self.metrics = {
            'total_functions': self.graph.number_of_nodes(),
            'total_calls': self.graph.number_of_edges(),
            'entry_points': len(self.entry_points),
            'max_depth': 0,
            'complexity': 0,
        }
        
        # Calculate depth from entry points
        if self.entry_points:
            depths = []
            for entry in self.entry_points:
                try:
                    # BFS to find maximum depth
                    levels = nx.single_source_shortest_path_length(self.graph, entry)
                    depths.append(max(levels.values()) if levels else 0)
                except:
                    pass
            self.metrics['max_depth'] = max(depths) if depths else 0
        
        # Calculate cyclomatic complexity (simplified)
        self.metrics['complexity'] = self.graph.number_of_edges() - self.graph.number_of_nodes() + 2
    
    def find_recursive_calls(self):
        """Detect recursive function calls"""
        recursive = []
        
        try:
            cycles = list(nx.simple_cycles(self.graph))
            for cycle in cycles:
                if len(cycle) == 1:  # Self-recursion
                    recursive.append({
                        'type': 'direct',
                        'function': cycle[0],
                        'name': self.graph.nodes[cycle[0]].get('name')
                    })
                else:  # Mutual recursion
                    recursive.append({
                        'type': 'mutual',
                        'functions': cycle,
                        'names': [self.graph.nodes[addr].get('name') for addr in cycle]
                    })
        except:
            pass
        
        return recursive
    
    def get_function_callers(self, function_address):
        """Get all functions that call the specified function"""
        return list(self.graph.predecessors(function_address))
    
    def get_function_callees(self, function_address):
        """Get all functions called by the specified function"""
        return list(self.graph.successors(function_address))
    
    def get_call_chain(self, from_address, to_address):
        """Find call chain between two functions"""
        try:
            paths = list(nx.all_simple_paths(self.graph, from_address, to_address, cutoff=10))
            return paths
        except:
            return []
    
    def calculate_centrality(self):
        """Calculate centrality metrics for functions"""
        centrality = {}
        
        try:
            # Degree centrality (how many connections)
            degree_cent = nx.degree_centrality(self.graph)
            
            # Betweenness centrality (how often function is in call paths)
            between_cent = nx.betweenness_centrality(self.graph)
            
            # PageRank (importance based on callers)
            pagerank = nx.pagerank(self.graph)
            
            for node in self.graph.nodes():
                centrality[node] = {
                    'degree': degree_cent.get(node, 0),
                    'betweenness': between_cent.get(node, 0),
                    'pagerank': pagerank.get(node, 0),
                }
        except:
            pass
        
        return centrality
    
    def export_dot(self, output_path):
        """Export graph to DOT format for Graphviz"""
        nx.drawing.nx_pydot.write_dot(self.graph, output_path)
    
    def export_graphml(self, output_path):
        """Export graph to GraphML format"""
        nx.write_graphml(self.graph, output_path)
    
    def get_subgraph(self, function_address, depth=2):
        """Get subgraph around a function"""
        nodes = {function_address}
        
        # Add neighbors up to specified depth
        for _ in range(depth):
            new_nodes = set()
            for node in nodes:
                new_nodes.update(self.graph.predecessors(node))
                new_nodes.update(self.graph.successors(node))
            nodes.update(new_nodes)
        
        return self.graph.subgraph(nodes)
