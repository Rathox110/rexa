import networkx as nx

class CFGGenerator:
    """Control Flow Graph generator for individual functions"""
    
    def __init__(self):
        self.cfg = nx.DiGraph()
    
    def build_from_basic_blocks(self, basic_blocks, edges):
        """
        Build CFG from basic blocks and edges
        
        Args:
            basic_blocks: List of basic block dicts
            edges: List of edge dicts with from/to addresses and type
        """
        # Add basic blocks as nodes
        for bb in basic_blocks:
            self.cfg.add_node(
                bb['start_address'],
                end_address=bb['end_address'],
                instructions=bb['instructions'],
                type=bb.get('type', 'sequential')
            )
        
        # Add edges
        for edge in edges:
            self.cfg.add_edge(
                edge['from'],
                edge['to'],
                type=edge['type']
            )
        
        return self.cfg
    
    def detect_loops(self):
        """Detect loops in the CFG"""
        loops = []
        
        try:
            # Find back edges (edges that point to ancestors in DFS tree)
            cycles = list(nx.simple_cycles(self.cfg))
            
            for cycle in cycles:
                loop_type = self._classify_loop(cycle)
                loops.append({
                    'type': loop_type,
                    'blocks': cycle,
                    'header': cycle[0] if cycle else None
                })
        except:
            pass
        
        return loops
    
    def _classify_loop(self, cycle):
        """Classify loop type (while, for, do-while)"""
        if len(cycle) == 1:
            return 'self-loop'
        elif len(cycle) == 2:
            return 'simple-loop'
        else:
            return 'complex-loop'
    
    def detect_conditionals(self):
        """Detect if/else patterns"""
        conditionals = []
        
        for node in self.cfg.nodes():
            successors = list(self.cfg.successors(node))
            
            # Conditional branches have 2 successors
            if len(successors) == 2:
                edges = [(node, succ) for succ in successors]
                edge_types = [self.cfg[node][succ]['type'] for succ in successors]
                
                # One should be conditional, one fallthrough
                if 'conditional' in edge_types:
                    conditionals.append({
                        'address': node,
                        'true_branch': successors[0],
                        'false_branch': successors[1],
                    })
        
        return conditionals
    
    def detect_switches(self):
        """Detect switch/case patterns"""
        switches = []
        
        for node in self.cfg.nodes():
            successors = list(self.cfg.successors(node))
            
            # Switch statements have multiple successors
            if len(successors) > 2:
                switches.append({
                    'address': node,
                    'cases': successors,
                    'num_cases': len(successors)
                })
        
        return switches
    
    def calculate_dominator_tree(self):
        """Calculate dominator tree"""
        try:
            # Find entry node (node with no predecessors)
            entry_nodes = [n for n in self.cfg.nodes() if self.cfg.in_degree(n) == 0]
            if not entry_nodes:
                return {}
            
            entry = entry_nodes[0]
            dominators = nx.dominance.immediate_dominators(self.cfg, entry)
            return dominators
        except:
            return {}
    
    def get_complexity(self):
        """Calculate cyclomatic complexity"""
        # McCabe's cyclomatic complexity: E - N + 2
        # where E = edges, N = nodes
        edges = self.cfg.number_of_edges()
        nodes = self.cfg.number_of_nodes()
        return edges - nodes + 2
    
    def export_dot(self, output_path):
        """Export CFG to DOT format"""
        nx.drawing.nx_pydot.write_dot(self.cfg, output_path)
