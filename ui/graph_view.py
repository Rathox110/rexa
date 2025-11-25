from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsLineItem, QGraphicsTextItem, QFileDialog
)
from PyQt6.QtCore import Qt, pyqtSignal, QPointF, QRectF
from PyQt6.QtGui import QPen, QBrush, QColor, QPainter
import math

class GraphView(QWidget):
    """Interactive graph visualization for call graphs and CFGs"""
    
    back_to_analysis = pyqtSignal()
    
    def __init__(self, sample_id, db_manager):
        super().__init__()
        self.sample_id = sample_id
        self.db = db_manager
        self.graph_data = None
        self.graph_type = 'call'  # 'call' or 'cfg'
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        back_btn = QPushButton("← Back")
        back_btn.clicked.connect(self.back_to_analysis.emit)
        toolbar.addWidget(back_btn)
        
        toolbar.addWidget(QLabel("Graph Type:"))
        self.graph_type_combo = QComboBox()
        self.graph_type_combo.addItems(["Call Graph", "Control Flow Graph", "Import Graph"])
        self.graph_type_combo.currentTextChanged.connect(self.on_graph_type_changed)
        toolbar.addWidget(self.graph_type_combo)
        
        toolbar.addWidget(QLabel("Layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Hierarchical", "Force-Directed", "Circular"])
        self.layout_combo.currentTextChanged.connect(self.update_layout)
        toolbar.addWidget(self.layout_combo)
        
        toolbar.addStretch()
        
        generate_btn = QPushButton("🔄 Generate")
        generate_btn.clicked.connect(self.generate_graph)
        toolbar.addWidget(generate_btn)
        
        export_btn = QPushButton("💾 Export")
        export_btn.clicked.connect(self.export_graph)
        toolbar.addWidget(export_btn)
        
        layout.addLayout(toolbar)
        
        # Graph view
        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.setStyleSheet("background-color: #1e1e1e; border: 1px solid #3e3e3e;")
        
        layout.addWidget(self.view)
        
        # Stats label
        self.stats_label = QLabel("No graph generated")
        self.stats_label.setStyleSheet("color: #888;")
        layout.addWidget(self.stats_label)
    
    def on_graph_type_changed(self, text):
        """Handle graph type change"""
        if text == "Call Graph":
            self.graph_type = 'call'
        elif text == "Control Flow Graph":
            self.graph_type = 'cfg'
        elif text == "Import Graph":
            self.graph_type = 'import'
    
    def generate_graph(self):
        """Generate and display graph"""
        if self.graph_type == 'call':
            self.generate_call_graph()
        elif self.graph_type == 'cfg':
            self.generate_cfg()
        elif self.graph_type == 'import':
            self.generate_import_graph()
    
    def generate_call_graph(self):
        """Generate call graph"""
        # Get functions
        functions = self.db.get_sample_functions(self.sample_id)
        
        if not functions:
            self.stats_label.setText("No functions available. Run disassembly first.")
            return
        
        # Create graph using visualization module
        try:
            from core.visualization.call_graph import CallGraphGenerator
            
            # Build graph
            generator = CallGraphGenerator()
            
            # Convert functions to dict format
            func_dicts = [
                {
                    'address': f.address,
                    'name': f.name,
                    'size': f.size,
                    'is_import': f.is_import
                }
                for f in functions
            ]
            
            # For now, use empty xrefs (would load from database)
            xrefs = []
            
            graph = generator.build_from_functions(func_dicts, xrefs)
            
            # Display graph
            self.display_networkx_graph(graph)
            
            # Update stats
            metrics = generator.metrics
            self.stats_label.setText(
                f"Functions: {metrics['total_functions']} | "
                f"Calls: {metrics['total_calls']} | "
                f"Entry Points: {metrics['entry_points']}"
            )
            
        except Exception as e:
            self.stats_label.setText(f"Error: {e}")
    
    def generate_cfg(self):
        """Generate control flow graph"""
        self.stats_label.setText("CFG generation not yet implemented")
    
    def generate_import_graph(self):
        """Generate import dependency graph"""
        self.stats_label.setText("Import graph not yet implemented")
    
    def display_networkx_graph(self, graph):
        """Display NetworkX graph"""
        self.scene.clear()
        
        if graph.number_of_nodes() == 0:
            return
        
        # Simple circular layout
        nodes = list(graph.nodes())
        n = len(nodes)
        radius = 200
        center_x = 0
        center_y = 0
        
        # Position nodes
        node_positions = {}
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / n
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            node_positions[node] = (x, y)
        
        # Draw edges
        for edge in graph.edges():
            from_node, to_node = edge
            from_pos = node_positions[from_node]
            to_pos = node_positions[to_node]
            
            line = QGraphicsLineItem(from_pos[0], from_pos[1], to_pos[0], to_pos[1])
            line.setPen(QPen(QColor("#666666"), 1))
            self.scene.addItem(line)
        
        # Draw nodes
        for node in nodes:
            x, y = node_positions[node]
            
            # Node circle
            node_item = QGraphicsEllipseItem(x - 15, y - 15, 30, 30)
            node_item.setBrush(QBrush(QColor("#007acc")))
            node_item.setPen(QPen(QColor("#ffffff"), 2))
            self.scene.addItem(node_item)
            
            # Node label
            name = graph.nodes[node].get('name', node)
            label = QGraphicsTextItem(name)
            label.setDefaultTextColor(QColor("#ffffff"))
            label.setPos(x - 20, y + 20)
            self.scene.addItem(label)
        
        # Fit in view
        self.view.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
    
    def update_layout(self, layout_name):
        """Update graph layout"""
        # Would implement different layout algorithms
        pass
    
    def export_graph(self):
        """Export graph"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Graph",
            "",
            "PNG Image (*.png);;SVG Image (*.svg);;DOT File (*.dot)"
        )
        
        if filename:
            if filename.endswith('.png'):
                # Export as PNG
                from PyQt6.QtGui import QImage, QPainter
                
                rect = self.scene.sceneRect()
                image = QImage(int(rect.width()), int(rect.height()), QImage.Format.Format_ARGB32)
                image.fill(Qt.GlobalColor.white)
                
                painter = QPainter(image)
                self.scene.render(painter)
                painter.end()
                
                image.save(filename)
