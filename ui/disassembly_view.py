from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QListWidget, QTextEdit,
    QPushButton, QLineEdit, QLabel, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter
import json

class AsmSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for assembly code"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Define highlighting rules
        self.highlighting_rules = []
        
        # Mnemonics (instructions)
        mnemonic_format = QTextCharFormat()
        mnemonic_format.setForeground(QColor("#569CD6"))  # Blue
        mnemonic_format.setFontWeight(QFont.Weight.Bold)
        mnemonics = ['mov', 'push', 'pop', 'call', 'jmp', 'je', 'jne', 'jz', 'jnz', 
                     'add', 'sub', 'xor', 'and', 'or', 'lea', 'ret', 'test', 'cmp']
        for mnemonic in mnemonics:
            self.highlighting_rules.append((f"\\b{mnemonic}\\b", mnemonic_format))
        
        # Registers
        register_format = QTextCharFormat()
        register_format.setForeground(QColor("#4EC9B0"))  # Cyan
        registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
                     'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp']
        for reg in registers:
            self.highlighting_rules.append((f"\\b{reg}\\b", register_format))
        
        # Hex numbers
        hex_format = QTextCharFormat()
        hex_format.setForeground(QColor("#B5CEA8"))  # Light green
        self.highlighting_rules.append(("0x[0-9a-fA-F]+", hex_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))  # Green
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((";.*", comment_format))
    
    def highlightBlock(self, text):
        import re
        for pattern, fmt in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)

class DisassemblyView(QWidget):
    """Interactive disassembly viewer with function list and code display"""
    
    back_to_analysis = pyqtSignal()
    
    def __init__(self, sample_id, db_manager):
        super().__init__()
        self.sample_id = sample_id
        self.db = db_manager
        self.functions = []
        self.current_function = None
        
        self.init_ui()
        self.load_disassembly()
    
    def init_ui(self):
        """Initialize the UI layout"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Top toolbar
        toolbar = QHBoxLayout()
        
        back_btn = QPushButton("← Back to Analysis")
        back_btn.clicked.connect(self.back_to_analysis.emit)
        toolbar.addWidget(back_btn)
        
        toolbar.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by mnemonic, address, or API...")
        self.search_input.textChanged.connect(self.search_code)
        toolbar.addWidget(self.search_input)
        
        analyze_btn = QPushButton("🔄 Re-analyze")
        analyze_btn.clicked.connect(self.run_disassembly)
        toolbar.addWidget(analyze_btn)
        
        export_btn = QPushButton("💾 Export")
        export_btn.clicked.connect(self.export_assembly)
        toolbar.addWidget(export_btn)
        
        layout.addLayout(toolbar)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel: Function list
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(5, 5, 5, 5)
        
        left_layout.addWidget(QLabel("Functions:"))
        
        self.function_list = QListWidget()
        self.function_list.itemClicked.connect(self.on_function_selected)
        left_layout.addWidget(self.function_list)
        
        # Function stats
        self.stats_label = QLabel("Total: 0 functions")
        self.stats_label.setStyleSheet("color: #888; font-size: 10px;")
        left_layout.addWidget(self.stats_label)
        
        splitter.addWidget(left_panel)
        
        # Center panel: Disassembly listing
        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(5, 5, 5, 5)
        
        center_layout.addWidget(QLabel("Disassembly:"))
        
        self.disasm_view = QTextEdit()
        self.disasm_view.setReadOnly(True)
        self.disasm_view.setFont(QFont("Courier New", 10))
        self.disasm_view.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e3e;
            }
        """)
        
        # Apply syntax highlighting
        self.highlighter = AsmSyntaxHighlighter(self.disasm_view.document())
        
        center_layout.addWidget(self.disasm_view)
        
        splitter.addWidget(center_panel)
        
        # Right panel: Cross-references and details
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(5, 5, 5, 5)
        
        right_layout.addWidget(QLabel("Cross-References:"))
        
        self.xref_table = QTableWidget()
        self.xref_table.setColumnCount(3)
        self.xref_table.setHorizontalHeaderLabels(["From", "To", "Type"])
        self.xref_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        right_layout.addWidget(self.xref_table)
        
        # Function info
        right_layout.addWidget(QLabel("Function Info:"))
        self.func_info = QTextEdit()
        self.func_info.setReadOnly(True)
        self.func_info.setMaximumHeight(150)
        right_layout.addWidget(self.func_info)
        
        splitter.addWidget(right_panel)
        
        # Set splitter sizes
        splitter.setSizes([250, 600, 250])
        
        layout.addWidget(splitter)
    
    def load_disassembly(self):
        """Load disassembly data from database"""
        self.functions = self.db.get_sample_functions(self.sample_id)
        
        if not self.functions:
            # No disassembly yet, show message
            self.disasm_view.setPlainText("No disassembly available. Click 'Re-analyze' to generate.")
            return
        
        # Populate function list
        self.function_list.clear()
        for func in self.functions:
            item_text = f"{func.address}  {func.name}"
            if func.is_import:
                item_text += " (import)"
            self.function_list.addItem(item_text)
        
        self.stats_label.setText(f"Total: {len(self.functions)} functions")
        
        # Select first function
        if self.functions:
            self.function_list.setCurrentRow(0)
            self.on_function_selected(self.function_list.item(0))
    
    def on_function_selected(self, item):
        """Handle function selection"""
        if not item:
            return
        
        index = self.function_list.row(item)
        if index < 0 or index >= len(self.functions):
            return
        
        func = self.functions[index]
        self.current_function = func
        
        # Display function disassembly
        self.display_function(func)
        
        # Update function info
        info_text = f"""
Address: {func.address}
Name: {func.name}
Size: {func.size} bytes
Type: {'Import' if func.is_import else 'Code'}
        """.strip()
        self.func_info.setPlainText(info_text)
        
        # Load cross-references
        self.load_xrefs(func.address)
    
    def display_function(self, func):
        """Display function disassembly"""
        # For now, show placeholder
        # In full implementation, would load instructions from database
        disasm_text = f"; Function: {func.name}\n"
        disasm_text += f"; Address: {func.address}\n"
        disasm_text += f"; Size: {func.size} bytes\n\n"
        
        if func.decompiled_code:
            disasm_text += "; Decompiled code:\n"
            disasm_text += func.decompiled_code
        else:
            disasm_text += "; Assembly code would be displayed here\n"
            disasm_text += "; (Load instructions from database in full implementation)\n"
        
        self.disasm_view.setPlainText(disasm_text)
    
    def load_xrefs(self, address):
        """Load cross-references for address"""
        # Placeholder - would query database for xrefs
        self.xref_table.setRowCount(0)
    
    def search_code(self, query):
        """Search for code by mnemonic, address, or API"""
        if not query:
            return
        
        # Simple search in function names
        for i in range(self.function_list.count()):
            item = self.function_list.item(i)
            if query.lower() in item.text().lower():
                self.function_list.setCurrentItem(item)
                break
    
    def run_disassembly(self):
        """Run disassembly analysis"""
        # Get sample
        sample = self.db.get_sample(self.sample_id)
        if not sample:
            return
        
        try:
            # Import disassembly engine
            from core.disassembly.capstone_engine import CapstoneEngine
            
            # Read file
            with open(sample.file_path, 'rb') as f:
                data = f.read()
            
            # Disassemble
            engine = CapstoneEngine('x86_64')
            instructions = engine.disassemble(data)
            
            # Identify functions
            functions = engine.identify_functions(instructions)
            
            # Save to database
            for func in functions:
                self.db.add_function(
                    self.sample_id,
                    func['address'],
                    func['name'],
                    func['size']
                )
            
            # Reload
            self.load_disassembly()
            
        except Exception as e:
            self.disasm_view.setPlainText(f"Error during disassembly: {e}")
    
    def export_assembly(self):
        """Export assembly listing"""
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Assembly",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                f.write(self.disasm_view.toPlainText())
