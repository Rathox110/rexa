from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget, QTextEdit, QTableWidget, QTableWidgetItem, 
    QLabel, QPushButton, QHBoxLayout, QMessageBox, QFrame, QFileDialog
)
from PyQt6.QtCore import pyqtSignal, QThread
from PyQt6.QtGui import QFont
import json
from ui.widgets.hex_editor import HexEditor
from core.ai.llm import OllamaProvider, CodeExplainer
from core.reporting import ReportGenerator

class AIWorker(QThread):
    finished = pyqtSignal(str)
    
    def __init__(self, text):
        super().__init__()
        self.text = text

    def run(self):
        provider = OllamaProvider()
        explainer = CodeExplainer(provider)
        result = explainer.explain_strings(self.text)
        self.finished.emit(result)

class AnalysisView(QWidget):
    back_to_project = pyqtSignal()
    open_disassembly = pyqtSignal()
    open_sandbox = pyqtSignal()
    open_graph = pyqtSignal()
    open_threat_intel = pyqtSignal()

    def __init__(self, sample_id, db_manager):
        super().__init__()
        self.sample_id = sample_id
        self.db = db_manager
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)
        self.sample = None
        self.analysis = {}
        self.init_ui()

    def init_ui(self):
        # Header
        header_container = QFrame()
        header_layout = QVBoxLayout(header_container)
        
        # Back button
        back_btn = QPushButton("← Back to Project")
        back_btn.clicked.connect(self.back_to_project.emit)
        back_btn.setMaximumWidth(200)
        header_layout.addWidget(back_btn)
        
        # Title
        self.title = QLabel("📄 Sample Analysis")
        self.title.setProperty("class", "header")
        self.title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header_layout.addWidget(self.title)
        
        # File info
        self.file_info = QLabel("")
        self.file_info.setStyleSheet("color: #b0b0b0; font-size: 10pt;")
        header_layout.addWidget(self.file_info)
        
        self.layout.addWidget(header_container)

        # Action Buttons
        action_layout = QHBoxLayout()
        action_layout.setSpacing(10)
        
        # Advanced analysis buttons
        disasm_btn = QPushButton("🔍 Disassembly")
        disasm_btn.clicked.connect(self.open_disassembly.emit)
        disasm_btn.setToolTip("View disassembly with Capstone")
        action_layout.addWidget(disasm_btn)
        
        sandbox_btn = QPushButton("📦 Sandbox")
        sandbox_btn.clicked.connect(self.open_sandbox.emit)
        sandbox_btn.setToolTip("Submit to Cuckoo/CAPE sandbox")
        action_layout.addWidget(sandbox_btn)
        
        graph_btn = QPushButton("📊 Graphs")
        graph_btn.clicked.connect(self.open_graph.emit)
        graph_btn.setToolTip("View call graphs and CFG")
        action_layout.addWidget(graph_btn)
        
        intel_btn = QPushButton("🌐 Threat Intel")
        intel_btn.clicked.connect(self.open_threat_intel.emit)
        intel_btn.setToolTip("Enrich with VirusTotal/OTX")
        action_layout.addWidget(intel_btn)
        
        action_layout.addStretch()
        
        # Export buttons
        self.export_json_btn = QPushButton("📥 Export JSON")
        self.export_json_btn.clicked.connect(self.export_json)
        action_layout.addWidget(self.export_json_btn)
        
        self.export_html_btn = QPushButton("📄 Export HTML")
        self.export_html_btn.clicked.connect(self.export_html)
        action_layout.addWidget(self.export_html_btn)
        
        self.ai_btn = QPushButton("🤖 AI Analysis")
        self.ai_btn.setProperty("class", "primary")
        self.ai_btn.clicked.connect(self.explain_strings)
        self.ai_btn.setEnabled(False)
        action_layout.addWidget(self.ai_btn)
        
        action_layout.addStretch()
        self.layout.addLayout(action_layout)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3e3e3e;
                background-color: #252526;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #2d2d2d;
                color: #d4d4d4;
                padding: 12px 24px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-size: 10pt;
            }
            QTabBar::tab:selected {
                background-color: #007acc;
                color: #ffffff;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: #3e3e3e;
            }
        """)
        self.layout.addWidget(self.tabs)
        
        # Summary Tab
        self.summary_tab = QTextEdit()
        self.summary_tab.setReadOnly(True)
        self.summary_tab.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                border: none;
                padding: 15px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10pt;
            }
        """)
        self.tabs.addTab(self.summary_tab, "📊 Summary")
        
        # Imports Tab
        self.imports_tab = QTableWidget()
        self.imports_tab.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e1e;
                border: none;
            }
        """)
        self.tabs.addTab(self.imports_tab, "📦 Imports")
        
        # Strings Tab
        self.strings_tab = QTextEdit()
        self.strings_tab.setReadOnly(True)
        self.strings_tab.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                border: none;
                padding: 15px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 9pt;
            }
        """)
        self.tabs.addTab(self.strings_tab, "🔤 Strings")

        # Hex View Tab
        self.hex_tab = HexEditor()
        self.tabs.addTab(self.hex_tab, "🔢 Hex View")

        # YARA Tab
        self.yara_tab = QTableWidget()
        self.yara_tab.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e1e;
                border: none;
            }
        """)
        self.tabs.addTab(self.yara_tab, "🛡️ YARA")

        self.load_data()

    def load_data(self):
        self.sample = self.db.get_sample(self.sample_id)
        if not self.sample:
            self.title.setText("❌ Sample not found")
            return

        self.title.setText(f"📄 {self.sample.filename}")
        self.file_info.setText(f"MD5: {self.sample.md5} • SHA256: {self.sample.sha256}")
        
        try:
            self.analysis = json.loads(self.sample.analysis_json)
        except:
            self.analysis = {}

        # Summary
        summary = f"═══════════════════════════════════════════════════\n"
        summary += f"  FILE INFORMATION\n"
        summary += f"═══════════════════════════════════════════════════\n\n"
        summary += f"Filename:  {self.sample.filename}\n"
        summary += f"Path:      {self.sample.file_path}\n"
        summary += f"MD5:       {self.sample.md5}\n"
        summary += f"SHA256:    {self.sample.sha256}\n"
        if 'type' in self.analysis:
            summary += f"Type:      {self.analysis['type']}\n"
        if 'sections' in self.analysis:
            summary += f"\n═══════════════════════════════════════════════════\n"
            summary += f"  PE SECTIONS ({len(self.analysis['sections'])})\n"
            summary += f"═══════════════════════════════════════════════════\n\n"
            for sec in self.analysis['sections']:
                summary += f"  {sec['name']:<10} | Entropy: {sec.get('entropy', 0):.2f}\n"
        self.summary_tab.setText(summary)
        
        # Load Hex
        self.hex_tab.load_file(self.sample.file_path)

        # Imports
        if 'imports' in self.analysis:
            self.imports_tab.setColumnCount(2)
            self.imports_tab.setHorizontalHeaderLabels(["DLL", "Function"])
            self.imports_tab.setRowCount(0)
            row = 0
            for dll, funcs in self.analysis['imports'].items():
                for func in funcs:
                    self.imports_tab.insertRow(row)
                    self.imports_tab.setItem(row, 0, QTableWidgetItem(dll))
                    func_name = func['name'] if isinstance(func, dict) else str(func)
                    self.imports_tab.setItem(row, 1, QTableWidgetItem(func_name))
                    row += 1
            self.imports_tab.resizeColumnsToContents()
        
        # Strings
        if 'strings' in self.analysis:
            self.strings_tab.setText("\n".join(self.analysis['strings']))
        elif 'strings_error' in self.analysis:
            self.strings_tab.setText(f"Error extracting strings: {self.analysis['strings_error']}")

        # YARA
        if 'yara' in self.analysis and len(self.analysis['yara']) > 0:
            self.yara_tab.setColumnCount(2)
            self.yara_tab.setHorizontalHeaderLabels(["Rule", "Tags"])
            self.yara_tab.setRowCount(0)
            row = 0
            for match in self.analysis['yara']:
                self.yara_tab.insertRow(row)
                self.yara_tab.setItem(row, 0, QTableWidgetItem(match['rule']))
                self.yara_tab.setItem(row, 1, QTableWidgetItem(str(match['tags'])))
                row += 1
            self.yara_tab.resizeColumnsToContents()
        else:
            # Show empty state
            self.yara_tab.setColumnCount(1)
            self.yara_tab.setHorizontalHeaderLabels(["Status"])
            self.yara_tab.setRowCount(1)
            self.yara_tab.setItem(0, 0, QTableWidgetItem("No YARA rules matched"))

        # Enable AI button if strings exist
        self.ai_btn.setEnabled(bool(self.strings_tab.toPlainText()))

    def export_json(self):
        if not self.sample:
            return
        reporter = ReportGenerator()
        path = reporter.generate_json(self.sample, self.analysis)
        QMessageBox.information(self, "Export Success", f"JSON report saved to:\n{path}")

    def export_html(self):
        if not self.sample:
            return
        reporter = ReportGenerator()
        path = reporter.generate_html(self.sample, self.analysis)
        QMessageBox.information(self, "Export Success", f"HTML report saved to:\n{path}")

    def explain_strings(self):
        text = self.strings_tab.toPlainText()
        if not text:
            return
        
        snippet = text[:2000]
        
        self.ai_btn.setEnabled(False)
        self.ai_btn.setText("🤖 Analyzing...")
        
        self.ai_worker = AIWorker(snippet)
        self.ai_worker.finished.connect(self.on_ai_finished)
        self.ai_worker.start()

    def on_ai_finished(self, result):
        self.ai_btn.setEnabled(True)
        self.ai_btn.setText("🤖 AI Analysis")
        
        msg = QMessageBox(self)
        msg.setWindowTitle("AI Analysis Result")
        msg.setText(result)
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()
