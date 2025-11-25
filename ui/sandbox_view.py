from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QProgressBar, QMessageBox, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont
import json

class SandboxWorker(QThread):
    """Background worker for sandbox submission"""
    
    progress_update = pyqtSignal(str, int)
    finished = pyqtSignal(dict)
    
    def __init__(self, provider, file_path):
        super().__init__()
        self.provider = provider
        self.file_path = file_path
    
    def run(self):
        try:
            # Submit sample
            self.progress_update.emit("Submitting sample...", 10)
            task_id = self.provider.submit_sample(self.file_path)
            
            if not task_id:
                self.finished.emit({'error': 'Failed to submit sample'})
                return
            
            # Wait for completion
            self.progress_update.emit(f"Analysis in progress (Task: {task_id})...", 50)
            success = self.provider.wait_for_completion(task_id)
            
            if not success:
                self.finished.emit({'error': 'Analysis failed'})
                return
            
            # Get report
            self.progress_update.emit("Retrieving report...", 90)
            report = self.provider.get_report(task_id)
            
            self.progress_update.emit("Complete!", 100)
            self.finished.emit(report)
            
        except Exception as e:
            self.finished.emit({'error': str(e)})

class SandboxView(QWidget):
    """Comprehensive sandbox results viewer"""
    
    back_to_analysis = pyqtSignal()
    
    def __init__(self, sample_id, db_manager):
        super().__init__()
        self.sample_id = sample_id
        self.db = db_manager
        self.report = None
        
        self.init_ui()
        self.load_sandbox_runs()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        back_btn = QPushButton("← Back")
        back_btn.clicked.connect(self.back_to_analysis.emit)
        toolbar.addWidget(back_btn)
        
        toolbar.addStretch()
        
        submit_cuckoo_btn = QPushButton("Submit to Cuckoo")
        submit_cuckoo_btn.clicked.connect(lambda: self.submit_to_sandbox('cuckoo'))
        toolbar.addWidget(submit_cuckoo_btn)
        
        submit_cape_btn = QPushButton("Submit to CAPE")
        submit_cape_btn.clicked.connect(lambda: self.submit_to_sandbox('cape'))
        toolbar.addWidget(submit_cape_btn)
        
        layout.addLayout(toolbar)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #888;")
        layout.addWidget(self.status_label)
        
        # Tabs
        self.tabs = QTabWidget()
        
        # Overview tab
        self.overview_tab = self.create_overview_tab()
        self.tabs.addTab(self.overview_tab, "📊 Overview")
        
        # Behavior tab
        self.behavior_tab = self.create_behavior_tab()
        self.tabs.addTab(self.behavior_tab, "🔍 Behavior")
        
        # Network tab
        self.network_tab = self.create_network_tab()
        self.tabs.addTab(self.network_tab, "🌐 Network")
        
        # Signatures tab
        self.signatures_tab = self.create_signatures_tab()
        self.tabs.addTab(self.signatures_tab, "🎯 Signatures")
        
        layout.addWidget(self.tabs)
    
    def create_overview_tab(self):
        """Create overview tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.verdict_label = QLabel("Verdict: Unknown")
        self.verdict_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(self.verdict_label)
        
        self.score_label = QLabel("Score: N/A")
        layout.addWidget(self.score_label)
        
        self.metadata_text = QTextEdit()
        self.metadata_text.setReadOnly(True)
        self.metadata_text.setMaximumHeight(200)
        layout.addWidget(self.metadata_text)
        
        layout.addStretch()
        
        return widget
    
    def create_behavior_tab(self):
        """Create behavior tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        layout.addWidget(QLabel("Process Tree:"))
        
        self.process_tree = QTreeWidget()
        self.process_tree.setHeaderLabels(["PID", "Process Name", "Command Line"])
        layout.addWidget(self.process_tree)
        
        return widget
    
    def create_network_tab(self):
        """Create network tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # DNS queries
        layout.addWidget(QLabel("DNS Queries:"))
        self.dns_table = QTableWidget()
        self.dns_table.setColumnCount(2)
        self.dns_table.setHorizontalHeaderLabels(["Domain", "IP"])
        self.dns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.dns_table)
        
        # HTTP requests
        layout.addWidget(QLabel("HTTP Requests:"))
        self.http_table = QTableWidget()
        self.http_table.setColumnCount(3)
        self.http_table.setHorizontalHeaderLabels(["Method", "URL", "Status"])
        self.http_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.http_table)
        
        return widget
    
    def create_signatures_tab(self):
        """Create signatures tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.signatures_table = QTableWidget()
        self.signatures_table.setColumnCount(3)
        self.signatures_table.setHorizontalHeaderLabels(["Name", "Severity", "Description"])
        self.signatures_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.signatures_table)
        
        return widget
    
    def load_sandbox_runs(self):
        """Load existing sandbox runs"""
        runs = self.db.get_sample_sandbox_runs(self.sample_id)
        
        if runs:
            # Load most recent completed run
            for run in reversed(runs):
                if run.status == 'completed':
                    self.load_run_report(run)
                    break
    
    def load_run_report(self, run):
        """Load sandbox run report"""
        # Get report from database (stored in SandboxResult)
        # For now, show basic info
        self.status_label.setText(f"Loaded {run.provider} analysis from {run.submitted_at}")
        
        if run.verdict:
            self.verdict_label.setText(f"Verdict: {run.verdict.upper()}")
            
            # Color code verdict
            if run.verdict == 'malicious':
                self.verdict_label.setStyleSheet("color: #ff4444;")
            elif run.verdict == 'suspicious':
                self.verdict_label.setStyleSheet("color: #ffaa00;")
            else:
                self.verdict_label.setStyleSheet("color: #44ff44;")
        
        if run.score is not None:
            self.score_label.setText(f"Score: {run.score}/10")
    
    def submit_to_sandbox(self, provider_type):
        """Submit sample to sandbox"""
        # Get sample
        sample = self.db.get_sample(self.sample_id)
        if not sample:
            QMessageBox.warning(self, "Error", "Sample not found")
            return
        
        # Create provider
        try:
            if provider_type == 'cuckoo':
                from core.sandbox.cuckoo_provider import CuckooProvider
                from core.config import ConfigManager
                config = ConfigManager()
                url = config.get('sandbox.cuckoo.url', 'http://localhost:8090')
                provider = CuckooProvider(url)
            elif provider_type == 'cape':
                from core.sandbox.cape_provider import CAPEProvider
                from core.config import ConfigManager
                config = ConfigManager()
                url = config.get('sandbox.cape.url', 'http://localhost:8000')
                provider = CAPEProvider(url)
            else:
                return
            
            # Start worker
            self.worker = SandboxWorker(provider, sample.file_path)
            self.worker.progress_update.connect(self.on_progress_update)
            self.worker.finished.connect(self.on_sandbox_finished)
            
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            self.worker.start()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to submit: {e}")
    
    def on_progress_update(self, message, progress):
        """Handle progress update"""
        self.status_label.setText(message)
        self.progress_bar.setValue(progress)
    
    def on_sandbox_finished(self, report):
        """Handle sandbox completion"""
        self.progress_bar.setVisible(False)
        
        if 'error' in report:
            QMessageBox.critical(self, "Error", report['error'])
            return
        
        # Save to database
        # (Implementation would save full report)
        
        # Display report
        self.display_report(report)
        
        QMessageBox.information(self, "Success", "Sandbox analysis complete!")
    
    def display_report(self, report):
        """Display sandbox report"""
        self.report = report
        
        # Update overview
        verdict = report.get('verdict', 'unknown')
        self.verdict_label.setText(f"Verdict: {verdict.upper()}")
        
        if verdict == 'malicious':
            self.verdict_label.setStyleSheet("color: #ff4444;")
        elif verdict == 'suspicious':
            self.verdict_label.setStyleSheet("color: #ffaa00;")
        else:
            self.verdict_label.setStyleSheet("color: #44ff44;")
        
        score = report.get('score', 0)
        self.score_label.setText(f"Score: {score}/10")
        
        # Metadata
        metadata = report.get('metadata', {})
        metadata_text = json.dumps(metadata, indent=2)
        self.metadata_text.setPlainText(metadata_text)
        
        # Process tree
        self.process_tree.clear()
        processes = report.get('behavior', {}).get('processes', [])
        for proc in processes:
            item = QTreeWidgetItem([
                str(proc.get('pid', '')),
                proc.get('name', ''),
                proc.get('command_line', '')
            ])
            self.process_tree.addTopLevelItem(item)
        
        # Network
        network = report.get('network', {})
        
        # DNS
        self.dns_table.setRowCount(0)
        for dns in network.get('dns', []):
            row = self.dns_table.rowCount()
            self.dns_table.insertRow(row)
            self.dns_table.setItem(row, 0, QTableWidgetItem(dns.get('request', '')))
            self.dns_table.setItem(row, 1, QTableWidgetItem(str(dns.get('answers', []))))
        
        # HTTP
        self.http_table.setRowCount(0)
        for http in network.get('http', []):
            row = self.http_table.rowCount()
            self.http_table.insertRow(row)
            self.http_table.setItem(row, 0, QTableWidgetItem(http.get('method', '')))
            self.http_table.setItem(row, 1, QTableWidgetItem(http.get('uri', '')))
            self.http_table.setItem(row, 2, QTableWidgetItem(str(http.get('status', ''))))
        
        # Signatures
        self.signatures_table.setRowCount(0)
        for sig in report.get('signatures', []):
            row = self.signatures_table.rowCount()
            self.signatures_table.insertRow(row)
            self.signatures_table.setItem(row, 0, QTableWidgetItem(sig.get('name', '')))
            self.signatures_table.setItem(row, 1, QTableWidgetItem(str(sig.get('severity', ''))))
            self.signatures_table.setItem(row, 2, QTableWidgetItem(sig.get('description', '')))
