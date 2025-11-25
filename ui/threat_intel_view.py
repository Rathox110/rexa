from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit, QProgressBar, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont
import json

class ThreatIntelWorker(QThread):
    """Background worker for threat intel enrichment"""
    
    progress_update = pyqtSignal(str)
    finished = pyqtSignal(dict)
    
    def __init__(self, sample_hash, config):
        super().__init__()
        self.sample_hash = sample_hash
        self.config = config
    
    def run(self):
        results = {}
        
        try:
            # VirusTotal
            vt_enabled = self.config.get('threat_intel.virustotal.enabled', False)
            if vt_enabled:
                self.progress_update.emit("Querying VirusTotal...")
                from integrations.virustotal import VirusTotalClient
                
                api_key = self.config.get_api_key('virustotal')
                if api_key:
                    vt = VirusTotalClient(api_key)
                    results['virustotal'] = vt.get_file_report(self.sample_hash)
            
            # OTX
            otx_enabled = self.config.get('threat_intel.otx.enabled', False)
            if otx_enabled:
                self.progress_update.emit("Querying AlienVault OTX...")
                from integrations.otx import OTXClient
                
                api_key = self.config.get_api_key('otx')
                if api_key:
                    otx = OTXClient(api_key)
                    results['otx'] = otx.get_file_reputation(self.sample_hash)
            
            self.progress_update.emit("Complete!")
            self.finished.emit(results)
            
        except Exception as e:
            self.finished.emit({'error': str(e)})

class ThreatIntelView(QWidget):
    """Aggregated threat intelligence dashboard"""
    
    back_to_analysis = pyqtSignal()
    
    def __init__(self, sample_id, db_manager):
        super().__init__()
        self.sample_id = sample_id
        self.db = db_manager
        self.intel_data = {}
        
        self.init_ui()
        self.load_threat_intel()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        back_btn = QPushButton("← Back")
        back_btn.clicked.connect(self.back_to_analysis.emit)
        toolbar.addWidget(back_btn)
        
        toolbar.addStretch()
        
        enrich_btn = QPushButton("🔄 Enrich with Threat Intel")
        enrich_btn.clicked.connect(self.enrich_sample)
        toolbar.addWidget(enrich_btn)
        
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
        
        # VirusTotal tab
        self.vt_tab = self.create_vt_tab()
        self.tabs.addTab(self.vt_tab, "🦠 VirusTotal")
        
        # OTX tab
        self.otx_tab = self.create_otx_tab()
        self.tabs.addTab(self.otx_tab, "👁️ AlienVault OTX")
        
        # Reputation tab
        self.reputation_tab = self.create_reputation_tab()
        self.tabs.addTab(self.reputation_tab, "📊 Reputation")
        
        layout.addWidget(self.tabs)
    
    def create_vt_tab(self):
        """Create VirusTotal tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.vt_detection_label = QLabel("Detection Ratio: N/A")
        self.vt_detection_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(self.vt_detection_label)
        
        layout.addWidget(QLabel("Vendor Results:"))
        
        self.vt_table = QTableWidget()
        self.vt_table.setColumnCount(3)
        self.vt_table.setHorizontalHeaderLabels(["Vendor", "Result", "Category"])
        self.vt_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.vt_table)
        
        return widget
    
    def create_otx_tab(self):
        """Create OTX tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.otx_pulse_label = QLabel("Pulses: 0")
        self.otx_pulse_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(self.otx_pulse_label)
        
        layout.addWidget(QLabel("Threat Pulses:"))
        
        self.otx_pulses_text = QTextEdit()
        self.otx_pulses_text.setReadOnly(True)
        layout.addWidget(self.otx_pulses_text)
        
        return widget
    
    def create_reputation_tab(self):
        """Create reputation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.reputation_score_label = QLabel("Aggregate Score: N/A")
        self.reputation_score_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(self.reputation_score_label)
        
        self.reputation_verdict_label = QLabel("Verdict: Unknown")
        layout.addWidget(self.reputation_verdict_label)
        
        layout.addWidget(QLabel("Source Breakdown:"))
        
        self.reputation_text = QTextEdit()
        self.reputation_text.setReadOnly(True)
        layout.addWidget(self.reputation_text)
        
        return widget
    
    def load_threat_intel(self):
        """Load existing threat intel from database"""
        intel_records = self.db.get_sample_threat_intel(self.sample_id)
        
        for record in intel_records:
            try:
                data = json.loads(record.data_json)
                self.intel_data[record.source] = data
            except:
                pass
        
        if self.intel_data:
            self.display_threat_intel()
    
    def enrich_sample(self):
        """Enrich sample with threat intelligence"""
        # Get sample
        sample = self.db.get_sample(self.sample_id)
        if not sample:
            return
        
        # Start worker
        from core.config import ConfigManager
        config = ConfigManager()
        
        self.worker = ThreatIntelWorker(sample.sha256, config)
        self.worker.progress_update.connect(self.on_progress_update)
        self.worker.finished.connect(self.on_enrichment_finished)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        
        self.worker.start()
    
    def on_progress_update(self, message):
        """Handle progress update"""
        self.status_label.setText(message)
    
    def on_enrichment_finished(self, results):
        """Handle enrichment completion"""
        self.progress_bar.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"Error: {results['error']}")
            return
        
        # Save to database
        for source, data in results.items():
            if source != 'error':
                self.db.add_threat_intel(
                    self.sample_id,
                    source,
                    json.dumps(data)
                )
        
        # Update display
        self.intel_data = results
        self.display_threat_intel()
        
        self.status_label.setText("Enrichment complete!")
    
    def display_threat_intel(self):
        """Display threat intelligence data"""
        # VirusTotal
        if 'virustotal' in self.intel_data:
            vt_data = self.intel_data['virustotal']
            
            if vt_data.get('found'):
                ratio = vt_data.get('detection_ratio', 'N/A')
                self.vt_detection_label.setText(f"Detection Ratio: {ratio}")
                
                # Vendor results
                self.vt_table.setRowCount(0)
                for vendor in vt_data.get('vendor_results', [])[:50]:  # Limit to 50
                    row = self.vt_table.rowCount()
                    self.vt_table.insertRow(row)
                    self.vt_table.setItem(row, 0, QTableWidgetItem(vendor.get('vendor', '')))
                    self.vt_table.setItem(row, 1, QTableWidgetItem(vendor.get('result', '')))
                    self.vt_table.setItem(row, 2, QTableWidgetItem(vendor.get('category', '')))
        
        # OTX
        if 'otx' in self.intel_data:
            otx_data = self.intel_data['otx']
            
            pulse_count = otx_data.get('pulse_count', 0)
            self.otx_pulse_label.setText(f"Pulses: {pulse_count}")
            
            # Pulses
            pulses_text = ""
            for pulse in otx_data.get('pulses', []):
                pulses_text += f"**{pulse.get('name', 'Unknown')}**\n"
                pulses_text += f"Author: {pulse.get('author', 'Unknown')}\n"
                pulses_text += f"Description: {pulse.get('description', 'N/A')}\n"
                pulses_text += f"Tags: {', '.join(pulse.get('tags', []))}\n\n"
            
            self.otx_pulses_text.setPlainText(pulses_text)
        
        # Reputation
        self.calculate_reputation()
    
    def calculate_reputation(self):
        """Calculate aggregate reputation score"""
        scores = []
        
        # VT score
        if 'virustotal' in self.intel_data:
            vt_data = self.intel_data['virustotal']
            if vt_data.get('found'):
                detections = vt_data.get('detections', 0)
                total = vt_data.get('total_engines', 1)
                vt_score = (detections / total) * 100 if total > 0 else 0
                scores.append(vt_score)
        
        # OTX score
        if 'otx' in self.intel_data:
            otx_data = self.intel_data['otx']
            otx_score = otx_data.get('reputation_score', 0)
            scores.append(otx_score)
        
        # Calculate average
        if scores:
            avg_score = sum(scores) / len(scores)
            self.reputation_score_label.setText(f"Aggregate Score: {avg_score:.1f}/100")
            
            # Verdict
            if avg_score >= 70:
                verdict = "MALICIOUS"
                color = "#ff4444"
            elif avg_score >= 40:
                verdict = "SUSPICIOUS"
                color = "#ffaa00"
            else:
                verdict = "SAFE"
                color = "#44ff44"
            
            self.reputation_verdict_label.setText(f"Verdict: {verdict}")
            self.reputation_verdict_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            
            # Breakdown
            breakdown = f"VirusTotal: {scores[0]:.1f}/100\n" if len(scores) > 0 else ""
            breakdown += f"AlienVault OTX: {scores[1]:.1f}/100\n" if len(scores) > 1 else ""
            self.reputation_text.setPlainText(breakdown)
