from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QLabel,
    QLineEdit, QPushButton, QCheckBox, QSpinBox, QComboBox, QFormLayout,
    QMessageBox, QGroupBox
)
from PyQt6.QtCore import Qt

class SettingsDialog(QDialog):
    """Application settings dialog"""
    
    def __init__(self, config_manager, parent=None):
        super().__init__(parent)
        self.config = config_manager
        self.setWindowTitle("Rexa Settings")
        self.setMinimumWidth(600)
        self.setMinimumHeight(500)
        
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Tabs
        tabs = QTabWidget()
        
        # Sandbox tab
        tabs.addTab(self.create_sandbox_tab(), "🔬 Sandbox")
        
        # Threat Intel tab
        tabs.addTab(self.create_threat_intel_tab(), "🌐 Threat Intel")
        
        # Disassembly tab
        tabs.addTab(self.create_disassembly_tab(), "⚙️ Disassembly")
        
        # UI tab
        tabs.addTab(self.create_ui_tab(), "🎨 UI")
        
        layout.addWidget(tabs)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_settings)
        button_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
    
    def create_sandbox_tab(self):
        """Create sandbox settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Cuckoo
        cuckoo_group = QGroupBox("Cuckoo Sandbox")
        cuckoo_layout = QFormLayout(cuckoo_group)
        
        self.cuckoo_enabled = QCheckBox()
        cuckoo_layout.addRow("Enabled:", self.cuckoo_enabled)
        
        self.cuckoo_url = QLineEdit()
        self.cuckoo_url.setPlaceholderText("http://localhost:8090")
        cuckoo_layout.addRow("URL:", self.cuckoo_url)
        
        self.cuckoo_timeout = QSpinBox()
        self.cuckoo_timeout.setRange(60, 3600)
        self.cuckoo_timeout.setValue(300)
        self.cuckoo_timeout.setSuffix(" seconds")
        cuckoo_layout.addRow("Timeout:", self.cuckoo_timeout)
        
        layout.addWidget(cuckoo_group)
        
        # CAPE
        cape_group = QGroupBox("CAPE Sandbox")
        cape_layout = QFormLayout(cape_group)
        
        self.cape_enabled = QCheckBox()
        cape_layout.addRow("Enabled:", self.cape_enabled)
        
        self.cape_url = QLineEdit()
        self.cape_url.setPlaceholderText("http://localhost:8000")
        cape_layout.addRow("URL:", self.cape_url)
        
        self.cape_timeout = QSpinBox()
        self.cape_timeout.setRange(60, 3600)
        self.cape_timeout.setValue(300)
        self.cape_timeout.setSuffix(" seconds")
        cape_layout.addRow("Timeout:", self.cape_timeout)
        
        layout.addWidget(cape_group)
        
        layout.addStretch()
        
        return widget
    
    def create_threat_intel_tab(self):
        """Create threat intel settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # VirusTotal
        vt_group = QGroupBox("VirusTotal")
        vt_layout = QFormLayout(vt_group)
        
        self.vt_enabled = QCheckBox()
        vt_layout.addRow("Enabled:", self.vt_enabled)
        
        self.vt_api_key = QLineEdit()
        self.vt_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.vt_api_key.setPlaceholderText("Enter API key...")
        vt_layout.addRow("API Key:", self.vt_api_key)
        
        self.vt_rate_limit = QSpinBox()
        self.vt_rate_limit.setRange(1, 100)
        self.vt_rate_limit.setValue(4)
        self.vt_rate_limit.setSuffix(" requests/min")
        vt_layout.addRow("Rate Limit:", self.vt_rate_limit)
        
        layout.addWidget(vt_group)
        
        # AlienVault OTX
        otx_group = QGroupBox("AlienVault OTX")
        otx_layout = QFormLayout(otx_group)
        
        self.otx_enabled = QCheckBox()
        otx_layout.addRow("Enabled:", self.otx_enabled)
        
        self.otx_api_key = QLineEdit()
        self.otx_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.otx_api_key.setPlaceholderText("Enter API key...")
        otx_layout.addRow("API Key:", self.otx_api_key)
        
        layout.addWidget(otx_group)
        
        layout.addStretch()
        
        return widget
    
    def create_disassembly_tab(self):
        """Create disassembly settings tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.ghidra_path = QLineEdit()
        self.ghidra_path.setPlaceholderText("Path to Ghidra installation...")
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_ghidra)
        
        ghidra_layout = QHBoxLayout()
        ghidra_layout.addWidget(self.ghidra_path)
        ghidra_layout.addWidget(browse_btn)
        
        layout.addRow("Ghidra Path:", ghidra_layout)
        
        self.default_arch = QComboBox()
        self.default_arch.addItems(["x86_64", "x86", "arm", "arm64", "mips", "mips64"])
        layout.addRow("Default Architecture:", self.default_arch)
        
        self.auto_analyze = QCheckBox()
        self.auto_analyze.setChecked(True)
        layout.addRow("Auto-analyze on upload:", self.auto_analyze)
        
        return widget
    
    def create_ui_tab(self):
        """Create UI settings tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.theme = QComboBox()
        self.theme.addItems(["Dark", "Light"])
        layout.addRow("Theme:", self.theme)
        
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 16)
        self.font_size.setValue(10)
        layout.addRow("Font Size:", self.font_size)
        
        self.graph_layout = QComboBox()
        self.graph_layout.addItems(["Hierarchical", "Force-Directed", "Circular"])
        layout.addRow("Graph Layout:", self.graph_layout)
        
        self.auto_save_interval = QSpinBox()
        self.auto_save_interval.setRange(0, 3600)
        self.auto_save_interval.setValue(300)
        self.auto_save_interval.setSuffix(" seconds")
        layout.addRow("Auto-save Interval:", self.auto_save_interval)
        
        return widget
    
    def browse_ghidra(self):
        """Browse for Ghidra installation"""
        from PyQt6.QtWidgets import QFileDialog
        
        path = QFileDialog.getExistingDirectory(self, "Select Ghidra Installation")
        if path:
            self.ghidra_path.setText(path)
    
    def load_settings(self):
        """Load settings from config"""
        # Sandbox
        self.cuckoo_enabled.setChecked(self.config.get('sandbox.cuckoo.enabled', False))
        self.cuckoo_url.setText(self.config.get('sandbox.cuckoo.url', 'http://localhost:8090'))
        self.cuckoo_timeout.setValue(self.config.get('sandbox.cuckoo.timeout', 300))
        
        self.cape_enabled.setChecked(self.config.get('sandbox.cape.enabled', False))
        self.cape_url.setText(self.config.get('sandbox.cape.url', 'http://localhost:8000'))
        self.cape_timeout.setValue(self.config.get('sandbox.cape.timeout', 300))
        
        # Threat Intel
        self.vt_enabled.setChecked(self.config.get('threat_intel.virustotal.enabled', False))
        vt_key = self.config.get_api_key('virustotal')
        if vt_key:
            self.vt_api_key.setText(vt_key)
        self.vt_rate_limit.setValue(self.config.get('threat_intel.virustotal.rate_limit', 4))
        
        self.otx_enabled.setChecked(self.config.get('threat_intel.otx.enabled', False))
        otx_key = self.config.get_api_key('otx')
        if otx_key:
            self.otx_api_key.setText(otx_key)
        
        # Disassembly
        self.ghidra_path.setText(self.config.get('disassembly.ghidra_path', ''))
        arch = self.config.get('disassembly.default_arch', 'x86_64')
        index = self.default_arch.findText(arch)
        if index >= 0:
            self.default_arch.setCurrentIndex(index)
        self.auto_analyze.setChecked(self.config.get('disassembly.auto_analyze', True))
        
        # UI
        theme = self.config.get('ui.theme', 'dark')
        self.theme.setCurrentText(theme.capitalize())
        self.font_size.setValue(self.config.get('ui.font_size', 10))
        self.graph_layout.setCurrentText(self.config.get('ui.graph_layout', 'hierarchical').capitalize())
        self.auto_save_interval.setValue(self.config.get('ui.auto_save_interval', 300))
    
    def save_settings(self):
        """Save settings to config"""
        # Sandbox
        self.config.set('sandbox.cuckoo.enabled', self.cuckoo_enabled.isChecked())
        self.config.set('sandbox.cuckoo.url', self.cuckoo_url.text())
        self.config.set('sandbox.cuckoo.timeout', self.cuckoo_timeout.value())
        
        self.config.set('sandbox.cape.enabled', self.cape_enabled.isChecked())
        self.config.set('sandbox.cape.url', self.cape_url.text())
        self.config.set('sandbox.cape.timeout', self.cape_timeout.value())
        
        # Threat Intel
        self.config.set('threat_intel.virustotal.enabled', self.vt_enabled.isChecked())
        if self.vt_api_key.text():
            self.config.set_api_key('virustotal', self.vt_api_key.text())
        self.config.set('threat_intel.virustotal.rate_limit', self.vt_rate_limit.value())
        
        self.config.set('threat_intel.otx.enabled', self.otx_enabled.isChecked())
        if self.otx_api_key.text():
            self.config.set_api_key('otx', self.otx_api_key.text())
        
        # Disassembly
        self.config.set('disassembly.ghidra_path', self.ghidra_path.text())
        self.config.set('disassembly.default_arch', self.default_arch.currentText())
        self.config.set('disassembly.auto_analyze', self.auto_analyze.isChecked())
        
        # UI
        self.config.set('ui.theme', self.theme.currentText().lower())
        self.config.set('ui.font_size', self.font_size.value())
        self.config.set('ui.graph_layout', self.graph_layout.currentText().lower())
        self.config.set('ui.auto_save_interval', self.auto_save_interval.value())
        
        # Validate
        errors = self.config.validate()
        if errors:
            QMessageBox.warning(self, "Validation Errors", "\n".join(errors))
        else:
            QMessageBox.information(self, "Success", "Settings saved successfully!")
            self.accept()
