import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QToolBar, QStatusBar, QLabel, QMenu, QMenuBar
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QFont
from core.database import DatabaseManager
from core.config import ConfigManager
from core.auth.user_manager import UserManager
from ui.dashboard import Dashboard
from ui.project_view import ProjectView
from ui.analysis_view import AnalysisView
from ui.disassembly_view import DisassemblyView
from ui.sandbox_view import SandboxView
from ui.graph_view import GraphView
from ui.threat_intel_view import ThreatIntelView
from ui.settings_dialog import SettingsDialog
from ui.login_dialog import LoginDialog
from ui.theme import DARK_THEME

# Ensure the project root is in sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Rexa - Reverse Engineering Command Center")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize Core
        self.db = DatabaseManager()
        self.config = ConfigManager()
        self.user_manager = UserManager(self.db)
        
        # Show login dialog
        self.show_login()

    
    def show_login(self):
        """Show login dialog"""
        login_dialog = LoginDialog(self.user_manager, self)
        if login_dialog.exec():
            # User logged in or chose guest mode
            self.init_ui()
        else:
            # User cancelled login
            sys.exit(0)
    
    def init_ui(self):
        """Initialize UI after login"""
        # Setup UI
        self.setup_menubar()
        self.setup_toolbar()
        self.setup_statusbar()
        
        # Central Widget Stack
        self.central_stack = QStackedWidget()
        self.setCentralWidget(self.central_stack)

        # Dashboard
        self.dashboard = Dashboard(self.db)
        self.dashboard.project_selected.connect(self.open_project)
        self.central_stack.addWidget(self.dashboard)
        
        # Update breadcrumbs
        self.update_breadcrumbs("Dashboard")
    
    def setup_menubar(self):
        """Setup menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        settings_action = QAction("⚙️ Settings", self)
        settings_action.triggered.connect(self.show_settings)
        file_menu.addAction(settings_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        dashboard_action = QAction("🏠 Dashboard", self)
        dashboard_action.triggered.connect(self.show_dashboard)
        view_menu.addAction(dashboard_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = QAction("About Rexa", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def setup_toolbar(self):
        self.toolbar = QToolBar("Navigation")
        self.toolbar.setMovable(False)
        self.toolbar.setStyleSheet("""
            QToolBar {
                background-color: #2d2d2d;
                border-bottom: 2px solid #007acc;
                spacing: 10px;
                padding: 8px;
            }
        """)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.toolbar)
        
        # Breadcrumbs label
        self.breadcrumbs = QLabel("🏠 Dashboard")
        self.breadcrumbs.setFont(QFont("Segoe UI", 11))
        self.breadcrumbs.setStyleSheet("color: #d4d4d4; padding: 5px;")
        self.toolbar.addWidget(self.breadcrumbs)
        
        self.toolbar.addSeparator()
        
        # Home action
        home_action = QAction("🏠 Home", self)
        home_action.triggered.connect(self.show_dashboard)
        self.toolbar.addAction(home_action)

    def setup_statusbar(self):
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.setStyleSheet("""
            QStatusBar {
                background-color: #007acc;
                color: #ffffff;
                font-weight: bold;
                padding: 5px;
            }
        """)
        self.statusbar.showMessage("Ready")

    def update_breadcrumbs(self, path):
        self.breadcrumbs.setText(f"🏠 {path}")

    def update_status(self, message):
        self.statusbar.showMessage(message)

    def open_project(self, project_id):
        # Get project name for breadcrumbs
        projects = self.db.get_projects()
        project_name = next((p.name for p in projects if p.id == project_id), f"Project {project_id}")
        
        self.project_view = ProjectView(project_id, self.db)
        self.project_view.back_to_dashboard.connect(self.show_dashboard)
        self.project_view.sample_selected.connect(self.open_sample)
        self.central_stack.addWidget(self.project_view)
        self.central_stack.setCurrentWidget(self.project_view)
        
        self.update_breadcrumbs(f"Dashboard > 📁 {project_name}")
        self.update_status(f"Viewing project: {project_name}")

    def show_dashboard(self):
        self.central_stack.setCurrentWidget(self.dashboard)
        self.dashboard.refresh_projects()
        self.update_breadcrumbs("Dashboard")
        self.update_status("Ready")

    def open_sample(self, sample_id):
        # Get sample name for breadcrumbs
        sample = self.db.get_sample(sample_id)
        if sample:
            self.current_sample_id = sample_id
            self.analysis_view = AnalysisView(sample_id, self.db)
            self.analysis_view.back_to_project.connect(self.show_project_view)
            
            # Connect to new views
            self.analysis_view.open_disassembly.connect(self.open_disassembly)
            self.analysis_view.open_sandbox.connect(self.open_sandbox)
            self.analysis_view.open_graph.connect(self.open_graph)
            self.analysis_view.open_threat_intel.connect(self.open_threat_intel)
            
            self.central_stack.addWidget(self.analysis_view)
            self.central_stack.setCurrentWidget(self.analysis_view)
            
            # Get project name
            projects = self.db.get_projects()
            project_name = next((p.name for p in projects if p.id == sample.project_id), "Project")
            
            self.update_breadcrumbs(f"Dashboard > 📁 {project_name} > 📄 {sample.filename}")
            self.update_status(f"Analyzing: {sample.filename}")
    
    def open_disassembly(self):
        """Open disassembly view"""
        if hasattr(self, 'current_sample_id'):
            disasm_view = DisassemblyView(self.current_sample_id, self.db)
            disasm_view.back_to_analysis.connect(self.show_analysis_view)
            self.central_stack.addWidget(disasm_view)
            self.central_stack.setCurrentWidget(disasm_view)
            self.update_status("Viewing disassembly")
    
    def open_sandbox(self):
        """Open sandbox view"""
        if hasattr(self, 'current_sample_id'):
            sandbox_view = SandboxView(self.current_sample_id, self.db)
            sandbox_view.back_to_analysis.connect(self.show_analysis_view)
            self.central_stack.addWidget(sandbox_view)
            self.central_stack.setCurrentWidget(sandbox_view)
            self.update_status("Viewing sandbox results")
    
    def open_graph(self):
        """Open graph view"""
        if hasattr(self, 'current_sample_id'):
            graph_view = GraphView(self.current_sample_id, self.db)
            graph_view.back_to_analysis.connect(self.show_analysis_view)
            self.central_stack.addWidget(graph_view)
            self.central_stack.setCurrentWidget(graph_view)
            self.update_status("Viewing graphs")
    
    def open_threat_intel(self):
        """Open threat intelligence view"""
        if hasattr(self, 'current_sample_id'):
            intel_view = ThreatIntelView(self.current_sample_id, self.db)
            intel_view.back_to_analysis.connect(self.show_analysis_view)
            self.central_stack.addWidget(intel_view)
            self.central_stack.setCurrentWidget(intel_view)
            self.update_status("Viewing threat intelligence")
    
    def show_analysis_view(self):
        """Return to analysis view"""
        if hasattr(self, 'analysis_view'):
            self.central_stack.setCurrentWidget(self.analysis_view)
            self.update_status("Viewing analysis")

    def show_project_view(self):
        if hasattr(self, 'project_view'):
            self.central_stack.setCurrentWidget(self.project_view)
            self.project_view.refresh_samples()
            
            # Update breadcrumbs
            projects = self.db.get_projects()
            if hasattr(self.project_view, 'project_id'):
                project_name = next((p.name for p in projects if p.id == self.project_view.project_id), "Project")
                self.update_breadcrumbs(f"Dashboard > 📁 {project_name}")
                self.update_status(f"Viewing project: {project_name}")
    
    def show_settings(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self.config, self)
        dialog.exec()
    
    def show_about(self):
        """Show about dialog"""
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.about(
            self,
            "About Rexa",
            "<h2>Rexa - Reverse Engineering Command Center</h2>"
            "<p>Version 2.0</p>"
            "<p>Advanced malware analysis platform with:</p>"
            "<ul>"
            "<li>Dynamic analysis (Cuckoo/CAPE sandbox)</li>"
            "<li>Disassembly & decompilation (Capstone/Ghidra)</li>"
            "<li>Graph visualization (Call graphs, CFG)</li>"
            "<li>Threat intelligence (VirusTotal, OTX)</li>"
            "<li>Collaborative features</li>"
            "</ul>"
        )

def main():
    app = QApplication(sys.argv)
    
    # Apply Dark Theme
    app.setStyleSheet(DARK_THEME)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
