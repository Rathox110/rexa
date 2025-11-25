from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QListWidget, QLabel, QHBoxLayout, 
    QFileDialog, QProgressBar, QMessageBox, QFrame, QListWidgetItem
)
from PyQt6.QtCore import pyqtSignal, QThread, Qt
from PyQt6.QtGui import QFont
from core.analysis.static import StaticAnalyzer
import os

class AnalysisWorker(QThread):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(str)
    
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        self.progress.emit("Analyzing file...")
        analyzer = StaticAnalyzer(self.file_path)
        results = analyzer.run()
        self.finished.emit(results)

class ProjectView(QWidget):
    sample_selected = pyqtSignal(int) # sample_id
    back_to_dashboard = pyqtSignal()

    def __init__(self, project_id, db_manager):
        super().__init__()
        self.project_id = project_id
        self.db = db_manager
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)
        self.init_ui()

    def init_ui(self):
        # Header
        header_container = QFrame()
        header_layout = QVBoxLayout(header_container)
        
        # Get project details
        projects = self.db.get_projects()
        project = next((p for p in projects if p.id == self.project_id), None)
        project_name = project.name if project else f"Project {self.project_id}"
        
        # Back button
        back_btn = QPushButton("← Back to Dashboard")
        back_btn.clicked.connect(self.back_to_dashboard.emit)
        back_btn.setMaximumWidth(200)
        header_layout.addWidget(back_btn)
        
        # Title
        self.title = QLabel(f"📁 {project_name}")
        self.title.setProperty("class", "header")
        self.title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header_layout.addWidget(self.title)
        
        # Sample count
        samples = self.db.get_project_samples(self.project_id)
        self.sample_count = QLabel(f"{len(samples)} samples")
        self.sample_count.setStyleSheet("color: #b0b0b0; font-size: 11pt;")
        header_layout.addWidget(self.sample_count)
        
        self.layout.addWidget(header_container)
        
        # Samples Section
        samples_header = QLabel("📄 Samples")
        samples_header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.layout.addWidget(samples_header)
        
        # Sample List
        self.sample_list = QListWidget()
        self.sample_list.setStyleSheet("""
            QListWidget {
                background-color: #252526;
                border: 1px solid #3e3e3e;
                border-radius: 8px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 12px;
                border-radius: 4px;
                margin: 3px;
                background-color: #2d2d2d;
            }
            QListWidget::item:selected {
                background-color: #007acc;
                color: #ffffff;
            }
            QListWidget::item:hover {
                background-color: #3e3e3e;
            }
        """)
        self.sample_list.itemDoubleClicked.connect(self.on_sample_double_click)
        self.layout.addWidget(self.sample_list)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        self.add_btn = QPushButton("➕ Add Sample")
        self.add_btn.setProperty("class", "primary")
        self.add_btn.setMinimumHeight(40)
        self.add_btn.clicked.connect(self.add_sample)
        btn_layout.addWidget(self.add_btn)
        
        self.open_btn = QPushButton("📊 Analyze Selected")
        self.open_btn.setMinimumHeight(40)
        self.open_btn.clicked.connect(self.analyze_selected)
        self.open_btn.setEnabled(False)
        btn_layout.addWidget(self.open_btn)
        
        self.layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3e3e3e;
                border-radius: 4px;
                text-align: center;
                background-color: #252526;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #007acc;
                border-radius: 3px;
            }
        """)
        self.layout.addWidget(self.progress)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #b0b0b0; font-style: italic;")
        self.layout.addWidget(self.status_label)
        
        # Connect selection changed
        self.sample_list.itemSelectionChanged.connect(self.on_selection_changed)
        
        self.refresh_samples()

    def refresh_samples(self):
        self.sample_list.clear()
        samples = self.db.get_project_samples(self.project_id)
        
        # Update count
        self.sample_count.setText(f"{len(samples)} samples")
        
        for s in samples:
            item_text = f"📄 {s.filename}\n   MD5: {s.md5} • Added {s.created_at.strftime('%Y-%m-%d %H:%M')}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, s.id)
            self.sample_list.addItem(item)

    def on_selection_changed(self):
        self.open_btn.setEnabled(len(self.sample_list.selectedItems()) > 0)

    def analyze_selected(self):
        items = self.sample_list.selectedItems()
        if items:
            sid = items[0].data(Qt.ItemDataRole.UserRole)
            self.sample_selected.emit(sid)

    def add_sample(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Sample", 
            "", 
            "Executable Files (*.exe *.dll *.sys);;All Files (*.*)"
        )
        if file_path:
            self.progress.setVisible(True)
            self.progress.setRange(0, 0) # Indeterminate
            self.status_label.setText("Analyzing sample...")
            self.add_btn.setEnabled(False)
            
            self.worker = AnalysisWorker(file_path)
            self.worker.finished.connect(lambda res: self.on_analysis_complete(file_path, res))
            self.worker.progress.connect(self.status_label.setText)
            self.worker.start()

    def on_analysis_complete(self, file_path, results):
        self.progress.setVisible(False)
        self.status_label.setText("")
        self.add_btn.setEnabled(True)
        
        filename = os.path.basename(file_path)
        md5 = results.get('md5', '')
        sha256 = results.get('sha256', '')
        
        self.db.add_sample(self.project_id, filename, file_path, md5, sha256, results)
        self.refresh_samples()
        
        QMessageBox.information(
            self, 
            "Success", 
            f"✅ Sample '{filename}' analyzed and added successfully!"
        )

    def on_sample_double_click(self, item):
        sid = item.data(Qt.ItemDataRole.UserRole)
        self.sample_selected.emit(sid)
