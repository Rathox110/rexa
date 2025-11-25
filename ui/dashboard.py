from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QListWidget, QLabel, QHBoxLayout, 
    QInputDialog, QMessageBox, QFrame, QGridLayout, QListWidgetItem
)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont

class Dashboard(QWidget):
    project_selected = pyqtSignal(int)  # Signal emitting project_id

    def __init__(self, db_manager):
        super().__init__()
        self.db = db_manager
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)
        self.init_ui()

    def init_ui(self):
        # Header Section
        header_container = QFrame()
        header_layout = QVBoxLayout(header_container)
        
        # Main Title
        title = QLabel("🔍 Rexa")
        title.setProperty("class", "header")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        header_layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Reverse Engineering Command Center")
        subtitle.setProperty("class", "subheader")
        subtitle.setStyleSheet("color: #b0b0b0; font-size: 12pt;")
        header_layout.addWidget(subtitle)
        
        self.layout.addWidget(header_container)
        
        # Stats Section
        self.stats_container = QFrame()
        self.stats_container.setStyleSheet("""
            QFrame {
                background-color: #252526;
                border: 1px solid #3e3e3e;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        stats_layout = QGridLayout(self.stats_container)
        
        self.total_projects_label = QLabel("0")
        self.total_projects_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        self.total_projects_label.setStyleSheet("color: #007acc;")
        self.total_projects_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        projects_text = QLabel("Total Projects")
        projects_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        projects_text.setStyleSheet("color: #b0b0b0;")
        
        self.total_samples_label = QLabel("0")
        self.total_samples_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        self.total_samples_label.setStyleSheet("color: #4ec9b0;")
        self.total_samples_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        samples_text = QLabel("Total Samples")
        samples_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        samples_text.setStyleSheet("color: #b0b0b0;")
        
        stats_layout.addWidget(self.total_projects_label, 0, 0)
        stats_layout.addWidget(projects_text, 1, 0)
        stats_layout.addWidget(self.total_samples_label, 0, 1)
        stats_layout.addWidget(samples_text, 1, 1)
        
        self.layout.addWidget(self.stats_container)
        
        # Projects Section Header
        projects_header = QHBoxLayout()
        projects_label = QLabel("📁 Recent Projects")
        projects_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        projects_header.addWidget(projects_label)
        projects_header.addStretch()
        self.layout.addLayout(projects_header)
        
        # Welcome/Empty State
        self.welcome_widget = QFrame()
        self.welcome_widget.setStyleSheet("""
            QFrame {
                background-color: #252526;
                border: 2px dashed #3e3e3e;
                border-radius: 8px;
                padding: 40px;
            }
        """)
        welcome_layout = QVBoxLayout(self.welcome_widget)
        
        welcome_icon = QLabel("🚀")
        welcome_icon.setFont(QFont("Segoe UI", 48))
        welcome_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_layout.addWidget(welcome_icon)
        
        welcome_title = QLabel("Welcome to Rexa!")
        welcome_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        welcome_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_layout.addWidget(welcome_title)
        
        welcome_text = QLabel("Get started by creating your first project.\nThen add samples to analyze malware and binaries.")
        welcome_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_text.setStyleSheet("color: #b0b0b0; margin-top: 10px;")
        welcome_layout.addWidget(welcome_text)
        
        self.layout.addWidget(self.welcome_widget)
        
        # Project List
        self.project_list = QListWidget()
        self.project_list.setStyleSheet("""
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
        self.project_list.itemDoubleClicked.connect(self.on_project_double_click)
        self.layout.addWidget(self.project_list)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        self.new_btn = QPushButton("➕ New Project")
        self.new_btn.setProperty("class", "primary")
        self.new_btn.setMinimumHeight(40)
        self.new_btn.clicked.connect(self.create_project)
        btn_layout.addWidget(self.new_btn)
        
        self.open_btn = QPushButton("📂 Open Selected")
        self.open_btn.setMinimumHeight(40)
        self.open_btn.clicked.connect(self.open_selected_project)
        self.open_btn.setEnabled(False)
        btn_layout.addWidget(self.open_btn)
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setMinimumHeight(40)
        self.refresh_btn.clicked.connect(self.refresh_projects)
        btn_layout.addWidget(self.refresh_btn)
        
        self.layout.addLayout(btn_layout)
        
        # Connect selection changed
        self.project_list.itemSelectionChanged.connect(self.on_selection_changed)
        
        self.refresh_projects()

    def refresh_projects(self):
        self.project_list.clear()
        projects = self.db.get_projects()
        
        # Update stats
        total_samples = 0
        for p in projects:
            samples = self.db.get_project_samples(p.id)
            total_samples += len(samples)
        
        self.total_projects_label.setText(str(len(projects)))
        self.total_samples_label.setText(str(total_samples))
        
        # Show/hide welcome widget
        if len(projects) == 0:
            self.welcome_widget.setVisible(True)
            self.project_list.setVisible(False)
        else:
            self.welcome_widget.setVisible(False)
            self.project_list.setVisible(True)
            
            for p in projects:
                samples = self.db.get_project_samples(p.id)
                item_text = f"📁 {p.name}\n   {len(samples)} samples • Created {p.created_at.strftime('%Y-%m-%d %H:%M')}"
                item = QListWidgetItem(item_text)
                item.setData(Qt.ItemDataRole.UserRole, p.id)
                self.project_list.addItem(item)

    def create_project(self):
        name, ok = QInputDialog.getText(self, "New Project", "Project Name:")
        if ok and name:
            if self.db.create_project(name):
                self.refresh_projects()
            else:
                QMessageBox.warning(self, "Error", "Could not create project (name might be taken).")

    def on_selection_changed(self):
        self.open_btn.setEnabled(len(self.project_list.selectedItems()) > 0)

    def open_selected_project(self):
        items = self.project_list.selectedItems()
        if items:
            pid = items[0].data(Qt.ItemDataRole.UserRole)
            self.project_selected.emit(pid)

    def on_project_double_click(self, item):
        pid = item.data(Qt.ItemDataRole.UserRole)
        self.project_selected.emit(pid)
