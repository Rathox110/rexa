from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QTabWidget, QWidget, QFormLayout
)
from PyQt6.QtCore import Qt

class LoginDialog(QDialog):
    """User login dialog"""
    
    def __init__(self, user_manager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        self.setWindowTitle("Rexa Login")
        self.setMinimumWidth(400)
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Rexa - Reverse Engineering Command Center")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin: 20px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Tabs
        tabs = QTabWidget()
        
        # Login tab
        login_tab = QWidget()
        login_layout = QFormLayout(login_tab)
        
        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("Enter username...")
        login_layout.addRow("Username:", self.login_username)
        
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_password.setPlaceholderText("Enter password...")
        self.login_password.returnPressed.connect(self.login)
        login_layout.addRow("Password:", self.login_password)
        
        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self.login)
        login_layout.addRow("", login_btn)
        
        tabs.addTab(login_tab, "Login")
        
        # Register tab
        register_tab = QWidget()
        register_layout = QFormLayout(register_tab)
        
        self.register_username = QLineEdit()
        self.register_username.setPlaceholderText("Choose username...")
        register_layout.addRow("Username:", self.register_username)
        
        self.register_email = QLineEdit()
        self.register_email.setPlaceholderText("Enter email...")
        register_layout.addRow("Email:", self.register_email)
        
        self.register_password = QLineEdit()
        self.register_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.register_password.setPlaceholderText("Choose password...")
        register_layout.addRow("Password:", self.register_password)
        
        self.register_confirm = QLineEdit()
        self.register_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.register_confirm.setPlaceholderText("Confirm password...")
        register_layout.addRow("Confirm:", self.register_confirm)
        
        register_btn = QPushButton("Register")
        register_btn.clicked.connect(self.register)
        register_layout.addRow("", register_btn)
        
        tabs.addTab(register_tab, "Register")
        
        layout.addWidget(tabs)
        
        # Guest mode button
        guest_btn = QPushButton("Continue as Guest")
        guest_btn.clicked.connect(self.guest_mode)
        layout.addWidget(guest_btn)
    
    def login(self):
        """Handle login"""
        username = self.login_username.text().strip()
        password = self.login_password.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter username and password")
            return
        
        user = self.user_manager.authenticate(username, password)
        
        if user:
            QMessageBox.information(self, "Success", f"Welcome back, {user.username}!")
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "Invalid username or password")
    
    def register(self):
        """Handle registration"""
        username = self.register_username.text().strip()
        email = self.register_email.text().strip()
        password = self.register_password.text()
        confirm = self.register_confirm.text()
        
        # Validation
        if not username or not email or not password:
            QMessageBox.warning(self, "Error", "All fields are required")
            return
        
        if len(username) < 3:
            QMessageBox.warning(self, "Error", "Username must be at least 3 characters")
            return
        
        if len(password) < 8:
            QMessageBox.warning(self, "Error", "Password must be at least 8 characters")
            return
        
        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return
        
        # Register
        user = self.user_manager.register_user(username, email, password)
        
        if user:
            QMessageBox.information(self, "Success", "Registration successful! You can now login.")
            # Clear fields
            self.register_username.clear()
            self.register_email.clear()
            self.register_password.clear()
            self.register_confirm.clear()
        else:
            QMessageBox.critical(self, "Error", "Registration failed. Username may already exist.")
    
    def guest_mode(self):
        """Continue in guest mode"""
        reply = QMessageBox.question(
            self,
            "Guest Mode",
            "Continue without logging in? Some features may be limited.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Set a flag to indicate guest mode
            self.user_manager.guest_mode = True
            self.accept()
