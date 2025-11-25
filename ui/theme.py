"""
Modern Dark Theme for Rexa
"""

DARK_THEME = """
QMainWindow {
    background-color: #1e1e1e;
}

QWidget {
    background-color: #1e1e1e;
    color: #d4d4d4;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 10pt;
}

/* Headers */
QLabel[class="header"] {
    font-size: 24pt;
    font-weight: bold;
    color: #ffffff;
    padding: 10px;
}

QLabel[class="subheader"] {
    font-size: 14pt;
    color: #b0b0b0;
    padding: 5px;
}

/* Buttons */
QPushButton {
    background-color: #2d2d2d;
    border: 1px solid #3e3e3e;
    border-radius: 4px;
    padding: 8px 16px;
    color: #d4d4d4;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #3e3e3e;
    border: 1px solid #007acc;
}

QPushButton:pressed {
    background-color: #007acc;
}

QPushButton[class="primary"] {
    background-color: #007acc;
    color: #ffffff;
    font-weight: bold;
}

QPushButton[class="primary"]:hover {
    background-color: #005a9e;
}

QPushButton[class="danger"] {
    background-color: #d32f2f;
    color: #ffffff;
}

QPushButton[class="danger"]:hover {
    background-color: #b71c1c;
}

/* List Widgets */
QListWidget {
    background-color: #252526;
    border: 1px solid #3e3e3e;
    border-radius: 4px;
    padding: 5px;
    outline: none;
}

QListWidget::item {
    padding: 10px;
    border-radius: 3px;
    margin: 2px;
}

QListWidget::item:selected {
    background-color: #007acc;
    color: #ffffff;
}

QListWidget::item:hover {
    background-color: #2d2d2d;
}

/* Table Widgets */
QTableWidget {
    background-color: #252526;
    border: 1px solid #3e3e3e;
    gridline-color: #3e3e3e;
    border-radius: 4px;
}

QTableWidget::item {
    padding: 5px;
}

QTableWidget::item:selected {
    background-color: #007acc;
}

QHeaderView::section {
    background-color: #2d2d2d;
    color: #d4d4d4;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #007acc;
    font-weight: bold;
}

/* Text Edits */
QTextEdit, QPlainTextEdit {
    background-color: #1e1e1e;
    border: 1px solid #3e3e3e;
    border-radius: 4px;
    padding: 8px;
    color: #d4d4d4;
    font-family: 'Consolas', 'Courier New', monospace;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #3e3e3e;
    background-color: #252526;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #2d2d2d;
    color: #d4d4d4;
    padding: 10px 20px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}

QTabBar::tab:selected {
    background-color: #007acc;
    color: #ffffff;
}

QTabBar::tab:hover {
    background-color: #3e3e3e;
}

/* Toolbar */
QToolBar {
    background-color: #2d2d2d;
    border-bottom: 2px solid #007acc;
    spacing: 5px;
    padding: 5px;
}

/* Status Bar */
QStatusBar {
    background-color: #007acc;
    color: #ffffff;
    font-weight: bold;
}

/* Progress Bar */
QProgressBar {
    border: 1px solid #3e3e3e;
    border-radius: 4px;
    text-align: center;
    background-color: #252526;
}

QProgressBar::chunk {
    background-color: #007acc;
    border-radius: 3px;
}

/* Scroll Bars */
QScrollBar:vertical {
    background-color: #1e1e1e;
    width: 12px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #3e3e3e;
    min-height: 20px;
    border-radius: 6px;
}

QScrollBar::handle:vertical:hover {
    background-color: #007acc;
}

QScrollBar:horizontal {
    background-color: #1e1e1e;
    height: 12px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background-color: #3e3e3e;
    min-width: 20px;
    border-radius: 6px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #007acc;
}

/* Input Dialog */
QInputDialog {
    background-color: #1e1e1e;
}

QLineEdit {
    background-color: #252526;
    border: 1px solid #3e3e3e;
    border-radius: 4px;
    padding: 6px;
    color: #d4d4d4;
}

QLineEdit:focus {
    border: 1px solid #007acc;
}

/* Message Box */
QMessageBox {
    background-color: #1e1e1e;
}

QMessageBox QLabel {
    color: #d4d4d4;
}
"""
