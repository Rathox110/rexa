from PyQt6.QtWidgets import QPlainTextEdit, QWidget, QVBoxLayout
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter

class HexHighlighter(QSyntaxHighlighter):
    def highlightBlock(self, text):
        # basic highlighting logic if needed, e.g. alternating colors
        pass

class HexEditor(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont("Courier New", 10))
        self.editor.setReadOnly(True)
        self.layout.addWidget(self.editor)

    def load_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                self.display_hex(data)
        except Exception as e:
            self.editor.setPlainText(f"Error reading file: {e}")

    def display_hex(self, data):
        hex_dump = []
        # Standard hex dump format: Offset  Hex Bytes  ASCII
        # 00000000  4D 5A 90 00 ...  MZ..
        
        chunk_size = 16
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            
            # Offset
            offset = f"{i:08X}  "
            
            # Hex
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            padding = "   " * (chunk_size - len(chunk))
            
            # ASCII
            ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            
            line = f"{offset}{hex_bytes}{padding}  |{ascii_text}|"
            hex_dump.append(line)
            
            # Limit for performance in MVP (first 16KB)
            if i > 16384:
                hex_dump.append("... (Truncated for performance) ...")
                break
                
        self.editor.setPlainText("\n".join(hex_dump))
