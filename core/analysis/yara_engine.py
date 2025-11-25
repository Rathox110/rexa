import yara
import os

class YaraEngine:
    def __init__(self, rules_path='rules'):
        self.rules_path = rules_path
        self.rules = None
        if not os.path.exists(rules_path):
            os.makedirs(rules_path)
        self.compile_rules()

    def compile_rules(self):
        filepaths = {}
        for root, dirs, files in os.walk(self.rules_path):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    filepaths[file] = os.path.join(root, file)
        
        if filepaths:
            try:
                self.rules = yara.compile(filepaths=filepaths)
            except yara.SyntaxError as e:
                print(f"YARA Syntax Error: {e}")
                self.rules = None
        else:
            self.rules = None

    def scan(self, file_path):
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(file_path)
            return [{'rule': m.rule, 'tags': m.tags, 'meta': m.meta} for m in matches]
        except Exception as e:
            print(f"YARA Scan Error: {e}")
            return []
