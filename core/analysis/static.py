import hashlib
import os
import pefile
try:
    import magic
except ImportError:
    magic = None

class FileProfiler:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = open(file_path, 'rb').read()
        self.info = {}

    def compute_hashes(self):
        self.info['md5'] = hashlib.md5(self.data).hexdigest()
        self.info['sha1'] = hashlib.sha1(self.data).hexdigest()
        self.info['sha256'] = hashlib.sha256(self.data).hexdigest()

    def detect_type(self):
        # Basic signature check
        if self.data.startswith(b'MZ'):
            self.info['type'] = 'PE'
        elif self.data.startswith(b'\x7fELF'):
            self.info['type'] = 'ELF'
        elif magic:
            try:
                self.info['type'] = magic.from_buffer(self.data)
            except:
                self.info['type'] = 'Unknown'
        else:
            self.info['type'] = 'Unknown'
            
    def analyze(self):
        self.compute_hashes()
        self.detect_type()
        return self.info

class PEAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        self.results = {
            'sections': [],
            'imports': {},
            'exports': []
        }

    def parse(self):
        try:
            self.pe = pefile.PE(self.file_path)
            self._parse_sections()
            self._parse_imports()
            self._parse_exports()
        except Exception as e:
            self.results['error'] = str(e)
        return self.results

    def _parse_sections(self):
        for section in self.pe.sections:
            sec_info = {
                'name': section.Name.decode().strip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'raw_size': hex(section.SizeOfRawData),
                'entropy': section.get_entropy()
            }
            self.results['sections'].append(sec_info)

    def _parse_imports(self):
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                self.results['imports'][dll_name] = []
                for imp in entry.imports:
                    func_name = imp.name.decode() if imp.name else f"ord({imp.ordinal})"
                    self.results['imports'][dll_name].append({
                        'name': func_name,
                        'address': hex(imp.address)
                    })

    def _parse_exports(self):
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                self.results['exports'].append({
                    'name': exp.name.decode() if exp.name else "N/A",
                    'ordinal': exp.ordinal,
                    'address': hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address)
                })

class StringExtractor:
    def __init__(self, data):
        self.data = data
        self.strings = []
        self.iocs = {
            'ipv4': [],
            'urls': [],
            'emails': []
        }

    def extract_ascii(self, min_len=4):
        import re
        # Regex for ASCII strings
        pattern = re.compile(b'[ -~]{' + str(min_len).encode() + b',}')
        for match in pattern.finditer(self.data):
            self.strings.append(match.group().decode('ascii'))

    def extract_unicode(self, min_len=4):
        import re
        # Basic wide string pattern
        pattern = re.compile(b'(?:[\x20-\x7E][\x00]){' + str(min_len).encode() + b',}')
        for match in pattern.finditer(self.data):
            try:
                self.strings.append(match.group().decode('utf-16le'))
            except:
                pass

    def extract_iocs(self):
        import re
        # Simple regexes for IOCs
        ipv4_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        url_re = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        email_re = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

        text = "\n".join(self.strings)
        self.iocs['ipv4'] = list(set(ipv4_re.findall(text)))
        self.iocs['urls'] = list(set(url_re.findall(text)))
        self.iocs['emails'] = list(set(email_re.findall(text)))
        return self.iocs

class DisassemblyMetrics:
    def __init__(self, file_path):
        self.file_path = file_path
        self.metrics = {'num_functions': 0, 'instructions': 0}

    def analyze(self):
        # Placeholder for Capstone/r2 integration
        # Real implementation would require parsing the PE entry point and following flow
        # For MVP, we might just return basic stats if we don't do full recursive traversal yet
        return self.metrics

from core.analysis.yara_engine import YaraEngine

class StaticAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.results = {}

    def run(self):
        # Profiler
        profiler = FileProfiler(self.file_path)
        self.results.update(profiler.analyze())
        
        # PE
        if self.results.get('type') == 'PE':
            pe = PEAnalyzer(self.file_path)
            self.results.update(pe.parse())
            
        # YARA
        try:
            yara_engine = YaraEngine()
            self.results['yara'] = yara_engine.scan(self.file_path)
        except Exception as e:
            self.results['yara_error'] = str(e)

        # Strings
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
                se = StringExtractor(data)
                se.extract_ascii()
                se.extract_iocs()
                # Limit strings to first 1000 to save DB space for MVP
                self.results['strings'] = se.strings[:1000] 
                self.results['iocs'] = se.iocs
        except Exception as e:
            self.results['strings_error'] = str(e)
            
        return self.results
