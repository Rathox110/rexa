import sys
import os
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.analysis.static import StaticAnalyzer
from core.database import DatabaseManager
from core.reporting import ReportGenerator

def test_core():
    print("Setting up test environment...")
    if not os.path.exists("tests"):
        os.makedirs("tests")
    
    # Clean up old DB
    if os.path.exists("tests/test_rexa.db"):
        os.remove("tests/test_rexa.db")

    # Create dummy sample
    sample_path = os.path.abspath("tests/dummy_sample.exe")
    with open(sample_path, "wb") as f:
        # MZ header + some strings
        # We need enough data for pefile not to crash immediately if we want to test PEAnalyzer, 
        # but PEAnalyzer might fail on invalid PE. StaticAnalyzer handles exceptions?
        # Let's check StaticAnalyzer code. It checks if type == 'PE' then runs PEAnalyzer.
        # FileProfiler checks startswith(b'MZ').
        # So it will try to run PEAnalyzer. PEAnalyzer.parse() has try-except.
        f.write(b"MZ" + b"\x00"*1024) 
        f.write(b"This is a test string.\n")
        f.write(b"http://malicious.com\n")
        f.write(b"192.168.1.1\n")

    print(f"Created dummy sample at {sample_path}")

    # 1. Static Analysis
    print("Running Static Analysis...")
    analyzer = StaticAnalyzer(sample_path)
    results = analyzer.run()
    print("Analysis Results (Keys):", results.keys())
    
    if results.get('type') != 'PE':
        print(f"WARNING: Detected type is {results.get('type')}, expected PE")
    
    # Check IOCs
    # Note: StringExtractor might need decoding.
    # Our dummy file has ASCII strings.
    iocs = results.get('iocs', {})
    print("IOCs Found:", iocs)
    
    # We might miss them if they are not separated by newlines or nulls correctly in my dummy write
    # The regex in StringExtractor runs on the *extracted strings list*, not raw data?
    # No, extract_iocs runs on "\n".join(self.strings).
    # extract_ascii finds sequences of printable chars.
    # "http://malicious.com" is printable.
    
    assert 'http://malicious.com' in iocs.get('urls', []), "URL not found"
    assert '192.168.1.1' in iocs.get('ipv4', []), "IP not found"

    # 1.1 YARA
    print("Testing YARA...")
    # Create a dummy rule
    if not os.path.exists("rules"):
        os.makedirs("rules")
    with open("rules/test.yar", "w") as f:
        f.write('rule TestRule { strings: $a = "test string" condition: $a }')
    
    # Re-run analysis to pick up YARA (need to reload analyzer or just test engine directly)
    from core.analysis.yara_engine import YaraEngine
    yara_engine = YaraEngine()
    matches = yara_engine.scan(sample_path)
    print("YARA Matches:", matches)
    assert any(m['rule'] == 'TestRule' for m in matches), "YARA rule not matched"

    # 2. Database
    print("Testing Database...")
    db_path = "sqlite:///tests/test_rexa.db"
    db = DatabaseManager(db_path)
    proj = db.create_project("Test Project")
    if not proj:
        # Might already exist if re-run
        proj = db.get_projects()[0]
        
    sample = db.add_sample(proj.id, "dummy_sample.exe", sample_path, results.get('md5'), results.get('sha256'), results)
    
    retrieved_sample = db.get_sample(sample.id)
    assert retrieved_sample.filename == "dummy_sample.exe"
    print("Database verification successful.")

    # 3. Reporting
    print("Testing Reporting...")
    reporter = ReportGenerator("tests/reports")
    json_path = reporter.generate_json(retrieved_sample, results)
    html_path = reporter.generate_html(retrieved_sample, results)
    
    assert os.path.exists(json_path)
    assert os.path.exists(html_path)
    print(f"Reports generated: {json_path}, {html_path}")

    print("ALL TESTS PASSED!")

if __name__ == "__main__":
    test_core()
