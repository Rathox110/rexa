import subprocess
import os
import json
import tempfile

class GhidraBridge:
    """Ghidra headless analyzer bridge for decompilation"""
    
    def __init__(self, ghidra_path):
        """
        Initialize Ghidra bridge
        
        Args:
            ghidra_path: Path to Ghidra installation directory
        """
        self.ghidra_path = ghidra_path
        self.headless_path = self._find_headless()
    
    def _find_headless(self):
        """Find Ghidra headless analyzer script"""
        if not self.ghidra_path or not os.path.exists(self.ghidra_path):
            return None
        
        # Try to find analyzeHeadless script
        if os.name == 'nt':  # Windows
            script = os.path.join(self.ghidra_path, 'support', 'analyzeHeadless.bat')
        else:  # Linux/Mac
            script = os.path.join(self.ghidra_path, 'support', 'analyzeHeadless')
        
        if os.path.exists(script):
            return script
        
        return None
    
    def is_available(self):
        """Check if Ghidra is available"""
        return self.headless_path is not None
    
    def analyze_file(self, file_path, output_dir=None):
        """
        Analyze file with Ghidra headless
        
        Args:
            file_path: Path to binary file
            output_dir: Output directory for results
            
        Returns:
            dict: Analysis results
        """
        if not self.is_available():
            return {'error': 'Ghidra not available'}
        
        if output_dir is None:
            output_dir = tempfile.mkdtemp()
        
        project_name = os.path.basename(file_path) + '_ghidra'
        
        # Build command
        cmd = [
            self.headless_path,
            output_dir,  # Project directory
            project_name,  # Project name
            '-import', file_path,  # Import file
            '-scriptPath', os.path.join(os.path.dirname(__file__), 'scripts'),
            '-postScript', 'ExportFunctions.py',  # Custom script
            '-deleteProject'  # Clean up after
        ]
        
        try:
            # Run Ghidra headless
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                return {
                    'error': 'Ghidra analysis failed',
                    'stderr': result.stderr
                }
            
            # Parse results
            results_file = os.path.join(output_dir, 'functions.json')
            if os.path.exists(results_file):
                with open(results_file, 'r') as f:
                    return json.load(f)
            
            return {'functions': [], 'message': 'No results generated'}
            
        except subprocess.TimeoutExpired:
            return {'error': 'Ghidra analysis timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def decompile_function(self, file_path, function_address):
        """
        Decompile a specific function
        
        Args:
            file_path: Path to binary file
            function_address: Address of function to decompile
            
        Returns:
            str: Decompiled C code
        """
        if not self.is_available():
            return "// Ghidra not available"
        
        # This would require a custom Ghidra script
        # For now, return placeholder
        return f"// Decompilation of function at {function_address}\n// Requires custom Ghidra script implementation"
    
    def get_function_list(self, file_path):
        """
        Get list of functions from binary
        
        Args:
            file_path: Path to binary file
            
        Returns:
            list: List of function dicts with address, name, size
        """
        analysis = self.analyze_file(file_path)
        
        if 'error' in analysis:
            return []
        
        return analysis.get('functions', [])
