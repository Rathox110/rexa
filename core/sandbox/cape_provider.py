import requests
import time
from .sandbox_provider import SandboxProvider

class CAPEProvider(SandboxProvider):
    """CAPE Sandbox API client with enhanced malware analysis features"""
    
    def __init__(self, base_url='http://localhost:8000', timeout=300):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
    
    def submit_sample(self, file_path, options=None):
        """Submit sample to CAPE"""
        url = f"{self.base_url}/tasks/create/file"
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            data = options or {}
            
            try:
                response = self.session.post(url, files=files, data=data)
                response.raise_for_status()
                result = response.json()
                return result.get('task_id') or result.get('data', {}).get('task_ids', [None])[0]
            except requests.exceptions.RequestException as e:
                raise Exception(f"Failed to submit sample to CAPE: {e}")
    
    def get_task_status(self, task_id):
        """Get task status from CAPE"""
        url = f"{self.base_url}/tasks/view/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            result = response.json()
            
            task = result.get('task', {})
            status = task.get('status', 'unknown')
            
            return {
                'status': status,
                'progress': self._calculate_progress(status),
                'message': f"CAPE task {status}"
            }
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'progress': 0,
                'message': str(e)
            }
    
    def _calculate_progress(self, status):
        """Calculate progress from status"""
        progress_map = {
            'pending': 10,
            'running': 50,
            'completed': 90,
            'reported': 100,
            'failed': 0
        }
        return progress_map.get(status, 0)
    
    def get_report(self, task_id):
        """Retrieve CAPE analysis report"""
        url = f"{self.base_url}/tasks/get/report/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            report = response.json()
            
            return self._parse_cape_report(report)
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get CAPE report: {e}")
    
    def _parse_cape_report(self, raw_report):
        """Parse CAPE report with enhanced features"""
        info = raw_report.get('info', {})
        behavior = raw_report.get('behavior', {})
        network = raw_report.get('network', {})
        signatures = raw_report.get('signatures', [])
        
        # CAPE-specific: Malware configuration extraction
        cape_config = raw_report.get('CAPE', {})
        target = raw_report.get('target', {})
        
        # Calculate verdict
        score = info.get('score', 0)
        if score >= 7:
            verdict = 'malicious'
        elif score >= 4:
            verdict = 'suspicious'
        else:
            verdict = 'benign'
        
        parsed = {
            'metadata': {
                'task_id': info.get('id'),
                'started': info.get('started'),
                'ended': info.get('ended'),
                'duration': info.get('duration'),
                'machine': info.get('machine', {}).get('name'),
            },
            'verdict': verdict,
            'score': score,
            'target': {
                'file': target.get('file', {}),
                'category': target.get('category'),
            },
            'behavior': {
                'processes': self._parse_processes(behavior.get('processes', [])),
                'summary': behavior.get('summary', {}),
                'apistats': behavior.get('apistats', {}),
            },
            'network': {
                'dns': network.get('dns', []),
                'http': network.get('http', []),
                'tcp': network.get('tcp', []),
                'udp': network.get('udp', []),
                'hosts': network.get('hosts', []),
            },
            'signatures': [
                {
                    'name': sig.get('name'),
                    'description': sig.get('description'),
                    'severity': sig.get('severity'),
                    'marks': sig.get('marks', []),
                    'ttp': sig.get('ttp', [])  # MITRE ATT&CK
                }
                for sig in signatures
            ],
            'cape': {
                'payloads': cape_config.get('payloads', []),
                'configs': self._extract_malware_configs(cape_config),
                'yara': cape_config.get('yara', []),
            },
            'dropped': raw_report.get('dropped', []),
            'screenshots': raw_report.get('shots', []),
            'memory': raw_report.get('procmemory', []),
        }
        
        return parsed
    
    def _parse_processes(self, processes):
        """Parse process tree with API calls"""
        parsed_procs = []
        
        for proc in processes:
            calls = proc.get('calls', [])
            
            parsed_procs.append({
                'pid': proc.get('process_id'),
                'ppid': proc.get('parent_id'),
                'name': proc.get('process_name'),
                'command_line': proc.get('command_line'),
                'first_seen': proc.get('first_seen'),
                'api_calls': len(calls),
                'modules': proc.get('modules', []),
            })
        
        return parsed_procs
    
    def _extract_malware_configs(self, cape_data):
        """Extract malware configuration from CAPE analysis"""
        configs = []
        
        for payload in cape_data.get('payloads', []):
            config = payload.get('cape_config', {})
            if config:
                configs.append({
                    'family': config.get('family'),
                    'c2': config.get('c2', []),
                    'encryption_key': config.get('encryption_key'),
                    'mutex': config.get('mutex'),
                    'version': config.get('version'),
                    'raw_config': config
                })
        
        return configs
    
    def download_artifacts(self, task_id, artifact_type):
        """Download CAPE artifacts"""
        if artifact_type == 'screenshots':
            return self._download_screenshots(task_id)
        elif artifact_type == 'pcap':
            return self._download_pcap(task_id)
        elif artifact_type == 'memory':
            return self._download_memory(task_id)
        elif artifact_type == 'dropped':
            return self._download_dropped_files(task_id)
        else:
            raise ValueError(f"Unknown artifact type: {artifact_type}")
    
    def _download_screenshots(self, task_id):
        """Download screenshots from CAPE"""
        # CAPE stores screenshots differently
        url = f"{self.base_url}/tasks/screenshots/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to download screenshots: {e}")
    
    def _download_pcap(self, task_id):
        """Download PCAP from CAPE"""
        url = f"{self.base_url}/pcap/get/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to download PCAP: {e}")
    
    def _download_memory(self, task_id):
        """Download memory dumps from CAPE"""
        url = f"{self.base_url}/tasks/procmemory/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to download memory: {e}")
    
    def _download_dropped_files(self, task_id):
        """Download dropped files from CAPE"""
        url = f"{self.base_url}/tasks/dropped/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to download dropped files: {e}")
    
    def wait_for_completion(self, task_id, poll_interval=10):
        """Wait for CAPE task completion"""
        start_time = time.time()
        
        while True:
            status_info = self.get_task_status(task_id)
            status = status_info['status']
            
            if status in ['completed', 'reported']:
                return True
            elif status == 'failed':
                return False
            
            if time.time() - start_time > self.timeout:
                raise TimeoutError(f"CAPE task {task_id} timed out")
            
            time.sleep(poll_interval)
