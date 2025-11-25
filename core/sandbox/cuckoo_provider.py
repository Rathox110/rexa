import requests
import time
import json
from .sandbox_provider import SandboxProvider

class CuckooProvider(SandboxProvider):
    """Cuckoo Sandbox REST API client"""
    
    def __init__(self, base_url='http://localhost:8090', timeout=300):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
    
    def submit_sample(self, file_path, options=None):
        """Submit sample to Cuckoo"""
        url = f"{self.base_url}/tasks/create/file"
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            data = options or {}
            
            try:
                response = self.session.post(url, files=files, data=data)
                response.raise_for_status()
                result = response.json()
                return result.get('task_id')
            except requests.exceptions.RequestException as e:
                raise Exception(f"Failed to submit sample: {e}")
    
    def get_task_status(self, task_id):
        """Get task status from Cuckoo"""
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
                'message': f"Task {status}"
            }
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'progress': 0,
                'message': str(e)
            }
    
    def _calculate_progress(self, status):
        """Calculate progress percentage from status"""
        progress_map = {
            'pending': 10,
            'running': 50,
            'completed': 100,
            'reported': 100,
            'failed': 0
        }
        return progress_map.get(status, 0)
    
    def get_report(self, task_id):
        """Retrieve analysis report from Cuckoo"""
        url = f"{self.base_url}/tasks/report/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            report = response.json()
            
            # Parse and structure the report
            return self._parse_report(report)
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get report: {e}")
    
    def _parse_report(self, raw_report):
        """Parse Cuckoo report into standardized format"""
        info = raw_report.get('info', {})
        behavior = raw_report.get('behavior', {})
        network = raw_report.get('network', {})
        signatures = raw_report.get('signatures', [])
        
        # Extract verdict and score
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
            },
            'verdict': verdict,
            'score': score,
            'behavior': {
                'processes': self._parse_processes(behavior.get('processes', [])),
                'summary': behavior.get('summary', {}),
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
                    'marks': sig.get('marks', [])
                }
                for sig in signatures
            ],
            'dropped': raw_report.get('dropped', []),
            'screenshots': [
                {'path': shot.get('path'), 'timestamp': i}
                for i, shot in enumerate(raw_report.get('screenshots', []))
            ]
        }
        
        return parsed
    
    def _parse_processes(self, processes):
        """Parse process tree"""
        parsed_procs = []
        
        for proc in processes:
            parsed_procs.append({
                'pid': proc.get('pid'),
                'ppid': proc.get('ppid'),
                'name': proc.get('process_name'),
                'command_line': proc.get('command_line'),
                'first_seen': proc.get('first_seen'),
            })
        
        return parsed_procs
    
    def download_artifacts(self, task_id, artifact_type):
        """Download artifacts from Cuckoo"""
        if artifact_type == 'screenshots':
            return self._download_screenshots(task_id)
        elif artifact_type == 'pcap':
            return self._download_pcap(task_id)
        elif artifact_type == 'memory':
            return self._download_memory(task_id)
        else:
            raise ValueError(f"Unknown artifact type: {artifact_type}")
    
    def _download_screenshots(self, task_id):
        """Download all screenshots"""
        url = f"{self.base_url}/tasks/screenshots/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            screenshots = response.json()
            
            # Download each screenshot
            images = []
            for shot in screenshots:
                img_url = f"{self.base_url}{shot.get('path')}"
                img_response = self.session.get(img_url)
                if img_response.status_code == 200:
                    images.append(img_response.content)
            
            return images
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to download screenshots: {e}")
    
    def _download_pcap(self, task_id):
        """Download PCAP file"""
        url = f"{self.base_url}/pcap/get/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to download PCAP: {e}")
    
    def _download_memory(self, task_id):
        """Download memory dump"""
        url = f"{self.base_url}/memory/get/{task_id}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to download memory dump: {e}")
    
    def wait_for_completion(self, task_id, poll_interval=10):
        """Wait for task to complete with polling"""
        start_time = time.time()
        
        while True:
            status_info = self.get_task_status(task_id)
            status = status_info['status']
            
            if status in ['completed', 'reported']:
                return True
            elif status == 'failed':
                return False
            
            # Check timeout
            if time.time() - start_time > self.timeout:
                raise TimeoutError(f"Task {task_id} timed out after {self.timeout}s")
            
            time.sleep(poll_interval)
