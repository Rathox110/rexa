import requests
import time
from datetime import datetime, timedelta

class VirusTotalClient:
    """VirusTotal API v3 client with rate limiting"""
    
    API_BASE = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key, rate_limit=4):
        """
        Initialize VT client
        
        Args:
            api_key: VirusTotal API key
            rate_limit: Requests per minute (default 4 for free tier)
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.request_times = []
        self.session = requests.Session()
        self.session.headers.update({
            'x-apikey': api_key
        })
    
    def _rate_limit_wait(self):
        """Implement rate limiting using token bucket"""
        now = datetime.now()
        
        # Remove requests older than 1 minute
        self.request_times = [t for t in self.request_times if now - t < timedelta(minutes=1)]
        
        # Wait if we've hit the limit
        if len(self.request_times) >= self.rate_limit:
            oldest = self.request_times[0]
            wait_time = 60 - (now - oldest).total_seconds()
            if wait_time > 0:
                time.sleep(wait_time + 1)
                self.request_times = []
        
        self.request_times.append(now)
    
    def get_file_report(self, file_hash):
        """
        Get file analysis report by hash
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            dict: Analysis report
        """
        self._rate_limit_wait()
        
        url = f"{self.API_BASE}/files/{file_hash}"
        
        try:
            response = self.session.get(url)
            
            if response.status_code == 404:
                return {'found': False, 'hash': file_hash}
            
            response.raise_for_status()
            data = response.json()
            
            return self._parse_file_report(data)
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
    
    def _parse_file_report(self, raw_data):
        """Parse VT file report"""
        data = raw_data.get('data', {})
        attributes = data.get('attributes', {})
        
        # Last analysis stats
        stats = attributes.get('last_analysis_stats', {})
        total_engines = sum(stats.values())
        detections = stats.get('malicious', 0) + stats.get('suspicious', 0)
        
        # Last analysis results
        results = attributes.get('last_analysis_results', {})
        vendor_results = []
        
        for vendor, result in results.items():
            vendor_results.append({
                'vendor': vendor,
                'result': result.get('result'),
                'category': result.get('category'),
                'engine_version': result.get('engine_version')
            })
        
        parsed = {
            'found': True,
            'hash': {
                'md5': attributes.get('md5'),
                'sha1': attributes.get('sha1'),
                'sha256': attributes.get('sha256'),
            },
            'detection_ratio': f"{detections}/{total_engines}",
            'detections': detections,
            'total_engines': total_engines,
            'stats': stats,
            'vendor_results': vendor_results,
            'names': attributes.get('names', []),
            'size': attributes.get('size'),
            'type': attributes.get('type_description'),
            'first_submission': attributes.get('first_submission_date'),
            'last_submission': attributes.get('last_submission_date'),
            'last_analysis': attributes.get('last_analysis_date'),
            'reputation': attributes.get('reputation', 0),
            'tags': attributes.get('tags', []),
            'popular_threat_name': attributes.get('popular_threat_classification', {}).get('suggested_threat_label'),
        }
        
        return parsed
    
    def submit_file(self, file_path):
        """
        Submit file for analysis
        
        Args:
            file_path: Path to file
            
        Returns:
            dict: Submission result with analysis ID
        """
        self._rate_limit_wait()
        
        url = f"{self.API_BASE}/files"
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            
            try:
                response = self.session.post(url, files=files)
                response.raise_for_status()
                data = response.json()
                
                return {
                    'success': True,
                    'analysis_id': data.get('data', {}).get('id'),
                    'message': 'File submitted successfully'
                }
            except requests.exceptions.RequestException as e:
                return {'success': False, 'error': str(e)}
    
    def get_comments(self, file_hash):
        """Get community comments for a file"""
        self._rate_limit_wait()
        
        url = f"{self.API_BASE}/files/{file_hash}/comments"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            comments = []
            for item in data.get('data', []):
                attrs = item.get('attributes', {})
                comments.append({
                    'text': attrs.get('text'),
                    'date': attrs.get('date'),
                    'votes': attrs.get('votes', {})
                })
            
            return comments
        except requests.exceptions.RequestException as e:
            return []
    
    def get_behavior_report(self, file_hash):
        """Get behavioral analysis report"""
        self._rate_limit_wait()
        
        url = f"{self.API_BASE}/files/{file_hash}/behaviour_summary"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            return data.get('data', {})
        except requests.exceptions.RequestException as e:
            return {}
    
    def get_relationships(self, file_hash, relationship_type):
        """
        Get file relationships (contacted IPs, domains, etc.)
        
        Args:
            file_hash: File hash
            relationship_type: contacted_ips, contacted_domains, contacted_urls, etc.
        """
        self._rate_limit_wait()
        
        url = f"{self.API_BASE}/files/{file_hash}/{relationship_type}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            relationships = []
            for item in data.get('data', []):
                relationships.append({
                    'id': item.get('id'),
                    'type': item.get('type'),
                    'attributes': item.get('attributes', {})
                })
            
            return relationships
        except requests.exceptions.RequestException as e:
            return []
