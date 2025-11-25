from OTXv2 import OTXv2, IndicatorTypes

class OTXClient:
    """AlienVault Open Threat Exchange client"""
    
    def __init__(self, api_key):
        """Initialize OTX client"""
        self.otx = OTXv2(api_key)
    
    def get_file_reputation(self, file_hash):
        """
        Get file reputation from OTX
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            dict: Reputation data
        """
        try:
            # Determine hash type
            hash_len = len(file_hash)
            if hash_len == 32:
                indicator_type = IndicatorTypes.FILE_HASH_MD5
            elif hash_len == 40:
                indicator_type = IndicatorTypes.FILE_HASH_SHA1
            elif hash_len == 64:
                indicator_type = IndicatorTypes.FILE_HASH_SHA256
            else:
                return {'error': 'Invalid hash length'}
            
            # Get general info
            general = self.otx.get_indicator_details_full(indicator_type, file_hash)
            
            # Parse pulses
            pulses = general.get('general', {}).get('pulse_info', {}).get('pulses', [])
            
            parsed_pulses = []
            for pulse in pulses:
                parsed_pulses.append({
                    'name': pulse.get('name'),
                    'description': pulse.get('description'),
                    'author': pulse.get('author_name'),
                    'created': pulse.get('created'),
                    'modified': pulse.get('modified'),
                    'tags': pulse.get('tags', []),
                    'references': pulse.get('references', []),
                    'malware_families': pulse.get('malware_families', []),
                    'adversary': pulse.get('adversary'),
                    'targeted_countries': pulse.get('targeted_countries', []),
                })
            
            # Get malware info
            malware = general.get('malware', {})
            
            # Calculate reputation score
            pulse_count = len(pulses)
            reputation_score = min(100, pulse_count * 10)  # Simple scoring
            
            return {
                'found': pulse_count > 0,
                'hash': file_hash,
                'pulse_count': pulse_count,
                'pulses': parsed_pulses,
                'malware': malware,
                'reputation_score': reputation_score,
                'verdict': 'malicious' if reputation_score > 50 else 'suspicious' if reputation_score > 20 else 'unknown'
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_ip_reputation(self, ip_address):
        """Get IP address reputation"""
        try:
            general = self.otx.get_indicator_details_full(IndicatorTypes.IPv4, ip_address)
            
            pulses = general.get('general', {}).get('pulse_info', {}).get('pulses', [])
            geo = general.get('geo', {})
            
            return {
                'found': len(pulses) > 0,
                'ip': ip_address,
                'pulse_count': len(pulses),
                'country': geo.get('country_name'),
                'city': geo.get('city'),
                'asn': geo.get('asn'),
                'pulses': [
                    {
                        'name': p.get('name'),
                        'tags': p.get('tags', [])
                    }
                    for p in pulses[:10]  # Limit to 10
                ]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_domain_reputation(self, domain):
        """Get domain reputation"""
        try:
            general = self.otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
            
            pulses = general.get('general', {}).get('pulse_info', {}).get('pulses', [])
            
            return {
                'found': len(pulses) > 0,
                'domain': domain,
                'pulse_count': len(pulses),
                'pulses': [
                    {
                        'name': p.get('name'),
                        'tags': p.get('tags', [])
                    }
                    for p in pulses[:10]
                ]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_url_reputation(self, url):
        """Get URL reputation"""
        try:
            general = self.otx.get_indicator_details_full(IndicatorTypes.URL, url)
            
            pulses = general.get('general', {}).get('pulse_info', {}).get('pulses', [])
            
            return {
                'found': len(pulses) > 0,
                'url': url,
                'pulse_count': len(pulses),
                'pulses': [
                    {
                        'name': p.get('name'),
                        'tags': p.get('tags', [])
                    }
                    for p in pulses[:10]
                ]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_related_samples(self, file_hash):
        """Get samples related to this hash"""
        try:
            # Determine hash type
            hash_len = len(file_hash)
            if hash_len == 32:
                indicator_type = IndicatorTypes.FILE_HASH_MD5
            elif hash_len == 40:
                indicator_type = IndicatorTypes.FILE_HASH_SHA1
            elif hash_len == 64:
                indicator_type = IndicatorTypes.FILE_HASH_SHA256
            else:
                return []
            
            general = self.otx.get_indicator_details_full(indicator_type, file_hash)
            
            # Extract related samples from pulses
            related = []
            pulses = general.get('general', {}).get('pulse_info', {}).get('pulses', [])
            
            for pulse in pulses:
                indicators = pulse.get('indicators', [])
                for ind in indicators:
                    if ind.get('type') in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                        if ind.get('indicator') != file_hash:
                            related.append({
                                'hash': ind.get('indicator'),
                                'type': ind.get('type'),
                                'pulse': pulse.get('name')
                            })
            
            return related[:50]  # Limit to 50
        except Exception as e:
            return []
    
    def search_pulses(self, query):
        """Search pulses by keyword"""
        try:
            results = self.otx.search_pulses(query)
            
            pulses = []
            for result in results.get('results', [])[:20]:  # Limit to 20
                pulses.append({
                    'name': result.get('name'),
                    'description': result.get('description'),
                    'author': result.get('author_name'),
                    'created': result.get('created'),
                    'tags': result.get('tags', []),
                })
            
            return pulses
        except Exception as e:
            return []
