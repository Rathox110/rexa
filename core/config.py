import yaml
import os
from cryptography.fernet import Fernet
from pathlib import Path

class ConfigManager:
    """Configuration management with encrypted API key storage"""
    
    DEFAULT_CONFIG = {
        'sandbox': {
            'cuckoo': {
                'enabled': False,
                'url': 'http://localhost:8090',
                'timeout': 300
            },
            'cape': {
                'enabled': False,
                'url': 'http://localhost:8000',
                'timeout': 300
            }
        },
        'threat_intel': {
            'virustotal': {
                'enabled': False,
                'api_key': '',
                'rate_limit': 4  # requests per minute
            },
            'otx': {
                'enabled': False,
                'api_key': ''
            },
            'hybrid_analysis': {
                'enabled': False,
                'api_key': ''
            }
        },
        'disassembly': {
            'ghidra_path': '',
            'default_arch': 'x86_64',
            'auto_analyze': True
        },
        'ui': {
            'theme': 'dark',
            'font_size': 10,
            'graph_layout': 'hierarchical',
            'auto_save_interval': 300  # seconds
        },
        'advanced': {
            'database_path': 'sqlite:///rexa.db',
            'log_level': 'INFO',
            'plugin_directory': 'plugins',
            'export_directory': 'reports'
        }
    }
    
    def __init__(self, config_path='config/settings.yaml'):
        self.config_path = config_path
        self.config_dir = os.path.dirname(config_path)
        self.key_file = os.path.join(self.config_dir, '.key')
        
        # Ensure config directory exists
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        
        # Initialize encryption key
        self.cipher = self._load_or_create_key()
        
        # Load or create config
        self.config = self.load_config()
    
    def _load_or_create_key(self):
        """Load existing encryption key or create new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
        return Fernet(key)
    
    def load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                # Merge with defaults for any missing keys
                return self._merge_configs(self.DEFAULT_CONFIG, config)
        else:
            # Create default config
            self.save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()
    
    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config
        
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def _merge_configs(self, default, custom):
        """Recursively merge custom config with defaults"""
        merged = default.copy()
        for key, value in custom.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
        return merged
    
    def get(self, key_path, default=None):
        """Get config value using dot notation (e.g., 'sandbox.cuckoo.url')"""
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value
    
    def set(self, key_path, value):
        """Set config value using dot notation"""
        keys = key_path.split('.')
        config = self.config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value
        self.save_config()
    
    def encrypt_api_key(self, api_key):
        """Encrypt API key for secure storage"""
        if not api_key:
            return ''
        return self.cipher.encrypt(api_key.encode()).decode()
    
    def decrypt_api_key(self, encrypted_key):
        """Decrypt API key"""
        if not encrypted_key:
            return ''
        try:
            return self.cipher.decrypt(encrypted_key.encode()).decode()
        except:
            return ''
    
    def set_api_key(self, service, api_key):
        """Set and encrypt API key for a service"""
        encrypted = self.encrypt_api_key(api_key)
        self.set(f'threat_intel.{service}.api_key', encrypted)
    
    def get_api_key(self, service):
        """Get and decrypt API key for a service"""
        encrypted = self.get(f'threat_intel.{service}.api_key', '')
        return self.decrypt_api_key(encrypted)
    
    def validate(self):
        """Validate configuration values"""
        errors = []
        
        # Validate Ghidra path if disassembly enabled
        ghidra_path = self.get('disassembly.ghidra_path')
        if ghidra_path and not os.path.exists(ghidra_path):
            errors.append(f"Ghidra path does not exist: {ghidra_path}")
        
        # Validate plugin directory
        plugin_dir = self.get('advanced.plugin_directory')
        if not os.path.exists(plugin_dir):
            try:
                os.makedirs(plugin_dir)
            except Exception as e:
                errors.append(f"Cannot create plugin directory: {e}")
        
        # Validate export directory
        export_dir = self.get('advanced.export_directory')
        if not os.path.exists(export_dir):
            try:
                os.makedirs(export_dir)
            except Exception as e:
                errors.append(f"Cannot create export directory: {e}")
        
        return errors
