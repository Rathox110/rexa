from abc import ABC, abstractmethod

class SandboxProvider(ABC):
    """Abstract base class for sandbox providers"""
    
    @abstractmethod
    def submit_sample(self, file_path, options=None):
        """
        Submit a sample for analysis
        
        Args:
            file_path: Path to the file to analyze
            options: Provider-specific options dict
            
        Returns:
            task_id: Unique identifier for the analysis task
        """
        pass
    
    @abstractmethod
    def get_task_status(self, task_id):
        """
        Get the status of an analysis task
        
        Args:
            task_id: Task identifier
            
        Returns:
            dict with keys: status, progress, message
        """
        pass
    
    @abstractmethod
    def get_report(self, task_id):
        """
        Retrieve the analysis report
        
        Args:
            task_id: Task identifier
            
        Returns:
            dict: Complete analysis report
        """
        pass
    
    @abstractmethod
    def download_artifacts(self, task_id, artifact_type):
        """
        Download analysis artifacts (screenshots, PCAP, memory dumps)
        
        Args:
            task_id: Task identifier
            artifact_type: Type of artifact (screenshot, pcap, memory)
            
        Returns:
            bytes or list of bytes: Artifact data
        """
        pass
