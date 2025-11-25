import requests
import json

class LLMClient:
    def generate(self, prompt):
        raise NotImplementedError

class OllamaProvider(LLMClient):
    def __init__(self, model="llama3", url="http://localhost:11434/api/generate"):
        self.model = model
        self.url = url

    def generate(self, prompt):
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        try:
            response = requests.post(self.url, json=payload)
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                return f"Error: {response.status_code} - {response.text}"
        except Exception as e:
            return f"Connection Error: {e}. Ensure Ollama is running."

class CodeExplainer:
    def __init__(self, provider: LLMClient):
        self.provider = provider

    def explain_function(self, assembly_code):
        prompt = f"""
        You are a malware analyst. Explain the following assembly code in simple terms.
        Focus on what the function does (e.g., file I/O, network connection, encryption).
        
        Code:
        {assembly_code}
        
        Explanation:
        """
        return self.provider.generate(prompt)

    def explain_strings(self, strings):
        prompt = f"""
        Analyze these strings extracted from a binary. Identify any suspicious indicators (IOCs) or functionality.
        
        Strings:
        {strings}
        
        Analysis:
        """
        return self.provider.generate(prompt)
