"""
Gemini Interpreter Module

This module provides intelligent interpretation of email security scan results using Google's Gemini API.
It analyzes the tone of emails, interprets prompt injection results, and explains VirusTotal findings.

"""
import os
import json
from typing import List, Dict, Any, Optional

try:
    import google.generativeai as genai
except ImportError:
    genai = None

try:
    import streamlit as st
except ImportError:
    st = None


class GeminiInterpreter:
    """
    A class that uses Google's Gemini to provide intelligent interpretation of email security scan results.
    """
    
    def __init__(self):
        """Initialize the GeminiInterpreter with API key."""
        self.api_key = self._get_api_key()
        self.model = None
        
        if genai and self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-2.0-flash')
            except Exception as e:
                print(f"Failed to initialize Gemini client: {e}")
    
    def _get_api_key(self) -> Optional[str]:
        """Get Gemini API key from environment or Streamlit secrets."""
        api_key = None
        
        # Try Streamlit secrets first
        try:
            if st and hasattr(st, "secrets") and "GEMINI_API_KEY" in st.secrets:
                api_key = st.secrets["GEMINI_API_KEY"]
        except Exception:
            pass
        
        # Try environment variable
        if not api_key:
            api_key = os.getenv("GEMINI_API_KEY")
        
        # Try loading from .env file directly
        if not api_key:
            try:
                env_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
                if os.path.exists(env_file_path):
                    with open(env_file_path, 'r') as f:
                        for line in f:
                            if line.startswith("GEMINI_API_KEY="):
                                api_key = line.split("=", 1)[1].strip().strip('"').strip('"')
                                break
            except Exception:
                pass
        
        return api_key
    
    def _format_virustotal_results(self, url_results: List[Dict[str, Any]]) -> str:
        """Format VirusTotal results for the prompt."""
        if not url_results:
            return "No URLs were found or scanned."
        
        formatted_results = []
        for url_info in url_results:
            url = url_info.get("url", "Unknown URL")
            result = url_info.get("result", {})
            
            malicious = result.get("malicious", 0)
            suspicious = result.get("suspicious", 0)
            categories = result.get("categories", {})
            threat_names = result.get("threat_names", [])
            
            status = "MALICIOUS" if malicious > 0 else "SUSPICIOUS" if suspicious > 0 else "CLEAN"
            
            formatted_result = f"URL: {url} - Status: {status}"
            if malicious > 0:
                formatted_result += f" (Malicious: {malicious}, Suspicious: {suspicious})"
            if categories:
                formatted_result += f" - Categories: {categories}"
            if threat_names:
                formatted_result += f" - Threats: {', '.join(threat_names)}"
            
            formatted_results.append(formatted_result)
        
        return "\n".join(formatted_results)
    
    def interpret_results(self, 
                         email_text: str, 
                         prompt_injection_result: Dict[str, Any], 
                         url_results: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Generate intelligent interpretation of all scan results.
        
        Args:
            email_text: The full email content
            prompt_injection_result: Results from Lakera prompt injection check
            url_results: Results from VirusTotal URL scanning
            
        Returns:
            Dictionary containing interpretations for tone, prompt injection, and URL analysis
        """
        if not self.model:
            return {
                "tone_analysis": "Gemini API not available",
                "prompt_injection_interpretation": "Gemini API not available", 
                "url_analysis": "Gemini API not available"
            }
        
        try:
            # Format VirusTotal results
            vt_results_text = self._format_virustotal_results(url_results)
            
            # Create comprehensive prompt
            prompt = f"""
Analyze the following email security scan results and provide concise interpretations (under 600 characters each):

EMAIL CONTENT:
{email_text}

PROMPT INJECTION RESULT:
{json.dumps(prompt_injection_result, indent=2)}

VIRUSTOTAL URL SCAN RESULTS:
{vt_results_text}

Provide three separate interpretations:

1. EMAIL TONE ANALYSIS: Analyze the tone, urgency, and social engineering tactics used in the email.

2. PROMPT INJECTION INTERPRETATION: Explain what the prompt injection detection means and its security implications.

3. URL THREAT ANALYSIS: Summarize the security risks found in the scanned URLs and their potential impact.

Keep each interpretation under 600 characters and focus on actionable security insights.
"""
            
            # Generate interpretation
            response = self.model.generate_content(prompt)
            
            interpretation_text = response.text.strip()
            
            # Parse the response into sections
            sections = self._parse_interpretation_sections(interpretation_text)
            
            return {
                "tone_analysis": sections.get("tone", "Analysis not available"),
                "prompt_injection_interpretation": sections.get("prompt_injection", "Analysis not available"),
                "url_analysis": sections.get("urls", "Analysis not available")
            }
            
        except Exception as e:
            return {
                "tone_analysis": f"Error in analysis: {str(e)}",
                "prompt_injection_interpretation": f"Error in analysis: {str(e)}",
                "url_analysis": f"Error in analysis: {str(e)}"
            }
    
    def _parse_interpretation_sections(self, text: str) -> Dict[str, str]:
        """Parse the Gemini response into separate sections."""
        sections = {}
        
        # Split by numbered sections
        parts = text.split('\n\n')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
                
            # Check for section headers
            if part.startswith('1.') or 'EMAIL TONE ANALYSIS' in part:
                # Extract content after the header
                content = part.split(':', 1)[1] if ':' in part else part
                sections['tone'] = content.strip()
                
            elif part.startswith('2.') or 'PROMPT INJECTION INTERPRETATION' in part:
                # Extract content after the header
                content = part.split(':', 1)[1] if ':' in part else part
                sections['prompt_injection'] = content.strip()
                
            elif part.startswith('3.') or 'URL THREAT ANALYSIS' in part:
                # Extract content after the header
                content = part.split(':', 1)[1] if ':' in part else part
                sections['urls'] = content.strip()
        
        return sections
    
    def is_available(self) -> bool:
        """Check if Gemini API is available and configured."""
        return self.model is not None
