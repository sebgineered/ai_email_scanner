# Lakera Guard API integration for prompt injection detection.
# 
# This module provides the LakeraChecker class, which sends text to the Lakera Guard API
# to analyze for prompt injection and other security risks. It supports API key retrieval
# from Streamlit secrets or environment variables, making it suitable for both local and
# Streamlit Cloud deployments. The main method, analyze_text, returns the API's analysis
# result as a dictionary.
# 
# Usage:
#   checker = LakeraChecker(api_key="your_api_key")
#   result = checker.analyze_text("some text to check")
# 
# If no API key is provided, it will look for LAKERA_API_KEY in Streamlit secrets or environment variables.

import requests
import os

try:
    import streamlit as st
except ImportError:
    st = None

class LakeraChecker:
    def __init__(self, api_key=None):
        if api_key:
            self.api_key = api_key
        elif st and hasattr(st, "secrets") and "LAKERA_API_KEY" in st.secrets:
            self.api_key = st.secrets["LAKERA_API_KEY"]
        else:
            self.api_key = os.getenv("LAKERA_API_KEY")

        self.session = requests.Session()
        self.endpoint = "https://api.lakera.ai/v2/guard"

        if not self.api_key:
            raise ValueError("Missing LAKERA_API_KEY in environment variables or secrets.toml")

    def analyze_text(self, text: str) -> dict:
        """Send user input to Lakera Guard API and return result."""
        payload = {
            "messages": [
                {
                    "content": text,
                    "role": "user"
                }
            ]
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}"
        }

        try:
            response = self.session.post(self.endpoint, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"score": 0.0, "error": str(e)}

def init_client() -> LakeraChecker:
    return LakeraChecker()
