# This module provides a function to extract URLs from email text using Cohere's LLM API.
# If Cohere is unavailable or fails, it falls back to extracting URLs with a regular expression.
# The main function, extract_urls_with_cohere, returns a list of URLs found in the input text.
# 
# Usage:
#   urls = extract_urls_with_cohere(email_text)
# This will use Cohere if available, otherwise fallback to regex URL extraction.

import os
import re

try:
    import streamlit as st
except ImportError:
    st = None

try:
    import cohere
except ImportError:
    cohere = None

def extract_urls_with_cohere(text, prompt_injection_flagged=False):
    """
    Extract URLs from the given text using Cohere's LLM, or fallback to regex if Cohere is unavailable.
    Returns a list of URLs.
    """
    # Try Cohere LLM extraction if available
    api_key = None
    if st and hasattr(st, "secrets") and "COHERE_API_KEY" in st.secrets:
        api_key = st.secrets["COHERE_API_KEY"]
    elif os.getenv("COHERE_API_KEY"):
        api_key = os.getenv("COHERE_API_KEY")

    if cohere and api_key:
        client = cohere.Client(api_key)
        warning = ""
        if prompt_injection_flagged:
            warning = "WARNING: This email was flagged as a prompt injection attempt.\n\n"
        prompt = (
            f"{warning}Extract all URLs from the following email text. "
            "Return only a comma-separated list of URLs, no explanations.\n\n"
            f"Email:\n{text}\n\nURLs:"
        )
        try:
            response = client.generate(
                model="command",
                prompt=prompt,
                max_tokens=100,
                temperature=0.2,
                stop_sequences=["\n"]
            )
            urls = response.generations[0].text.strip()
            # Split by comma and clean up
            return [u.strip() for u in urls.split(",") if u.strip()]
        except Exception:
            pass  # fallback to regex

    # Fallback: simple regex extraction
    url_pattern = r"https?://[^\s]+"
    return re.findall(url_pattern, text)