# This module provides a function to extract URLs from email text using enhanced regex patterns.
# The main function, extract_urls_enhanced, returns a list of URLs found in the input text.
# 
# Usage:
#   urls = extract_urls_enhanced(email_text)
# This will extract URLs using comprehensive regex patterns.

import os
import re
import urllib.parse

try:
    import streamlit as st
except ImportError:
    st = None

def extract_urls_enhanced(text):
    """
    Extract URLs from the given text using enhanced regex patterns.
    Returns a list of cleaned URLs.
    """
    # Comprehensive URL patterns
    url_patterns = [
        # Standard HTTP/HTTPS URLs
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        # URLs in code blocks (backticks)
        r'`(https?://[^`]+)`',
        # URLs in parentheses
        r'\((https?://[^)]+)\)',
        # URLs in quotes
        r'["\'](https?://[^"\']+)["\']',
        # URLs with common TLDs (for catching partial URLs)
        r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"{}|\\^`\[\]]*)?',
    ]
    
    all_urls = []
    
    for pattern in url_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        all_urls.extend(matches)
    
    # Clean and validate URLs
    cleaned_urls = []
    for url in all_urls:
        # Remove common trailing punctuation
        url = re.sub(r'[.,;!?]+$', '', url.strip())
        
        # Basic URL validation
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                cleaned_urls.append(url)
        except:
            continue
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in cleaned_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls

def extract_urls_with_urllib(text, prompt_injection_flagged=False):
    """
    Extract URLs from the given text using enhanced regex patterns.
    Returns a list of URLs.
    """
    return extract_urls_enhanced(text)

import tldextract

def extract_domains_from_text(text):
    # Extract domains from URLs
    urls = extract_urls_enhanced(text)
    domains = []
    for url in urls:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        domains.append(domain)
    return domains

from urlextract import URLExtract

def extract_urls_with_urlextract(text):
    extractor = URLExtract()
    return extractor.find_urls(text)