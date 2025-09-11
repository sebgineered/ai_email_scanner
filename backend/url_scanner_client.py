import os
import requests
import base64

try:
    import streamlit as st
except ImportError:
    st = None

def check_url_with_mcp(url, api_key=None):
    """
    Check a URL with VirusTotal and return the scan result.
    """
    # Get API key from Streamlit secrets or environment variable
    if not api_key:
        if st and hasattr(st, "secrets") and "VIRUSTOTAL_API_KEY" in st.secrets:
            api_key = st.secrets["VIRUSTOTAL_API_KEY"]
        else:
            api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise ValueError("Missing VIRUSTOTAL_API_KEY in environment variables or secrets.toml")

    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    # Step 1: Submit the URL for scanning
    data = {"url": url}
    try:
        post_response = requests.post(endpoint, headers=headers, data=data, timeout=10)
        post_response.raise_for_status()
    except Exception as e:
        return {"error": f"Submission failed: {str(e)}"}

    # Step 2: Get the scan ID (base64-encoded URL, no padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    get_url = f"{endpoint}/{url_id}"

    #Testing breakpoint
    #import pdb; pdb.set_trace()

    try:
        get_response = requests.get(get_url, headers=headers, timeout=10)
        get_response.raise_for_status()
        vt_data = get_response.json()
        attr = vt_data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        categories = attr.get("categories", {})
        reputation = attr.get("reputation", 0)
        
        # Ensure last_analysis_date is an integer timestamp
        last_analysis_date = attr.get("last_analysis_date", None)
        if last_analysis_date is not None:
            try:
                # Convert to int if it's a string
                if isinstance(last_analysis_date, str) and last_analysis_date.isdigit():
                    last_analysis_date = int(last_analysis_date)
            except (ValueError, TypeError):
                pass  # Keep the original value if conversion fails
                
        last_final_url = attr.get("last_final_url", "")
        threat_names = attr.get("threat_names", [])
        votes = attr.get("total_votes", {})
        # Get top engines that flagged as malicious/suspicious
        flagged_engines = []
        for engine, result in attr.get("last_analysis_results", {}).items():
            if result.get("category") in ("malicious", "suspicious"):
                flagged_engines.append({
                    "engine": engine,
                    "category": result.get("category"),
                    "result": result.get("result")
                })
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "categories": categories,
            "reputation": reputation,
            "last_analysis_date": last_analysis_date,
            "last_final_url": last_final_url,
            "threat_names": threat_names,
            "votes": votes,
            "flagged_engines": flagged_engines,
            "raw": vt_data  # Optionally include the raw data for debugging
        }
    except Exception as e:
        return {"error": f"Result fetch failed: {str(e)}"}