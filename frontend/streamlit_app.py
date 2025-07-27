import sys
import os
import streamlit as st

# Add the parent directory to the Python path to allow backend imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.email_security_pipeline import EmailSecurityPipeline

# Set page config
st.set_page_config(page_title="AI Email Security Scanner", layout="wide")

# Title and instructions
st.title("AI Email Security Scanner")
st.markdown("""
Enter the **content of an email** you'd like to analyze.  
This tool will:
1. Detect **prompt injection risks** (via Lakera)
2. Extract any **URLs** from the message
3. Check those URLs for **malware/phishing** (via VirusTotal)
""")

# Input area
email_text = st.text_area("✉️ Paste email content here:", height=250)

# Run analysis
if st.button("🔍 Scan Email"):
    if not email_text.strip():
        st.warning("Please enter some email content first.")
    else:
        with st.spinner("Analyzing email..."):
            pipeline = EmailSecurityPipeline()
            result = pipeline.process_email(email_text)

        # Display prompt injection score
        score = result.get("prompt_score", 0)
        st.markdown(f"### Prompt Injection Risk Score: `{score:.2f}`")

        if score > 0.8:
            st.error("High risk of prompt injection detected!")
        elif score > 0.4:
            st.warning("Moderate prompt injection risk.")
        else:
            st.success("Low prompt injection risk.")

        # Display URL results
        url_results = result.get("urls", [])
        if url_results:
            st.markdown("### Extracted URLs and Scan Results:")
            for url_info in url_results:
                url = url_info["url"]
                vt_result = url_info["result"]
                malicious = vt_result.get("malicious", 0)
                suspicious = vt_result.get("suspicious", 0)

                st.markdown(f"- **{url}**")
                st.markdown(f"  -  Malicious: `{malicious}`")
                st.markdown(f"  - Suspicious: `{suspicious}`")
        else:
            st.info("No URLs found in the email.")

# Footer
st.markdown("---")
st.markdown("Built by **Sebastian Konefal** · Powered by [Lakera](https://lakera.ai), [Cohere](https://cohere.ai) & [VirusTotal](https://virustotal.com)")