import streamlit as st
from backend.sonnylabs_checker import analyze_with_sonnylabs
from backend.gpt_url_extractor import extract_urls
from backend.url_scanner_client import scan_url
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(page_title="AI Email Security Scanner", page_icon="🛡️")

# App title
st.title("🛡️ AI Email Security Scanner")
st.markdown("Paste an email message below to scan it for prompt injection risks and malicious URLs.")

# Email content input
email_text = st.text_area("✉️ Email Content", height=300)

# Trigger scan
if st.button("🔍 Scan Email"):
    if not email_text.strip():
        st.warning("⚠️ Please paste email content before scanning.")
    else:
        # Step 1: SonnyLabs prompt injection scan
        st.subheader("1 Prompt Injection Risk Analysis")
        with st.spinner("Scanning for prompt injection with SonnyLabs..."):
            injection_result = analyze_with_sonnylabs(email_text)
            if injection_result["success"]:
                score = injection_result["score"]
                logger.info(f"Prompt injection score: {score}")
                st.markdown(f"**Risk Score:** `{score:.2f}`")
                if score > 0.7:
                    st.error("High risk of prompt injection.")
                elif score > 0.4:
                    st.warning("Moderate risk of injection.")
                else:
                    st.success("Low injection risk.")
            else:
                st.error(f"Error from SonnyLabs: {injection_result['error']}")

        # Step 2: GPT-4 URL extraction
        st.subheader("2 URL Extraction")
        with st.spinner("Extracting URLs using GPT-4..."):
            urls = extract_urls(email_text)
            if urls:
                st.success(f"✅ {len(urls)} URL(s) extracted.")
                for url in urls:
                    st.markdown(f"- {url}")
            else:
                st.info("No URLs found in the message.")

        # Step 3: VirusTotal threat scan via MCP
        if urls:
            st.subheader("3 URL Threat Analysis (VirusTotal)")
            for url in urls:
                with st.spinner(f"Scanning: {url}"):
                    scan_result = scan_url(url)
                    if scan_result["success"]:
                        threat_level = scan_result["threat_level"]
                        if threat_level == "HIGH":
                            st.error(f" {url} - High threat (malicious)")
                        elif threat_level == "MEDIUM":
                            st.warning(f" {url} - Suspicious")
                        else:
                            st.success(f" {url} - Clean")
                    else:
                        st.warning(f"Error scanning {url}: {scan_result['error']}")
