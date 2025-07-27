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
                categories = vt_result.get("categories", {})
                reputation = vt_result.get("reputation", 0)
                last_analysis_date = vt_result.get("last_analysis_date", None)
                last_final_url = vt_result.get("last_final_url", "")
                threat_names = vt_result.get("threat_names", [])
                votes = vt_result.get("votes", {})
                flagged_engines = vt_result.get("flagged_engines", [])

                def get_color(malicious, suspicious=0, field="default"):
                    if field == "malicious":
                        return "red" if malicious > 0 else "green"
                    if field == "suspicious":
                        return "orange" if suspicious > 0 else "green"
                    return "red" if malicious > 0 else "green"

                # Color the Malicious count
                malicious_color = get_color(malicious, field="malicious")
                # Suspicious is orange if > 0, else green
                suspicious_color = get_color(malicious, suspicious, field="suspicious")
                categories_color = get_color(malicious)
                reputation_color = get_color(malicious)
                last_analysis_date_color = get_color(malicious)
                last_final_url_color = get_color(malicious)
                threat_names_color = get_color(malicious)
                votes_color = get_color(malicious)

                if malicious > 0:
                    # Obfuscate to prevent auto-linking
                    safe_url = url.replace('.', '[.]')
                    st.markdown(f"- <span style='color:red'><b>{safe_url}</b> (malicious, link disabled)</span>", unsafe_allow_html=True)
                else:
                    # Show as clickable link
                    st.markdown(f"- [**{url}**]({url})")

                st.markdown(f"  -  Malicious: <span style='color:{malicious_color}'><b>{malicious}</b></span>", unsafe_allow_html=True)
                st.markdown(f"  - Suspicious: <span style='color:{suspicious_color}'>{suspicious}</span>", unsafe_allow_html=True)
                st.markdown(f"  - Categories: <span style='color:{categories_color}'>{categories}</span>", unsafe_allow_html=True)
                st.markdown(f"  - Reputation: <span style='color:{reputation_color}'>{reputation}</span>", unsafe_allow_html=True)
                if last_analysis_date:
                    import datetime
                    dt = datetime.datetime.fromtimestamp(last_analysis_date)
                    st.markdown(f"  - Last Analysis Date: <span style='color:{last_analysis_date_color}'>{dt}</span>", unsafe_allow_html=True)
                if last_final_url and last_final_url != url:
                    if malicious > 0:
                        # Obfuscate to prevent auto-linking
                        safe_final_url = last_final_url.replace('.', '[.]')
                        st.markdown(f"  - Last Final URL: <span style='color:{last_final_url_color}'>{safe_final_url} (malicious, link disabled)</span>", unsafe_allow_html=True)
                    else:
                        # Show as clickable link
                        st.markdown(f"  - Last Final URL: <span style='color:{last_final_url_color}'><a href='{last_final_url}' target='_blank'>{last_final_url}</a></span>", unsafe_allow_html=True)
                if threat_names:
                    st.markdown(f"  - Threat Names: <span style='color:{threat_names_color}'>{', '.join(threat_names)}</span>", unsafe_allow_html=True)
                if votes:
                    st.markdown(f"  - Votes: <span style='color:{votes_color}'>{votes}</span>", unsafe_allow_html=True)
                if flagged_engines:
                    with st.expander("Engines flagged as malicious/suspicious"):
                        for engine in flagged_engines:
                            category = engine['category']
                            result = engine['result']
                            # Color malicious/suspicious in red, clean/harmless in green, else default
                            if category == "malicious" or result in ("malicious", "phishing", "malware"):
                                color = "red"
                            elif category == "harmless" or result in ("clean", "unrated"):
                                color = "green"
                            else:
                                color = "orange"
                            st.markdown(
                                f"- **{engine['engine']}**: "
                                f"<span style='color:{color}'>{category}</span> "
                                f"(<span style='color:{color}'>{result}</span>)",
                                unsafe_allow_html=True
                            )
        else:
            st.info("No URLs found in the email.")

# Footer
st.markdown("---")
st.markdown("Built by **Sebastian Konefal** · Powered by [Lakera](https://lakera.ai), [Cohere](https://cohere.ai) & [VirusTotal](https://virustotal.com)")