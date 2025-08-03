import streamlit as st
from backend import extract_urls_with_urllib, lakera_checker, url_scanner_client, gemini_interpreter

'''
Centralises logic and validation.
Enforces security checks like Lakera prompt scanning.
Makes testing, logging, and audit trails easier.
Prevents business logic from being bypassed.
'''

class EmailSecurityPipeline:
    def __init__(self):
        # Pass Lakera API key from Streamlit secrets
        self.lakera_api_key = st.secrets["LAKERA_API_KEY"]

    def process_email(self, email_text: str):
        # Step 1: Scan user input for prompt injection using Lakera
        checker = lakera_checker.LakeraChecker(api_key=self.lakera_api_key)
        prompt_result = checker.analyze_text(email_text)
        flagged = prompt_result.get("flagged", False)

        # Step 2: Extract URLs using enhanced regex patterns, inform if prompt injection flagged
        urls = extract_urls_with_urllib.extract_urls_with_urllib(email_text, prompt_injection_flagged=flagged)

        # Step 3: Scan each URL with VirusTotal via MCP
        results = []
        for url in urls:
            scan = url_scanner_client.check_url_with_mcp(url)
            results.append({"url": url, "result": scan})

        # Step 4: Generate intelligent interpretation using Cohere
        interpreter = gemini_interpreter.GeminiInterpreter()
        interpretations = interpreter.interpret_results(
            email_text=email_text,
            prompt_injection_result=prompt_result,
            url_results=results
        )

        return {
            "prompt_flagged": flagged,
            "urls": results,
            "interpretations": interpretations
        }
