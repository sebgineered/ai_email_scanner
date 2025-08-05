import streamlit as st
import os
from backend import extract_urls_with_urllib, lakera_checker, url_scanner_client, gemini_interpreter
from backend.file_scanner import FileScanner
import tempfile
import hashlib
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
        self.file_scanner = FileScanner()
        
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

        return self._build_response(flagged, results, interpretations)

    def _build_response(self, flagged: bool, url_results: list, interpretations: dict) -> dict:
        """Builds the final response dictionary."""
        return {
            "prompt_flagged": flagged,
            "urls": url_results,
            "interpretations": interpretations
        }

    def process_attachment(self, uploaded_file) -> dict:
        tmp_path = None
        try:
            # Write to a temporary file
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(uploaded_file.read())
                tmp_path = tmp.name

            # 1. Get hash
            with open(tmp_path, "rb") as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()

            # 2. Check with VirusTotal
            vt_result = self.file_scanner.check_file_hash(file_hash)
            
            # 3. Interpret using Gemini
            interpretation = self.file_scanner.interpret_file_results(vt_result)

            return {
                "hash": file_hash,
                "vt_result": vt_result,
                "interpretations": interpretation
            }

        except Exception as e:
            return {"error": str(e)}
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)