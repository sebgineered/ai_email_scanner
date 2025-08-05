import hashlib
import os
import virustotal_python
from backend.gemini_interpreter import GeminiInterpreter
try:
    import streamlit as st
except ImportError:
    st = None

class FileScanner:
    def __init__(self):
        self.vt_api_key = self._get_virustotal_api_key()
        self.interpreter = GeminiInterpreter()

    def _get_virustotal_api_key(self):
        """Fetch VirusTotal API key from Streamlit secrets or environment variables."""
        vt_api_key = None
        try:
            if st and hasattr(st, "secrets") and "VIRUSTOTAL_API_KEY" in st.secrets:
                vt_api_key = st.secrets["VIRUSTOTAL_API_KEY"]
        except Exception:
            pass

        if not vt_api_key:
            vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

        if not vt_api_key:
            try:
                env_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
                if os.path.exists(env_file_path):
                    with open(env_file_path, 'r') as f:
                        for line in f:
                            if line.startswith("VIRUSTOTAL_API_KEY="):
                                vt_api_key = line.split("=", 1)[1].strip().strip('"').strip('"')
                                break
            except Exception:
                pass
        return vt_api_key

    def generate_file_hash(self, file_path):
        """Generate SHA256 hash of the file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            while chunk := f.read(4096):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def check_file_hash(self, file_hash: str):
        """Check file hash against VirusTotal."""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured."}
        try:
            vtotal = virustotal_python.Virustotal(self.vt_api_key)
            resp = vtotal.request(f"files/{file_hash}")
            return resp.data
        except virustotal_python.exceptions.APIError as e:
            return {"error": f"VirusTotal API Error: {e}"}
        except Exception as e:
            return {"error": f"Error checking file hash: {e}"}

    def interpret_file_results(self, vt_result: dict):
        """Generate an interpretation of the file scan results."""
        return self.interpreter.interpret_file_results(vt_result)

    def scan_file_with_virustotal(self, file_path):
        """Upload file to VirusTotal and retrieve scan results."""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured."}

        try:
            with open(file_path, "rb") as f:
                vtotal = virustotal_python.Virustotal(self.vt_api_key)
                resp = vtotal.request(f"files", data=f, method='POST')
                analysis_id = resp.json().get("data", {}).get("id")

                if not analysis_id:
                    return {"error": "Failed to initiate VirusTotal analysis."}

                # Retrieve analysis results
                analysis_resp = vtotal.request(f"analyses/{analysis_id}")
                analysis_results = analysis_resp.json()

                return analysis_results

        except virustotal_python.exceptions.APIError as e:
            return {"error": f"VirusTotal API Error: {e}"}
        except Exception as e:
            return {"error": f"Error scanning file: {e}"}
