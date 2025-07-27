
from backend import extract_urls_with_cohere, sonnylabs_checker, url_scanner_client

'''Centralises logic and validation
Enforces security checks like SonnyLabs prompt scanning
Makes testing, logging, and audit trails easier
Prevents business logic from being bypassed'''

class EmailSecurityPipeline:
    def __init__(self):
        self.prompt_scanner = sonnylabs_checker.init_client()
    
    def process_email(self, email_text: str):
        # Step 1: Scan user input for prompt injection
        prompt_result = self.prompt_scanner.analyze_text(email_text, scan_type="input")
        tag = prompt_result["tag"]
        
        # Step 2: Extract URLs using GPT
        urls = extract_urls_with_cohere.extract_urls_with_gpt(email_text)

        # Step 3: Scan each URL with VirusTotal via MCP
        results = []
        for url in urls:
            scan = url_scanner_client.check_url_with_mcp(url)
            results.append({"url": url, "result": scan})

        return {
            "prompt_score": prompt_result["analysis"][0]["result"],
            "urls": results
        }
