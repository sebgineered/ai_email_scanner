from backend import extract_urls_with_cohere, lakera_checker, url_scanner_client

'''Centralises logic and validation
Enforces security checks like Lakera prompt scanning
Makes testing, logging, and audit trails easier
Prevents business logic from being bypassed'''

class EmailSecurityPipeline:
    def __init__(self):
        self.prompt_scanner = lakera_checker.init_client()
    
    def process_email(self, email_text: str):
        # Step 1: Scan user input for prompt injection using Lakera
        prompt_result = self.prompt_scanner.analyze_text(email_text)
        
        # Step 2: Extract URLs using Cohere
        urls = extract_urls_with_cohere.extract_urls_with_cohere(email_text)

        # Step 3: Scan each URL with VirusTotal via MCP
        results = []
        for url in urls:
            scan = url_scanner_client.check_url_with_mcp(url)
            results.append({"url": url, "result": scan})

        return {
            "prompt_score": prompt_result.get("score", 0),
            "urls": results
        }
