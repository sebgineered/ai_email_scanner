import os
import re
import email
import base64
import hashlib
import tempfile
import quopri
from email.parser import BytesParser
from email.policy import default
from bs4 import BeautifulSoup
import extract_msg
import ipaddress

class EmailParser:
    """Parser for .eml and .msg email files."""
    
    def __init__(self):
        self.max_file_size = 15 * 1024 * 1024  # 15MB
        self.max_attachments = 15
        self.temp_files = []
    
    def __del__(self):
        """Clean up temporary files when the object is destroyed."""
        self.cleanup_temp_files()
    
    def cleanup_temp_files(self):
        """Remove all temporary files created during parsing."""
        for temp_file in self.temp_files:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass
        self.temp_files = []
    
    def parse_email_file(self, file_path):
        """Parse an email file (.eml or .msg) and extract its contents.
        
        Args:
            file_path: Path to the email file
            
        Returns:
            dict: Email contents including headers, body, and attachments
        """
        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size:
            return {"error": f"File size exceeds maximum allowed size (15MB). File size: {file_size/1024/1024:.2f}MB"}
        
        # Check file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        if ext == ".eml":
            return self._parse_eml(file_path)
        elif ext == ".msg":
            return self._parse_msg(file_path)
        else:
            return {"error": f"Unsupported file format: {ext}. Only .eml and .msg formats are supported."}
    
    def _parse_eml(self, file_path):
        """Parse an .eml file."""
        try:
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=default).parse(f)
            
            return self._process_email_message(msg)
        except Exception as e:
            return {"error": f"Error parsing .eml file: {str(e)}"}
    
    def _parse_msg(self, file_path):
        """Parse an .msg (Outlook) file."""
        try:
            msg = extract_msg.Message(file_path)
            
            # Extract basic headers
            headers = {
                "Subject": msg.subject,
                "From": msg.sender,
                "To": msg.to,
                "Date": msg.date,
                "Message-ID": msg.message_id
            }
            
            # Get body text (prefer plain text)
            body_text = msg.body
            body_html = msg.htmlBody
            
            # Process attachments
            attachments = []
            for attachment in msg.attachments:
                if len(attachments) >= self.max_attachments:
                    break
                    
                # Create a temporary file for the attachment
                with tempfile.NamedTemporaryFile(delete=False) as temp:
                    temp.write(attachment.data)
                    temp_path = temp.name
                    self.temp_files.append(temp_path)
                
                # Calculate hash
                file_hash = hashlib.sha256(attachment.data).hexdigest()
                
                attachments.append({
                    "filename": attachment.longFilename or attachment.shortFilename or "unknown",
                    "mime_type": attachment.mimetype or "application/octet-stream",
                    "size": len(attachment.data),
                    "sha256": file_hash,
                    "temp_path": temp_path
                })
            
            # Convert HTML to text if plain text is missing
            if not body_text and body_html:
                body_text = self._html_to_text(body_html)
            
            # Defang URLs in body text
            body_text = self._defang_urls(body_text)
            
            # Check for private IPs in body
            has_private_ips = self._check_for_private_ips(body_text)
            
            return {
                "headers": headers,
                "body_text": body_text,
                "body_html": body_html,
                "attachments": attachments,
                "has_private_ips": has_private_ips
            }
        except Exception as e:
            return {"error": f"Error parsing .msg file: {str(e)}"}
    
    def _process_email_message(self, msg):
        """Process an email.message.Message object."""
        # Extract headers
        headers = {
            "Subject": msg.get("Subject", ""),
            "From": msg.get("From", ""),
            "To": msg.get("To", ""),
            "Date": msg.get("Date", ""),
            "Message-ID": msg.get("Message-ID", "")
        }
        
        # Get body parts
        body_text = ""
        body_html = ""
        attachments = []
        
        # Process all parts
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()
            
            # Skip multipart containers
            if content_type.startswith("multipart/"):
                continue
                
            # Handle attachments
            if content_disposition == "attachment" or (content_disposition and "attachment" in content_disposition):
                if len(attachments) >= self.max_attachments:
                    continue
                    
                filename = part.get_filename() or "unknown"
                payload = part.get_payload(decode=True)
                
                if payload:
                    # Create a temporary file for the attachment
                    with tempfile.NamedTemporaryFile(delete=False) as temp:
                        temp.write(payload)
                        temp_path = temp.name
                        self.temp_files.append(temp_path)
                    
                    # Calculate hash
                    file_hash = hashlib.sha256(payload).hexdigest()
                    
                    attachments.append({
                        "filename": filename,
                        "mime_type": content_type,
                        "size": len(payload),
                        "sha256": file_hash,
                        "temp_path": temp_path
                    })
            # Handle text parts
            elif content_type == "text/plain" and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        body_text = payload.decode(charset)
                    except UnicodeDecodeError:
                        body_text = payload.decode('utf-8', errors='replace')
            # Handle HTML parts
            elif content_type == "text/html" and not body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        body_html = payload.decode(charset)
                    except UnicodeDecodeError:
                        body_html = payload.decode('utf-8', errors='replace')
        
        # Convert HTML to text if plain text is missing
        if not body_text and body_html:
            body_text = self._html_to_text(body_html)
        
        # Defang URLs in body text
        body_text = self._defang_urls(body_text)
        
        # Check for private IPs in body
        has_private_ips = self._check_for_private_ips(body_text)
        
        return {
            "headers": headers,
            "body_text": body_text,
            "body_html": body_html,
            "attachments": attachments,
            "has_private_ips": has_private_ips
        }
    
    def _html_to_text(self, html_content):
        """Convert HTML content to plain text."""
        if not html_content:
            return ""
            
        try:
            # Parse HTML and remove scripts and styles
            soup = BeautifulSoup(html_content, 'html.parser')
            for script_or_style in soup(["script", "style"]):
                script_or_style.extract()
                
            # Get text content
            text = soup.get_text()
            
            # Remove extra whitespace
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = '\n'.join(chunk for chunk in chunks if chunk)
            
            return text
        except Exception:
            # Fallback to simple HTML tag removal if BeautifulSoup fails
            text = re.sub(r'<[^>]+>', ' ', html_content)
            return re.sub(r'\s+', ' ', text).strip()
    
    def _defang_urls(self, text):
        """Replace dots in URLs with [.] to prevent accidental clicking."""
        if not text:
            return ""
            
        # Simple URL regex pattern
        url_pattern = r'https?://[\w\.-]+'
        
        def replace_dots(match):
            url = match.group(0)
            return url.replace('.', '[.]')
            
        return re.sub(url_pattern, replace_dots, text)
    
    def _check_for_private_ips(self, text):
        """Check if the text contains any private IP addresses."""
        if not text:
            return False
            
        # IP address pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for match in re.finditer(ip_pattern, text):
            ip_str = match.group(0)
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private:
                    return True
            except ValueError:
                continue
                
        return False
    
    def get_attachment_risk_level(self, attachment):
        """Determine the risk level of an attachment based on its type.
        
        Returns:
            str: 'high', 'medium', or 'low'
        """
        filename = attachment.get("filename", "").lower()
        mime_type = attachment.get("mime_type", "").lower()
        
        # High risk extensions and MIME types
        high_risk_exts = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi", ".jar"]
        high_risk_mimes = ["application/x-msdownload", "application/x-executable", "application/x-dosexec"]
        
        # Medium risk extensions and MIME types (may contain macros or scripts)
        medium_risk_exts = [".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".zip", ".rar", ".7z", ".html", ".htm"]
        medium_risk_mimes = ["application/vnd.ms-excel.sheet.macroEnabled", "application/vnd.ms-word.document.macroEnabled", 
                            "application/vnd.ms-powerpoint.presentation.macroEnabled", "application/zip", "application/x-rar-compressed",
                            "application/x-7z-compressed", "text/html"]
        
        # Check extension
        for ext in high_risk_exts:
            if filename.endswith(ext):
                return "high"
                
        for ext in medium_risk_exts:
            if filename.endswith(ext):
                return "medium"
        
        # Check MIME type
        if any(mime in mime_type for mime in high_risk_mimes):
            return "high"
            
        if any(mime in mime_type for mime in medium_risk_mimes):
            return "medium"
        
        # Default to low risk
        return "low"