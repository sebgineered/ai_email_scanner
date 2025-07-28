# AI Email Security Scanner

A Streamlit-based web app that scans email content for prompt injection vulnerabilities and malicious URLs using:

- [Lakera](https://lakera.ai) — AI security vulnerability scanner
- [Cohere](https://cohere.com) — for intelligent analysis and interpretation
- [VirusTotal](https://www.virustotal.com) — to detect malicious links

**▶️ [Try the deployed app here](https://aiemailscanner.streamlit.app/)**

This tool is ideal for red teamers, AI engineers, security analysts, and anyone looking to audit email security in a structured and user-friendly way with AI-powered insights.

---

## Features

- **🔍 Prompt Injection Detection**: Check for prompt injection risks using Lakera Guard API
- **🔗 URL Extraction**: Extract URLs from email text using enhanced regex patterns (no LLM dependency)
- **🛡️ URL Scanning**: Scan URLs for malware and phishing via VirusTotal with detailed results
- **🤖 AI-Powered Analysis**: Get intelligent interpretations of:
  - Email tone and social engineering tactics
  - Prompt injection security implications
  - URL threat analysis and risk assessment
- **📊 Rich UI**: Clean, color-coded Streamlit interface with actionable insights
- **📧 Demo Mode**: Example malicious email for testing and demonstration

---

## Recent Updates

### v2.0 - AI-Powered Analysis
- **🤖 New CohereInterpreter**: Intelligent analysis of email tone, security implications, and threat context
- **🔗 Enhanced URL Extraction**: Replaced LLM-based extraction with robust regex patterns for better reliability
- **📊 Improved UI**: Added AI-powered analysis section with actionable insights
- **⚡ Better Performance**: Faster URL extraction without API dependencies

### v1.0 - Core Features
- Prompt injection detection with Lakera
- URL scanning with VirusTotal
- Basic Streamlit interface

---

## Incoming Features

- **📎 Attachment Scanning**[^1]: Upload and scan email attachments (PDF, DOCX, etc.) for malware
- **🔗 MCP Integration**: Support for Model Context Protocol servers for enhanced threat intelligence
- **📈 Analytics Dashboard**: Historical scan results and threat trends

---

[^1]: Attachment Scanning will allow users to upload and scan email attachments (PDF, DOCX, etc.) for malware or phishing links. This will integrate with VirusTotal or other file scanning APIs to enhance email security analysis.

---

## Project Structure

```
ai_email_scanner/
├── frontend/                 # Streamlit web UI
│   └── streamlit_app.py
├── backend/                  # Core logic components
│   ├── lakera_checker.py
│   ├── extract_urls_with_urllib.py
│   ├── cohere_interpreter.py
│   └── url_scanner_client.py
├── .env                      # Your secret API keys (not committed)
├── .env.template             # Template for environment setup
├── requirements.txt          # Python dependencies
├── setup_venv.bat            # Windows environment setup script
├── setup_venv.sh             # Linux/macOS setup script
└── README.md
```

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ai_email_scanner.git
cd ai_email_scanner
```

### 2. Create and Activate Virtual Environment

#### On Windows:
```bash
setup_venv.bat
```

#### On macOS/Linux:
```bash
chmod +x setup_venv.sh
./setup_venv.sh
```

---

## Environment Variables

Copy `.env.template` and rename it to `.env`, then fill in your actual API keys:

```env
LAKERA_API_KEY=your_lakera_api_key
COHERE_API_KEY=your_cohere_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

---

## Run the App Manually (If Not Using Script)

```bash
python -m venv .venv
.venv\Scripts\activate          # On Windows
# OR
source .venv/bin/activate       # On Linux/macOS

pip install -r requirements.txt
streamlit run frontend/streamlit_app.py
```

---

## Usage

1. **📝 Input Email**: Paste or type email content into the text area
2. **🧪 Demo Mode**: Optionally, tick the checkbox to auto-populate an example malicious email
3. **🔍 Scan**: Click **Scan Email** to run the complete security analysis
4. **📊 Review Results**: View:
   - Prompt injection detection status
   - AI-powered analysis of email tone and threats
   - Detailed URL scan results with threat scores
   - Color-coded results (red for malicious, green for safe)
5. **🛡️ Take Action**: Links are automatically disabled if found malicious

---

## Deployment

This app is fully compatible with [Streamlit Community Cloud](https://streamlit.io/cloud):

- Make sure `frontend/streamlit_app.py` is the entry point
- Add your secrets in the **Streamlit deploy settings**

---

## Example Use Case

> Paste a suspicious email into the app and see:
> - **🔍 Prompt Injection Detection**: Immediate flagging of potential LLM manipulation attempts
> - **🤖 AI Analysis**: Intelligent interpretation of email tone, urgency, and social engineering tactics
> - **🔗 URL Extraction**: Automatic detection of URLs using enhanced regex patterns
> - **🛡️ Threat Assessment**: Detailed VirusTotal analysis with threat scores and categories
> - **📊 Actionable Insights**: Clear, concise explanations of security implications
> 
---

## Technical Details

### Architecture
- **Backend Pipeline**: Modular design with separate components for each security check
- **URL Extraction**: Enhanced regex patterns handle URLs in code blocks, parentheses, and quotes
- **AI Integration**: Cohere LLM provides intelligent analysis without executing user input
- **API Security**: All external calls use secure API keys from environment variables

### Security Features
- **No Code Execution**: User input is never executed as code
- **Link Safety**: Malicious URLs are automatically disabled and obfuscated
- **API Protection**: Secure handling of all external API calls
- **Input Validation**: Comprehensive validation and sanitization

### Testing
- [Semgrep](https://semgrep.dev/) SAST testing for code quality
- Example malicious email for testing all features
- Comprehensive error handling and graceful degradation
