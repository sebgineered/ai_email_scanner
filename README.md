# AI Email Security Scanner

A Streamlit-based web app that scans email content for prompt injection vulnerabilities and malicious URLs using:

- [Lakera](https://lakera.ai) — AI security vulnerability scanner
- [Cohere](https://cohere.com) — for intelligent URL extraction
- [VirusTotal](https://www.virustotal.com) — to detect malicious links

**▶️ [Try the deployed app here](https://aiemailscanner.streamlit.app/)**

This tool is ideal for red teamers, AI engineers, and security analysts looking to audit LLM-based inputs in a structured and user-friendly way.

---

## Features

- Check for **prompt injection risks** using Lakera Guard API (shows only flagged/unflagged status)
- Extract **URLs from unstructured email text** using Cohere's LLM (or regex fallback)
- Scan URLs for malware and phishing via VirusTotal, with rich per-link details and color-coded results
- Clean, readable **Streamlit UI** for fast feedback
- Example malicious email available via opt-in checkbox

---

## Incoming Features

- **Attachment Scanning**[^1]

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
│   ├── extract_urls_with_cohere.py
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

- Paste or type email content into the text area.
- Optionally, tick the checkbox to auto-populate an example malicious email.
- Click **Scan Email** to analyze for prompt injection and malicious URLs.
- Results are color-coded and links are disabled if found malicious.

---

## Deployment

This app is fully compatible with [Streamlit Community Cloud](https://streamlit.io/cloud):

- Make sure `frontend/streamlit_app.py` is the entry point
- Add your secrets in the **Streamlit deploy settings**

---

## Example Use Case

> Paste a suspicious email into the app and see:
> - Prompt injection flagged status (no risk score, just flagged/unflagged)
> - Extracted links
> - VirusTotal threat detection results for each URL, with color-coded and clickable/disabled links
> 
---

## Security & Testing

- All API keys are loaded from environment variables or Streamlit secrets.
- The app disables clickable links for malicious URLs and obfuscates them.
- [Semgrep](https://semgrep.dev/)
