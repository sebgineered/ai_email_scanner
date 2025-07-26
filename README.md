# AI Email Security Scanner

A Streamlit-based web app that scans email content for prompt injection vulnerabilities and malicious URLs using:

- [SonnyLabs](https://sonnylabs.ai) — AI security vulnerability scanner
- OpenAI GPT-4 — for intelligent URL extraction
- [VirusTotal](https://www.virustotal.com) — to detect malicious links

This tool is ideal for red teamers, AI engineers, and security analysts looking to audit LLM-based inputs in a structured and user-friendly way.

---

## Features

- Check for **prompt injection risks** using SonnyLabs API
- Extract **URLs from unstructured email text** using GPT-4
- Scan URLs for malware and phishing via VirusTotal
- Clean, readable **Streamlit UI** for fast feedback

---

## Project Structure

```
ai_email_scanner/
├── frontend/                 # Streamlit web UI
│   └── app.py
├── backend/                  # Core logic components
│   ├── sonnylabs_checker.py
│   ├── gpt_url_extractor.py
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
OPENAI_API_KEY=your_openai_key
SONNYLABS_API_TOKEN=your_sonnylabs_api_token
SONNYLABS_ANALYSIS_ID=your_analysis_id
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
streamlit run frontend/app.py
```

---

## Deployment

This app is fully compatible with [Streamlit Community Cloud](https://streamlit.io/cloud):

- Make sure `frontend/app.py` is the entry point
- Add your secrets in the **Streamlit deploy settings**
- Add a navigation link to this app in your Hugo website if desired

---

## Example Use Case

> Paste a suspicious email into the app and see:
> - Prompt injection risk score
> - Extracted links
> - VirusTotal threat detection results for each URL

---