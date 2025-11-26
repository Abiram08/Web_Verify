# 🛡️ WebVerify: Minimalist AI Phishing Detector

**WebGuard** is a powerful, single-file cybersecurity tool designed to detect phishing URLs with high accuracy. It combines three layers of defense into a lightweight Flask application:

1.  **Machine Learning**: Instant pattern-based detection using a pre-trained model.
2.  **VirusTotal Intelligence**: Real-time reputation checks from 70+ security vendors.
3.  **Google Gemini AI**: Heuristic analysis of URL structure, brand impersonation, and social engineering tactics.

---

## ✨ Key Features

*   **🚀 Ultra-Lightweight**: Entire application logic, UI, and ML inference in a **single file** (`app.py`).
*   **🧠 Hybrid Analysis**: Merges static ML analysis with dynamic AI reasoning.
*   **🎨 Modern UI**: Beautiful, dark-themed interface embedded directly in the code.
*   **🔌 Easy Integration**: Simple REST API endpoint (`/predict`) for programmatic use.
*   **🔒 Privacy-Focused**: Runs locally; API keys are stored securely in your environment.

---

## 🛠️ Installation

### Prerequisites
*   Python 3.8+
*   `pip`

### Quick Start

1.  **Clone & Enter**
    ```powershell
    git clone <repository-url>
    cd website-checker
    ```

2.  **Set up Virtual Environment**
    ```powershell
    python -m venv .venv
    # Activate:
    .venv\Scripts\Activate.ps1
    ```

3.  **Install Dependencies**
    ```powershell
    pip install -r requirements.txt
    ```

4.  **Run the App**
    ```powershell
    python app.py
    ```
    The app will automatically open in your browser at `http://127.0.0.1:5000`.

---

## ⚙️ Configuration

To unlock the full power of WebGuard (VirusTotal & Gemini AI), you need to set up your API keys.

Create a `.env` file in the root directory:

```env
# Required for AI Analysis
GEMINI_API_KEY=your_gemini_api_key_here

# Required for Reputation Checks
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

*   **Gemini API Key**: Get it from [Google AI Studio](https://aistudio.google.com/).
*   **VirusTotal API Key**: Get it from [VirusTotal](https://www.virustotal.com/).

> **Note**: If keys are missing, the app will fallback to using only the local Machine Learning model.

---

## 📂 Project Structure

The project has been refactored for absolute minimalism:

```text
📂 website-checker
├── 🐍 app.py             # The Core: Flask App + UI + ML Logic
├── 🧠 model.pkl          # The Brain: Pre-trained Random Forest Model
├── 📜 requirements.txt   # The Fuel: Python dependencies
└── 📄 README.md          # The Guide: You are here
```

---

## ⚠️ Disclaimer

This tool is for educational and defensive purposes only. Always verify suspicious URLs through multiple channels.

---

*Built with 💙 using Flask, Scikit-learn, and Google Gemini.*
