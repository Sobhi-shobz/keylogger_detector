# 🛡️ Advanced Keylogger & Hooking Detector

A Python-based Windows security tool designed to identify active keyloggers and input-monitoring processes using behavioral analysis, native Windows API inspection (`PSAPI`), and heuristic threat scoring.

## 🚀 Features

- **Anti-Hooking Module Inspection:** Interrogates DLL modules loaded in active memory space via Windows Native APIs (`EnumProcessModules`, `GetModuleBaseNameA`).
- **Behavioral Threat Scoring:** Evaluates process characteristics such as windowless background execution, high disk I/O, and active network connectivity.
- **64-bit Pointer Safety:** Handles 64-bit integer pointer buffers safely across memory space.

## 🛠️ Prerequisites

- Windows 10 / 11
- Python 3.10+

## 📥 Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR-USERNAME/keylogger-detector.git](https://github.com/YOUR-USERNAME/keylogger-detector.git)
   cd keylogger-detector
   
##**Create and activate a virtual environment:**

DOS
python -m venv venv
venv\Scripts\activate

**Install dependencies:**

DOS
pip install -r requirements.txt
