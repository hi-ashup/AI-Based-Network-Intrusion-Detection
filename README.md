# 🛡️ AI-Based Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![AI Model](https://img.shields.io/badge/AI-Groq%20Llama3-purple)
![License](https://img.shields.io/badge/License-MIT-green)

A professional-grade cybersecurity dashboard that leverages Machine Learning (Random Forest) for real-time packet filtering and Generative AI (LLMs) for automated forensic reporting.

## 📖 Overview
Traditional firewalls provide alerts, but this system provides **answers**. 
By training on the CIC-IDS2017 dataset, the engine classifies traffic with high accuracy (98%+). Suspicious (or safe) packets are then analyzed by the **Groq Llama 3 AI**, which explains the "Why" behind the classification in a generated text report.

## 🚀 Key Features
*   **Hybrid Analysis:** Speed of ML + Reasoning of LLMs.
*   **Live Injection Module:** Simulate specific attack parameters (DDoS intensity, short durations) to test detection capabilities.
*   **Forensic Dashboard:** A high-contrast "Dark Mode" console featuring syntax-highlighted AI reports (Neon Green data points).
*   **Visual Diagnostics:** Real-time Confusion Matrix with a built-in guide for interpretation.
*   **Professional Reporting:** Generates a multi-page **PDF Audit Report** containing:
    *   System Metrics & Threat Counts.
    *   Confusion Matrix Visualization.
    *   Complete Session Event Logs (Terminal Dump).

## 🛠️ Installation & Usage

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/YOUR_USERNAME/AI-NIDS.git
    cd AI-NIDS
    ```

2.  **Install Requirements**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the System**
    ```bash
    python src/main.py
    ```

## 📊 How to Operate
1.  **API Key:** Enter a free [Groq API Key](https://console.groq.com/keys) in the configuration panel.
2.  **Initialize:** Load data (Simulated or Real CSV) and click "INITIALIZE" to train the model.
3.  **Simulate Attack:** Go to "Live Packet Stimulation". Enter aggressive values (e.g., Duration: 50ms, Packets: 500) and click **INJECT**.
4.  **Read Analysis:** The Dashboard will update with a forensic breakdown.
5.  **Export:** Click "PDF REPORT" to save a comprehensive audit file.

## 📜 Technology Stack
*   **Core:** Python 3.12, Tkinter (GUI)
*   **Machine Learning:** Scikit-Learn (Random Forest)
*   **GenAI:** Groq Cloud API (Llama-3-70b-Versatile)
*   **Visualization:** Matplotlib, Seaborn
*   **Reporting:** Matplotlib Backend PDF

## ⚖️ License
MIT Open Source License.