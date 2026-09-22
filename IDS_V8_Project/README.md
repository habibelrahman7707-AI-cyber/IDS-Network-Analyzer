# 🛡️ Intrusion Detection System (IDS) V8

A comprehensive Network Traffic Analysis and Intrusion Detection System built with Python. This application features a robust GUI, real-time packet sniffing, and advanced Machine Learning models (RNN, LSTM, GRU) for classifying network anomalies.

## ✨ Features
- **Real-time Packet Sniffing**: Uses Scapy to capture and analyze network traffic in real-time.
- **Advanced Machine Learning**: Integrates Deep Learning models (TensorFlow/Keras) including LSTM and GRU for highly accurate anomaly detection.
- **Interactive GUI**: Built with Tkinter for easy management, model training, and analysis.
- **Reporting System**: Automatically generates PDF reports and supports email alerts for detected intrusions.
- **User Authentication**: Secure SQLite-based user management with role-based access.

## 🚀 Installation

1. **Clone the repository:**
   \\ash
   git clone https://github.com/YOUR_USERNAME/IDS_V8.git
   cd IDS_V8
   \
2. **Install Dependencies:**
   Make sure you have Python 3 installed. Install the required libraries:
   \\ash
   pip install pandas scikit-learn scapy numpy fpdf tensorflow imbalanced-learn
   # Note: Tkinter and SQLite3 are included with standard Python installations.
   \   *(If you are on Windows, ensure Npcap/WinPcap is installed for Scapy to work properly)*

3. **Run the Application:**
   \\ash
   python ids_v8.py
   \
## 📂 Project Structure
- \ids_v8.py\: The main application and GUI entry point.
- \models/\: Contains pre-trained Keras models.
- \data/\: Directory for datasets (PCAP/CSV).
- eports/\: Generated PDF reports are saved here.

## 📝 License
This project is licensed under the MIT License.
