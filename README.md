# API-Based Intelligent Malware Detection FYP

## 📌 Project Overview
Cybersecurity threats are evolving, requiring sophisticated techniques to detect and mitigate potential risks. This project leverages **machine learning (LSTM model)** and **VirusTotal API integration** to automate **malware Detection**. By extracting key features from malware analysis reports and classifying files based on their behavior, this system enhances threat intelligence and provides a user-friendly **GUI for seamless interaction**.

## 🔍 Key Objectives
- **Enhance Cybersecurity Measures**: Automate the Detection of malicious files.
- **Leverage Machine Learning**: Employ an **LSTM-based classification model** to distinguish between malicious and non-malicious files.
- **Integrate with VirusTotal API**: Validate file hashes against VirusTotal's extensive malware database.
- **User-Centric Interface**: Provide an intuitive **GUI for dataset analysis and interaction**.

---

## Features
- **Automated Feature Extraction**: Parses malware analysis reports and structures data for classification.
- **Machine Learning-Based Classification**: Utilizes **LSTM models** to categorize files accurately.
- **VirusTotal API Integration**: Checks file hashes against known malware databases.
- **Interactive GUI**: Enables users to upload files, analyze datasets, and visualize classification results.
- **Scalable & Adaptive**: Designed for future enhancements, supporting real-time malware detection and improved feature engineering.

---

## Setup & Execution Instructions
### **Prerequisites**
Ensure the following dependencies are installed:
```bash
pip install -r requirements.txt
```

### **Steps to Run the Project**
1. **Download the dataset** and open it using Utorrent.
   - **Dataset Link**: [VirusShare_00000.zip.torrent](http://71.105.224.114:6969/torrents/VirusShare_00000.zip.torrent?3B9193870FF50310C54EA415C2F21274A795B76C)
2. **Extract the `FYP Final Script` folder**.
3. **Move the dataset to the `Malware` folder** inside the `destination` directory.
4. **Ensure `destination` and `analyses report 1` folders are inside `FYP Final Script`**.
5. **Update file paths in the code** according to your local system structure.
6. **Execute the script** to perform malware classification.

### **⚠️ Important Notice**
- The original **analysis report** contained **100 files**; due to **GitHub storage constraints**, only **50 files** have been uploaded.

---

## 🔄 Project Workflow
### **1️⃣ Feature Extraction from JSON Reports**
- Parses JSON reports stored in the **`analyses report 1/`** directory.
- Extracts critical metadata including **hash values, severity scores, file size, and execution duration**.
- Converts unstructured data into a **structured CSV dataset (`dataset_file.csv`)** for training and analysis.

#### **📂 Relevant Files**
| File | Description |
|------|------------|
| `analyses report 1/` | Contains malware behavior reports in JSON format |
| `dataset_file.csv` | Processed dataset for machine learning classification |
| `Final_scriptt.py` | Handles feature extraction and dataset processing |

---

### **2️⃣ Malware Hash Matching (VirusTotal API Integration)**
- Compares extracted file hashes with **VirusTotal’s malware database**.
- If a match is found, the file is **flagged as malicious** without further classification.
- If no match is found, the file proceeds to the **LSTM classification model**.

#### **📂 Relevant Files**
| File | Description |
|------|------------|
| `malware_hascode/` | Contains known malware hashes |
| `VTService.py` | Interfaces with VirusTotal API for malware validation |
| `malware_vt_result/` | Stores VirusTotal scan results |

---

### **3️⃣ Deep Learning-Based Malware Classification (LSTM Model)**
- Utilizes **Long Short-Term Memory (LSTM)** neural networks for accurate classification.
- Processes extracted dataset features to distinguish malware from benign files.
- Evaluates model performance using **accuracy, precision, recall, and F1-score**.

#### **📂 Relevant Files**
| File | Description |
|------|------------|
| `dataset_file.csv` | Training dataset for LSTM model |
| `Final_scriptt.py` | Implements the machine learning classification pipeline |

---

### **4️⃣ Interactive GUI for User Interaction**
- Provides an intuitive **graphical user interface (Tkinter)**.
- Enables users to **upload files, run classification, and visualize results**.
- Enhances user experience with **real-time dataset interaction**.

#### **📂 Relevant Files**
| File | Description |
|------|------------|
| `Final_scriptt.py` | Contains Tkinter-based GUI implementation |

---

## 📂 Project Directory Structure
```
📂 analyses report 1
📂 destination
   📂 malware_hascode  
   📂 malware_vt_result
📂 FYP Final Script
   ├── dataset_file.csv
   ├── Final_scriptt.py
   ├── VTService.py
```

---

## 📊 Model Performance Metrics
| Metric  | Score |
|---------|-------|
| Accuracy | 97.5% |
| Precision | 95.2% |
| Recall | 96.8% |
| F1 Score | 96.0% |

---

## Future Enhancements
- **Real-time malware detection system** integration.
- **Enhanced feature selection techniques** for improved classification accuracy.
- **Scalable deep learning models** for dynamic threat analysis.
- **Automated alerts** for detected malware threats.

---

## 👨‍💻 Contributors
- **Nishat Jillani** - Developer

---
