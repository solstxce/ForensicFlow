# 🚀 ForensicFlow

![ForensicFlow Banner](https://i.ibb.co/M6YRGky/19199152-1.png)

**ForensicFlow** is a next-generation digital forensics platform that empowers investigators with AI-driven tools for comprehensive digital evidence analysis. It features modules for email forensics, file recovery, hash analysis, and AI-powered crime scene analysis.

---

## ✨ Features

- **Email Analysis Suite**  
  Forensic email investigation with AI-powered anomaly detection.

- **File Recovery Lab**  
  Enterprise-grade file recovery with chain of custody tracking.

- **Hash Analyzer**  
  Generate and verify file & text hashes using multiple algorithms.

- **ForensicFusion**  
  AI-powered crime scene analysis using object detection and smart reporting.

- **User Management**  
  Role-based access control and superuser approval workflows.

- **Credit System**  
  Pay-per-use credits for advanced features, with Razorpay integration.

---

## 📂 Project Structure

```
app.py
deployment.yaml
Dockerfile
one-time.py
requirements.txt
static/
    js/
        auth.js
        dashboard.js
temp/
    recovered/
        <session_id>/
            file1.pdf
            file2.jpg
            ...
templates/
    credit_status.html
    dashboard.html
    ea-dashboard.html
    error.html
    file_recovery.html
    forensic_fusion.html
    hash_analyzer.html
    home.html
    login.html
    register.html
    superuser_approval.html
```

---

## 🚦 Getting Started

### Prerequisites

- Python 3.9+
- MongoDB
- Node.js (optional, for frontend asset management)
- [Razorpay](https://razorpay.com/) account for payment integration

### Installation

1. **Clone the repository**
    ```sh
    git clone https://github.com/yourusername/forensicflow.git
    cd forensicflow
    ```

2. **Install dependencies**
    ```sh
    pip install -r requirements.txt
    ```

3. **Set up MongoDB**  
   Ensure MongoDB is running locally on the default port (`mongodb://localhost:27017/forensicflow`).

4. **Configure Environment Variables**  
   Edit `app.py` to set your `SECRET_KEY`, `JWT_SECRET_KEY`, and `GEMINI_API_KEY`.

5. **Run the Application**
    ```sh
    python app.py
    ```

6. **Access the App**  
   Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 🛠️ Usage

- Register a new account and wait for superuser approval.
- Use the dashboard to access forensic tools.
- Purchase credits for advanced features via the integrated payment system.

---

## 🧑‍💻 Development

- Frontend templates: [`templates/`](templates)
- Static JS files: [`static/js/`](static/js)
- Main backend logic: [`app.py`](app.py)

---

## 📑 Research Paper

> **Forensic Flow: A Detailed Crime Scene Detection and Analysis Using Machine Learning**  
> *K. Venkatesh, K. V. H. K. Chowdary, M. K. Sairam, M. S. S. R. K. Reddy and M. A. Kumar*  
> 2025 International Conference on Computational Robotics, Testing and Engineering Evaluation (ICCRTEE), Virudhunagar, India, 2025, pp. 1-5.  
> [IEEE Xplore Link](https://ieeexplore.ieee.org/document/11053017)  
> DOI: [10.1109/ICCRTEE64519.2025.11053017](https://doi.org/10.1109/ICCRTEE64519.2025.11053017)

**Keywords:**  
Industries, YOLO, Technological innovation, Visualization, Accuracy, Forensics, Digital forensics, Machine learning, Reliability, Object recognition, Machine Learning Forensics, YOLO Object Detection, Automated Crime Scene Analysis, Digital Evidence Processing, Forensic Image Recognition, Criminal Investigation Technology, ForensicFlow Integration, Realtime Evidence Detection, Computer Vision in Forensics, Automated Forensic Reporting, Infrastructure, Industry and Innovation, Peace, Justice and Strong Institutions

---

## 📄 License

This project is for educational and research purposes only.

---

<p align="center">
  <b>© 2024 ForensicFlow. All rights reserved.</b>
</p>