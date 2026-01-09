# 🚗 Contract AI - Car Deal Analyzer

An AI-powered web application that analyzes car lease and loan contracts, providing instant deal scoring, market price comparisons, and intelligent negotiation assistance.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.28+-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 📋 Features

### Core Capabilities

* **🔍 Smart OCR Extraction** - Automatically extracts text from PDF and image contracts
* **📊 Contract Analysis** - Identifies key terms (APR, monthly payment, down payment, lease terms)
* **🚗 VIN Decoding** - Automatically detects and decodes Vehicle Identification Numbers via NHTSA API
* **💰 Real-Time Market Pricing** - Fetches current market values from VehicleDatabases API
* **🎯 Deal Scoring** - Compares contract price vs. market value with color-coded ratings
* **📈 Lease Parity Analysis** - Calculates fair monthly lease payments
* **💬 AI Chat Assistant** - Multi-contract comparison with conversation memory (powered by Groq)
* **📂 Multi-Contract Support** - Upload and compare multiple contracts side-by-side

### Advanced Features

* **Vector Database** - ChromaDB integration for semantic contract search
* **Persistent Storage** - SQLite database for contract history
* **Export Options** - Download extracted text and structured JSON data
* **Responsive UI** - Beautiful glassmorphism design with animated backgrounds

## 🛠️ Technology Stack

| Component                  | Technology                          |
| -------------------------- | ----------------------------------- |
| **Framework**        | Streamlit                           |
| **AI/LLM**           | Groq (Llama 3.3 70B)                |
| **OCR**              | Tesseract / PDF parsing             |
| **Vector DB**        | ChromaDB                            |
| **Database**         | SQLite                              |
| **APIs**             | NHTSA VIN Decoder, VehicleDatabases |
| **Image Processing** | Pillow (PIL)                        |
| **Environment**      | Python-dotenv                       |

## 📁 Project Structure

```
contract-ai/
├── app.py                    # Main Streamlit application
├── ocr.py                    # OCR text extraction logic
├── summarization.py          # AI contract summarization
├── contract_extraction.py    # SLA field extraction
├── vin_lookup.py            # VIN decoding via NHTSA
├── price_estimator.py       # Market price fetching
├── vector_store.py          # ChromaDB operations
├── database.py              # SQLite database management
├── lease_parity.py          # Lease payment calculations
├── fairness_score.py        # Deal scoring logic
├── run_summary.py           # Summary generation utilities
├── test_env.py              # Environment variable testing
├── requirements.txt         # Python dependencies
├── .env                     # API keys (not in repo)
├── .gitignore              # Git ignore rules
├── LICENSE                  # MIT License
├── README.md               # This file
├── assets/
│   └── bg_car.jpg          # Background image
├── chroma_db/              # ChromaDB storage (auto-created)
└── contracts.db            # SQLite database (auto-created)
```

## 🚀 Installation

### Prerequisites

* Python 3.8 or higher
* Tesseract OCR (for image processing)
* Git

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/contract-ai.git
cd contract-ai
```

### Step 2: Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Install Tesseract OCR

**Windows:**

1. Download from [GitHub](https://github.com/UB-Mannheim/tesseract/wiki)
2. Install to `C:\Program Files\Tesseract-OCR`
3. Add to PATH

**macOS:**

```bash
brew install tesseract
```

**Linux:**

```bash
sudo apt-get install tesseract-ocr
```

### Step 5: Configure Environment Variables

Create a `.env` file in the project root:

```env
# Required API Keys
GROQ_API_KEY=gsk_your_groq_api_key_here

# Optional API Keys
VEHICLEDATABASES_API_KEY=your_vehicledatabases_key
MARKETCHECK_API_KEY=your_marketcheck_key

# Tesseract Path (Windows only)
TESSERACT_PATH=C:\Program Files\Tesseract-OCR\tesseract.exe
```

### Step 6: Run Application

```bash
streamlit run app.py
```

The app will open at `http://localhost:8501`

## 🔑 API Keys Setup

### 1. Groq API (Required)

* Sign up at [https://console.groq.com](https://console.groq.com/)
* Create API key
* Add to `.env` as `GROQ_API_KEY`

### 2. VehicleDatabases (Optional)

* Sign up at [https://www.vehicledatabases.com](https://www.vehicledatabases.com/)
* Get API key
* Add to `.env` as `VEHICLEDATABASES_API_KEY`

### 3. MarketCheck (Optional)

* Alternative pricing source
* Add to `.env` as `MARKETCHECK_API_KEY`

## 📖 Usage Guide

### Upload & Analyze Contract

1. **Upload File**
   * Click "Browse files" or drag-and-drop
   * Supports: PDF, PNG, JPG, JPEG
   * Max size: 200MB
2. **Run Analysis**
   * Click "🚀 Run Full Analysis"
   * Wait for OCR, summarization, and pricing
3. **Review Results**
   * **Contract Summary** - AI-generated overview
   * **SLA Fields** - Extracted terms (APR, payments, etc.)
   * **VIN Decode** - Vehicle details
   * **Market Price** - Current market value
   * **Deal Score** - Green/Yellow/Red rating
   * **Lease Parity** - Monthly payment comparison

### Multi-Contract Comparison

1. Upload first contract → Analyze
2. Upload second contract → Analyze
3. Go to chat section
4. Ask: "Compare these two contracts"

### Chat with AI

Ask questions like:

* "What's the APR on this contract?"
* "Is this a good deal?"
* "Compare the monthly payments of both contracts"
* "What fees should I negotiate?"
* "Which contract has better terms?"

## 🎨 UI Features

* **🌈 Animated Gradient Headers** - Eye-catching title animations
* **✨ Glassmorphism Design** - Modern frosted glass effects
* **🔵 Cyan Theme** - Professional blue/cyan color scheme
* **📱 Responsive Layout** - Works on desktop and mobile
* **🎭 Dark Mode** - Comfortable viewing experience
* **⚡ Smooth Animations** - Polished micro-interactions

## 📊 Database Schema

### Contracts Table

```sql
CREATE TABLE contracts (
    id INTEGER PRIMARY KEY,
    filename TEXT,
    created_at TIMESTAMP
)
```

### Contract Data Table

```sql
CREATE TABLE contract_data (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER,
    summary TEXT,
    sla TEXT,
    FOREIGN KEY(contract_id) REFERENCES contracts(id)
)
```

### Chat Messages Table

```sql
CREATE TABLE chat_messages (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER,
    role TEXT,
    message TEXT,
    timestamp TIMESTAMP,
    FOREIGN KEY(contract_id) REFERENCES contracts(id)
)
```

## 🧪 Testing

### Test Environment Setup

```bash
python test_env.py
```

### Manual Testing

1. Use provided Tesla test PDF in `/test_contracts/`
2. Upload and verify all features work
3. Check database entries in `contracts.db`

## 🐛 Troubleshooting

### OCR Not Working

* **Issue:** "Tesseract not found"
* **Solution:** Install Tesseract and set `TESSERACT_PATH` in `.env`

### API Errors

* **Issue:** "GROQ_API_KEY not found"
* **Solution:** Add valid API key to `.env` and restart app

### Database Errors

* **Issue:** "Database locked"
* **Solution:** Close app, delete `contracts.db`, restart

### Pricing Not Loading

* **Issue:** Market price shows "N/A"
* **Solution:** Verify VIN is detected or add API keys

## 🤝 Contributing

Contributions welcome! Please follow these steps:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](https://claude.ai/chat/LICENSE) file for details.

## 🙏 Acknowledgments

* **Groq** - Fast LLM inference
* **Streamlit** - Web framework
* **NHTSA** - Free VIN decoding API
* **VehicleDatabases** - Vehicle pricing data
* **ChromaDB** - Vector database
* **Tesseract** - OCR engine

## 📧 Contact

**Project Maintainer:** Your Name

* 📧 Email: shivas35147@gmail.com
* 🐙 GitHub: https://github.com/golivishiva

## 🗺️ Roadmap

* [ ] Add support for multiple languages
* [ ] Integrate real-time loan calculators
* [ ] Add export to Excel/CSV
* [ ] Support for insurance documents
* [ ] Mobile app version
* [ ] Dealer negotiation tips database
* [ ] Integration with CarFax/AutoCheck
* [ ] Email notifications for deal alerts

## ⭐ Star History

If you find this project helpful, please consider giving it a star on GitHub!

---

**Made with ❤️ using Streamlit and AI**

*Last Updated: January 2025*
