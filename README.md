
# 🛡️ Hybrid AI Spam Filter

This is a hybrid email spam filtering system I developed to explore the practical applications of advanced data structures and Generative AI. The project accurately classifies emails and manages sender domain reputations by combining algorithmic efficiency with semantic analysis.

For this project, I integrated the **O(1) lookup speed of Bloom Filters**, the **balanced O(log n) operations of Red-Black Trees**, and the **contextual understanding of Google's Gemini AI** to create a robust, multi-layered defense against spam and phishing.

---

# 🚀 Project Features

## ⚡ Fast Keyword Pre-check (Bloom Filter)
I implemented a custom **Bloom Filter** using multiple hash functions (**Murmur, FNV, DJB2, SDBM**) to detect known spam keywords in **O(1)** time.  
This acts as a fast first-pass filter and helps save unnecessary AI API calls.

## 🌳 Domain Reputation Tracking (Red-Black Tree)
I built a **Red-Black Tree from scratch** to manage sender trust scores.  
This guarantees **O(log n)** performance for:

- Tracking domain reputation
- Updating trust scores
- Querying sender domains

This keeps the system efficient even as the dataset grows.

## 🧠 Smart AI Analysis (Google Gemini)
I integrated the **gemini-2.5-flash API** to semantically analyze the email **subject** and **body** whenever algorithmic checks require deeper context.

## 🌐 Web Interface & API
I created a **Flask-based web application** that provides REST endpoints to:

- Check emails
- Report spam
- Whitelist domains
- View live tree structures
- Access system statistics

## 💾 Data Persistence
I implemented file handling to automatically save:

- Red-Black Tree states
- Blacklists
- Domain reputation scores

These are stored in **JSON and TXT files** when the server shuts down, allowing the system to preserve historical trust scores across restarts.

## 📊 Advanced Analytics
The system generates detailed analytics including:

- Tree balance metrics
- Bloom filter capacity usage
- Top spam domains
- Top trusted domains

These analytics help monitor system performance.

---

# 🏗️ System Architecture

## Layer 1: Bloom Filter (`bloom_filter.py`)
Scans incoming text against thousands of known spam phrases.

If the spam score is definitively high based on keyword matches, it directly influences the final classification.

---

## Layer 2: Gemini AI (`main.py`)
If the Bloom Filter result is uncertain, the email content is passed to **Gemini AI** for contextual reasoning and a nuanced spam score.

Gemini analyzes:

- Email subject
- Email body
- Semantic intent
- Potential phishing patterns

---

## Layer 3: Domain Reputation  
Files: `rbtree_core.py` and `analytics_final.py`

The system extracts the **sender domain** and checks its historical reputation stored in the **Red-Black Tree**.

- Spam reports → decrease reputation score
- Whitelisting → increase reputation score

---

## Final Verdict

The algorithm computes a **weighted average** of:

- **Content Score** (Bloom Filter + Gemini AI)
- **Domain Reputation Score**

This combined score determines whether the email is classified as:

- Spam
- Suspicious
- Safe

---

# ⚙️ Getting Started

## Prerequisites

- Python **3.8+**
- Google **Gemini API Key**

---

# 📦 Installation

## Clone the Repository

```bash
git clone https://github.com/yourusername/Spam_Filter_AI.git
cd Spam_Filter_AI


## Install Dependencies

```bash
pip install flask python-dotenv google-genai
```

## Set Up Environment Variables

Create a `.env` file in the root directory and add your Gemini API key:

```env
GEMINI_API_KEY=your_api_key_here
```

⚠️ Make sure to add `.env` to your **.gitignore** so your API key is not exposed.

---

# 💻 Usage

## Running the Web Application

Launch the Flask web interface:

```bash
python app.py
```

The web application will be available at:

```
http://127.0.0.1:5000
```

Domain reputation data is automatically saved to:

```
domain_reputation.json
```

when the server is terminated safely.

---

## Running the CLI Demo

You can also execute the spam filter directly from the terminal:

```bash
python main.py
```

This runs the core filtering logic and demonstrates the system without the web interface.

---

# 🔌 API Endpoints

### Check Email

```
POST /check_email
```

Request body:

```json
{
  "sender": "example@email.com",
  "subject": "Limited time offer",
  "body": "Click this link to claim your reward"
}
```

Returns a detailed spam analysis.

---

### Report Spam

```
POST /report_spam
```

Reports an email/domain and decreases its reputation score.

---

### Whitelist Domain

```
POST /whitelist
```

Boosts the reputation score of a trusted domain.

---

### System Statistics

```
GET /statistics
```

Returns:

* Bloom filter efficiency
* Keyword hit counts
* Top spam domains
* Top trusted domains

---

### Tree Structure

```
GET /tree_structure
```

Returns the current **Red-Black Tree structure** and balance information.

---

# 📂 Project Structure

```
Spam_Filter_AI/
│
├── app.py
├── main.py
│
├── bloom_filter.py
├── bloom_application.py
│
├── rbtree_core.py
├── analytics_final.py
│
├── spam_keywords.txt
├── domain_reputation.json
│
└── README.md
```

### File Descriptions

| File                     | Description                          |
| ------------------------ | ------------------------------------ |
| `app.py`                 | Flask web server and API routes      |
| `main.py`                | Core spam filtering orchestrator     |
| `bloom_filter.py`        | Bloom Filter implementation          |
| `bloom_application.py`   | Keyword detection logic              |
| `rbtree_core.py`         | Red-Black Tree implementation        |
| `analytics_final.py`     | Tree analytics and statistics        |
| `spam_keywords.txt`      | Dataset of spam keywords             |
| `domain_reputation.json` | Persistent domain reputation storage |

```
```
