# Acme Cloud — Flagsmith A/B Signup Experiment (Toggle Wars)

A production-grade, privacy-first A/B experimentation platform built with **Flask**, **Flagsmith**, and **SQLite**. This project demonstrates how modern engineering and growth teams use feature flags to test onboarding friction, target multivariate variations by identity traits, and track dual-funnel guardrail metrics without leaking personally identifiable information (PII).

---

## 🔬 Project Overview & A/B Hypothesis

In SaaS onboarding, there is a fundamental tension between **top-of-funnel signup velocity** and **sales pipeline qualification depth**:

- **Control (`six_fields`)**: High-friction form collecting **Full Name**, **Work Email**, **Password**, **Company Name**, **Job Role**, and **Phone Number**.
- **Treatment (`three_fields`)**: Frictionless form collecting only **Full Name**, **Work Email**, and **Password**.

### The Core Hypothesis
> *"Reducing the signup form to 3 essential fields will increase top-of-funnel signup conversion rates by >30% without critically degrading qualified enterprise lead volume when paired with trait-based segment routing."*

Using **Flagsmith's server-side multivariate evaluation**, each unique visitor is deterministically assigned to either `six_fields` or `three_fields`. The experiment tracks both the primary conversion event (`signup_completed`) and a guardrail qualification metric (`lead_qualified`).

---

## ✨ Key Features

- **Dynamic Multivariate Evaluation**: Evaluates the `signup_form_type` flag in real time using the official Flagsmith Python SDK.
- **Identity Trait & Segment Targeting**: Automatically inspects email domains to infer the visitor's `account_tier` trait (`enterprise` for corporate domains vs. `self_serve` for consumer webmail like Gmail/Outlook), enabling Flagsmith Segments to dynamically target enterprise prospects.
- **Dual Telemetry & Guardrail Analytics (`/stats`)**:
  - **Primary Metric**: `signup_completed` (tracked in Flagsmith and SQLite).
  - **Guardrail Metric**: `lead_qualified` (triggered when company size and role or enterprise domains are captured).
  - **Statistical Engine**: Real-time two-proportion z-tests computing z-scores, p-values, relative lift (%), and statistical confidence intervals for both signups and lead qualification.
- **Realistic SaaS Traffic Simulator**: Built-in simulator generating realistic SaaS distributions (~22% CR for 6 fields with ~75% qualification vs. ~31% CR for 3 fields with ~35% qualification) plus a one-click reset button for clean live demonstrations.
- **Zero-PII Data Privacy & Hardened Security**:
  - Passwords, names, emails, and phone numbers are **never stored** in SQLite or transmitted to Flagsmith.
  - Visitor IDs are strictly validated against `^[a-zA-Z0-9_-]{1,64}$`.
  - Flask binds strictly to `127.0.0.1` with interactive debugging disabled by default.
  - Session-based CSRF protection on all state-changing endpoints.
  - Strict security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and a hardened `Content-Security-Policy`).
  - Graceful offline fallback: if Flagsmith is unreachable or times out, the app safely defaults to `six_fields` and flags the status as `FALLBACK (Offline Safe)` in the debug panel.
- **Editorial Gallery Aesthetic**: Warm blush-alabaster canvas (`#FAF3EE`), pure white gallery cards with hairline borders (`#E5DCD5`), Playfair Display typography, and a 60fps kinetic pixel-dot canvas animation.

---

## 🛠️ Step-by-Step Flagsmith Configuration

To replicate or link this experiment in your own Flagsmith dashboard:

### 1. Create a Project & Environment
1. Log in to [Flagsmith](https://app.flagsmith.com/).
2. Create a project named **Toggle Wars** (or your organization name).
3. Under your environment (e.g., *Development* or *Production*), go to **Settings** > **Keys** and copy your **Server-Side Environment Key** (starts with `ser.`).

### 2. Configure the Multivariate Flag
1. Navigate to **Features** > **Create Feature**.
2. Set **Feature Name / Key**: `signup_form_type`.
3. Set **Feature Type**: Toggle **Multivariate** ON.
4. Define the variations:
   - **Default Value (Control)**: `six_fields` (Weight: 50%)
   - **Variation 1 (Treatment)**: `three_fields` (Weight: 50%)
5. Save the feature.

### 3. Configure Events / Conversion Goals
1. Under **Analytics** / **Events**, verify tracking is enabled for:
   - `signup_completed` (Primary Conversion)
   - `lead_qualified` (Secondary Guardrail)

### 4. Optional: Segment Rule for Enterprise Users
1. Go to **Segments** > **Create Segment**.
2. Name: `Enterprise Visitors`.
3. Add a condition: `account_tier` EQUALS `enterprise`.
4. In **Features** > `signup_form_type` > **Segment Overrides**, you can override or weight variations specifically for enterprise traffic.

---

## 🚀 Quickstart & Local Installation

### Prerequisites
- Python 3.9+ installed
- Git

### 1. Clone & Set Up Directory
```bash
git clone https://github.com/your-username/toggle-wars-signup.git
cd toggle-wars-signup
```

### 2. Create and Activate Virtual Environment
```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy the example environment file:
```bash
cp .env.example .env
```
Edit `.env` and paste your Flagsmith Server-Side Environment Key:
```env
FLAGSMITH_ENVIRONMENT_KEY=ser.your_actual_key_here
FLASK_SECRET_KEY=generate_a_random_32_char_secret
FLASK_DEBUG=false
PORT=5001
```

### 5. Launch the Application
```bash
python app.py
```
The server will start on [http://127.0.0.1:5001](http://127.0.0.1:5001).

---

## 🧪 Interactive Testing URLs

You can test deterministic multivariate routing, segment targeting, and the stats dashboard directly:

| URL Endpoint | Purpose |
|---|---|
| [http://127.0.0.1:5001/](http://127.0.0.1:5001/) | Default visitor flow (Flagsmith evaluates identity or defaults safely) |
| [http://127.0.0.1:5001/?user_id=user_0](http://127.0.0.1:5001/?user_id=user_0) | Force 3-field treatment variant (`three_fields`) |
| [http://127.0.0.1:5001/?user_id=user_5](http://127.0.0.1:5001/?user_id=user_5) | Force 6-field baseline variant (`six_fields`) |
| [http://127.0.0.1:5001/?user_id=user_corp&email=sarah@stripe.com](http://127.0.0.1:5001/?user_id=user_corp&email=sarah@stripe.com) | Test Enterprise trait targeting (`account_tier=enterprise`) |
| [http://127.0.0.1:5001/?user_id=user_free&email=alex@gmail.com](http://127.0.0.1:5001/?user_id=user_free&email=alex@gmail.com) | Test Self-Serve trait targeting (`account_tier=self_serve`) |
| [http://127.0.0.1:5001/stats](http://127.0.0.1:5001/stats) | Experiment dashboard with z-tests, relative lift, and simulation controls |

---

## 🔒 Security & Privacy Architecture

This codebase is hardened for public demonstrations and security compliance:
- **No PII Stored**: Passwords and contact emails are scrubbed before persistence; only categorical operational indicators are logged.
- **CSRF Protected**: State-changing endpoints require valid session-bound CSRF tokens.
- **Strict Host Binding**: Bound to local loopback `127.0.0.1` to prevent unauthorized network access.
- **Secret Separation**: `.gitignore` strictly blocks all `.env`, `.env.*`, `*.db`, and cache artifacts. A sanitized `.env.example` is provided for setup.

---

## 📂 Project Structure

```
├── app.py                  # Core Flask server, Flagsmith client, stats calculator & security hooks
├── requirements.txt        # Python dependency manifest
├── .env.example            # Safe template for environment variables
├── .gitignore              # Ignores .env, SQLite databases, and virtualenvs
├── README.md               # Project documentation and Flagsmith setup guide
├── static/
│   └── img/
│       ├── logo.png        # Transparent Acme Cloud brand logo
│       └── favicon.png     # Browser tab favicon
└── templates/
    ├── index.html          # Kinetic SaaS signup form with Flagsmith debug badge
    ├── stats.html          # Experimentation analytics dashboard & traffic simulator
    └── success.html        # Post-signup confirmation & telemetry inspection
```

---

## 📜 License

MIT License. Designed for experimentation and growth engineering demonstration.
