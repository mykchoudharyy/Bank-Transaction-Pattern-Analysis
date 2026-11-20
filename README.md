# Banking Transaction Pattern Analysis

A secure, multi-bank analytics workspace built with **Python, SQLite, Pandas, Plotly and Streamlit**. Bank staff sign in to their own bank's workspace, explore payment patterns, catch suspicious transactions, onboard customers and post live payments, all backed by a normalised SQLite database.

**Live demo:** https://bank-txn.streamlit.app

> Transaction data in this repository is synthetic. No real customer or bank data is used.

---

## Why this project

Retail banks process lakhs of payments a day across UPI, cards, NEFT and more. Analysts need to answer questions such as:

- Which channel carries the most value, and which one fails the most?
- At what hour of the day do payments fail or load peak?
- How do spending habits differ by city tier, account type and age group?
- Which transactions look unusual and need a human review?

This project answers those questions in one place and also demonstrates the full operational flow behind them: onboarding, payments, fraud review and auditing.

---

## Features

### Security
- Staff registration requires a **bank authorization key**, so outsiders cannot create accounts
- Passwords hashed with **PBKDF2-SHA256** (200,000 rounds, random salt per user); older SHA-256 hashes upgrade automatically on login
- **Account lockout**: 5 wrong passwords lock the account for 5 minutes
- **Session timeout** after 15 minutes of inactivity
- Strong password policy (8+ characters, upper, lower, number, special character)
- **Bank-level data isolation**: an analyst only ever sees their own bank's transactions
- **Audit log** of every sign-in, payment, customer action, review and export

### Analytics (9 workspace tabs)
| Tab | What it shows |
|---|---|
| Overview | KPIs with month-on-month change, monthly count and volume, 7-day trend, status mix, next-month projection |
| Channels | Volume, value, share and failure rate per channel, channel mix over time |
| Failures | Failure rate by channel and hour, weekday x hour load heatmap, worst cities |
| Spending | Spend by merchant category, city tier, account type, age group, weekday, top customers |
| Fraud alerts | Rule-based detection, risk score, case review (confirmed, false positive, escalated) saved to the database |
| Customers | Add customer, open account with opening deposit, Customer 360 view, searchable directory |
| Payment desk | Post a real payment through authorisation, balance, limit and fraud checks |
| Reports | CSV exports, executive summary, Welch t-test between groups |
| Audit log | Full activity trail for the bank |

Global filters (date range, channel, status) apply across all analytics tabs.

### Fraud detection rules
1. **Unusual amount**: z-score above a configurable threshold within the payment's channel
2. **Large night payment**: amount above the 75th percentile between 00:00 and 04:59
3. **Velocity**: several payments from one account within an hour

Each flagged transaction gets a 0-100 risk score (Low, Medium, High).

### Payment workflow
```
Choose account -> enter payment -> re-enter password to authorise
   -> per-payment limit (Rs 10,00,000)
   -> balance check (debits)
   -> daily debit limit (Rs 5,00,000)
   -> fraud screening
   -> write to ledger -> receipt -> all dashboards update
```
Rejected payments are still recorded with status `Failed`, as in a real ledger. Risky but successful payments are queued automatically in **Fraud alerts**.

### Customer onboarding workflow
```
Add customer (name is masked for privacy) -> open account + opening deposit
   -> account appears in Payment desk -> view in Customer 360
```

---

## Tech stack

| Layer | Tools |
|---|---|
| Language | Python 3.10+ |
| UI | Streamlit, custom CSS |
| Charts | Plotly Express |
| Data | Pandas, NumPy |
| Statistics | SciPy (Welch t-test) |
| Database | SQLite (normalised schema) |

---

## Database schema

```
customers (customer_id PK, masked_name, age_band, city, city_tier)
accounts  (account_id PK, customer_id FK, account_type, ...)
merchants (merchant_id PK, merchant_name, category)
transactions (txn_id PK, account_id FK, merchant_id FK, bank_name,
              timestamp, txn_type, channel, amount, status, city, balance_after)

users          (username PK, full_name, bank_name, password_hash,
                failed_attempts, locked_until, last_login)
audit_log      (id PK, ts, username, bank_name, action, detail)
alert_reviews  (txn_id PK, bank_name, status, note, reviewer, ts)
```

The four business tables are normalised and joined at query time. The last three tables are created automatically by the app on first run.

---

## Getting started

```bash
# 1. Clone
git clone https://github.com/mykchoudharyy/Bank-Transaction-Pattern-Analysis.git
cd Bank-Transaction-Pattern-Analysis

# 2. Create a virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Run
streamlit run app.py
```

The app opens at `http://localhost:8501`.

### First use
1. Open **Create staff account**
2. Pick a bank and enter its authorization key (demo keys below)
3. Choose a username and a strong password, for example `Demo@2026`
4. Switch to **Sign in** and log in with the same bank

**Demo bank keys**

| Bank | Key |
|---|---|
| HDFC Bank | `HDFC-2026` |
| State Bank of India | `SBI-2026` |
| ICICI Bank | `ICICI-2026` |
| Punjab National Bank | `PNB-2026` |
| Axis Bank | `AXIS-2026` |

To override a key, set an environment variable such as `BANK_KEY_HDFC_BANK` or `BANK_KEY_STATE_BANK_OF_INDIA` before starting the app.

---

## Project structure

```
.
├── app.py                 # Streamlit application (auth, analytics, payments, customers)
├── seed_db.py             # Script that generates the synthetic data
├── bank_transactions.db   # SQLite database with synthetic data
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## Try this walkthrough

1. Sign in and review **Overview** and **Failures**
2. In **Customers**, add a customer and open an account with a deposit
3. In **Payment desk**, post a normal payment, then a very large one
4. Open **Fraud alerts**, find the large payment and record a decision
5. Check **Audit log** to see every step recorded

Verify persistence directly in SQLite:

```sql
SELECT COUNT(*) FROM transactions;
SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 1;
```

---

## Limitations and future scope

- SQLite suits a single-user project; move to PostgreSQL or MySQL for production
- Fraud detection is rule-based; Isolation Forest or gradient-boosted models could improve it
- Add role-based access (admin and analyst), email alerts and real-time streaming ingestion
- Add automated tests and a CI pipeline

---

## Author

**Mayank Choudhary**

## License

Released under the MIT License. See `LICENSE`.
