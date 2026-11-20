import sqlite3
import numpy as np
from datetime import datetime, timedelta

DB_PATH = "bank_transactions.db"

def generate_dataset(n_customers=1000, n_accounts=1500, n_merchants=200, n_txns=120000, seed=42):
    rng = np.random.default_rng(seed)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.executescript("""
    DROP TABLE IF EXISTS transactions;
    DROP TABLE IF EXISTS accounts;
    DROP TABLE IF EXISTS customers;
    DROP TABLE IF EXISTS merchants;

    CREATE TABLE customers (
        customer_id TEXT PRIMARY KEY,
        masked_name TEXT NOT NULL,
        age_band TEXT NOT NULL,
        city TEXT NOT NULL,
        city_tier TEXT NOT NULL
    );

    CREATE TABLE accounts (
        account_id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL,
        account_type TEXT NOT NULL,
        opening_balance REAL NOT NULL,
        FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
    );

    CREATE TABLE merchants (
        merchant_id TEXT PRIMARY KEY,
        merchant_name TEXT NOT NULL,
        category TEXT NOT NULL
    );

    CREATE TABLE transactions (
        txn_id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        merchant_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        txn_type TEXT NOT NULL,
        channel TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT NOT NULL,
        city TEXT NOT NULL,
        balance_after REAL NOT NULL,
        is_seeded_anomaly INTEGER NOT NULL,
        seeded_reason TEXT,
        FOREIGN KEY (account_id) REFERENCES accounts(account_id),
        FOREIGN KEY (merchant_id) REFERENCES merchants(merchant_id)
    );
    """)

    cities = [
        ("Mumbai", "Tier-1"), ("Delhi NCR", "Tier-1"), ("Bengaluru", "Tier-1"), ("Hyderabad", "Tier-1"),
        ("Pune", "Tier-2"), ("Jaipur", "Tier-2"), ("Lucknow", "Tier-2"), ("Indore", "Tier-2"),
        ("Meerut", "Tier-3"), ("Hapur", "Tier-3"), ("Bareilly", "Tier-3"), ("Kota", "Tier-3")
    ]
    age_bands = ["18-25", "26-35", "36-45", "46-60", "60+"]
    age_probs = [0.22, 0.36, 0.24, 0.13, 0.05]

    cust_rows = []
    for i in range(1, n_customers + 1):
        c_name, c_tier = cities[rng.integers(0, len(cities))]
        cust_rows.append((f"CUST-{i:04d}", f"Customer_{i:04d}", rng.choice(age_bands, p=age_probs), c_name, c_tier))
    cur.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?)", cust_rows)

    acc_types = ["Savings", "Salary", "Current"]
    acc_probs = [0.58, 0.28, 0.14]
    acc_rows, acc_city_map, acc_type_map = [], {}, {}
    cust_city_dict = {r[0]: r[3] for r in cust_rows}

    for i in range(1, n_accounts + 1):
        cid = f"CUST-{rng.integers(1, n_customers + 1):04d}"
        atype = rng.choice(acc_types, p=acc_probs)
        bal = float(np.round(rng.uniform(15000, 350000), 2))
        aid = f"ACC-XXXX-{i:04d}"
        acc_rows.append((aid, cid, atype, bal))
        acc_city_map[aid] = cust_city_dict[cid]
        acc_type_map[aid] = atype
    cur.executemany("INSERT INTO accounts VALUES (?, ?, ?, ?)", acc_rows)

    categories = ["Groceries", "Utilities", "Food & Dining", "Fuel", "E-Commerce", "Travel", "Healthcare", "Rent & Transfers"]
    merch_rows, merch_cat_map = [], {}
    for i in range(1, n_merchants + 1):
        cat = categories[i % len(categories)]
        mid = f"MER-{i:03d}"
        merch_rows.append((mid, f"{cat}_Merchant_{i:03d}", cat))
        merch_cat_map[mid] = cat
    cur.executemany("INSERT INTO merchants VALUES (?, ?, ?)", merch_rows)

    start_dt = datetime(2025, 11, 1)
    channels = ["UPI", "Debit Card", "Credit Card", "NEFT", "IMPS", "Net Banking", "ATM", "RTGS"]
    ch_probs = [0.46, 0.16, 0.12, 0.08, 0.07, 0.05, 0.04, 0.02]

    acc_ids = [r[0] for r in acc_rows]
    merch_ids = [r[0] for r in merch_rows]

    chosen_accs = rng.choice(acc_ids, size=n_txns)
    chosen_merchs = rng.choice(merch_ids, size=n_txns)
    chosen_channels = rng.choice(channels, size=n_txns, p=ch_probs)
    day_offsets = rng.integers(0, 365, size=n_txns)

    hour_weights = np.array([1,1,1,1,1,2,3,5,7,9,10,10,9,8,8,8,9,10,11,11,9,6,3,2], dtype=float)
    hour_weights /= hour_weights.sum()
    hours = rng.choice(np.arange(24), size=n_txns, p=hour_weights)
    minutes = rng.integers(0, 60, size=n_txns)
    seconds = rng.integers(0, 60, size=n_txns)

    txn_rows = []
    for i in range(n_txns):
        ts = start_dt + timedelta(days=int(day_offsets[i]), hours=int(hours[i]), minutes=int(minutes[i]), seconds=int(seconds[i]))
        aid, mid, ch = chosen_accs[i], chosen_merchs[i], chosen_channels[i]
        atype, city = acc_type_map[aid], acc_city_map[aid]

        if ch == "UPI":
            amt = float(rng.lognormal(mean=6.3, sigma=0.8))
        elif ch == "RTGS":
            amt = float(rng.uniform(200000, 950000))
        elif ch in ("NEFT", "IMPS", "Net Banking"):
            amt = float(rng.lognormal(mean=8.6, sigma=0.9))
        else:
            amt = float(rng.lognormal(mean=7.4, sigma=0.85))

        if ts.day <= 5:
            amt *= 1.25
        if ts.weekday() >= 5 and merch_cat_map[mid] in ("E-Commerce", "Food & Dining", "Travel"):
            amt *= 1.20
        if atype == "Current":
            amt *= 1.6
        amt = round(max(50.0, amt), 2)

        fail_prob = 0.14 if (1 <= ts.hour <= 4) else 0.035
        r_val = rng.random()
        status = "Failed" if r_val < fail_prob else ("Reversed" if r_val < fail_prob + 0.015 else "Success")
        txn_type = "Credit" if (ts.day <= 3 and ch == "NEFT" and rng.random() < 0.25) else "Debit"
        bal_after = round(float(rng.uniform(5000, 400000)), 2)

        txn_rows.append([
            f"TXN-{i+1:06d}", aid, mid, ts.strftime("%Y-%m-%d %H:%M:%S"),
            txn_type, ch, amt, status, city, bal_after, 0, None
        ])

    anom_indices = rng.choice(n_txns, size=int(n_txns * 0.004), replace=False)
    for idx in anom_indices:
        row = txn_rows[idx]
        if idx % 2 == 0:
            row[6] = round(float(rng.uniform(450000, 1850000)), 2)
            row[10], row[11] = 1, "Extreme Ticket Size Spike"
        else:
            old_ts = datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S").replace(hour=int(rng.integers(2, 4)))
            row[3] = old_ts.strftime("%Y-%m-%d %H:%M:%S")
            row[6] = round(float(rng.uniform(180000, 650000)), 2)
            row[10], row[11] = 1, "Odd-Hour High-Value Deviation"

    cur.executemany("INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", txn_rows)
    conn.commit()
    conn.close()
    print(f"Seeded {n_txns:,} transactions into {DB_PATH}")

if __name__ == "__main__":
    generate_dataset()
