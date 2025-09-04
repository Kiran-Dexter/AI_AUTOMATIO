#!/usr/bin/env python3
"""
Damien Data Query Engine v2.1
=================================
A hacker-themed interactive query engine for CSV/XLS/XLSX files.
## pip install pandas tabulate fuzzywuzzy openpyxl ##
Features:
- Search across all columns
- Supports AND / OR logic (default interactive)
- Optional NOT and XOR filters
- Regex + fuzzy matching
- TOP-N patterns per column with frequency counts
- Export search results to Excel (.xlsx)
"""

import pandas as pd
from tabulate import tabulate
from fuzzywuzzy import fuzz, process
import os, sys, re, time, random, datetime

# ====== COLORS ======
GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
RESET = "\033[0m"

# ====== UTILS ======
def hacker_print(text, color=GREEN, delay=0.01):
    """Print text with hacker-style typing effect"""
    for char in text:
        sys.stdout.write(color + char + RESET)
        sys.stdout.flush()
        time.sleep(delay * random.uniform(0.8, 1.2))  # random jitter
    print("")

def progress_bar(task="Loading", steps=20, delay=0.05):
    """Fake hacker-style progress bar"""
    sys.stdout.write(CYAN + f"{task}: [" + RESET)
    sys.stdout.flush()
    for i in range(steps):
        sys.stdout.write(GREEN + "#" + RESET)
        sys.stdout.flush()
        time.sleep(delay * random.uniform(0.8, 1.3))
    sys.stdout.write(CYAN + "] DONE\n" + RESET)

def banner():
    hacker_print(r"""
        \m/  EVIL HORN  \m/
    """, RED, delay=0.005)

# ====== CORE ======
def build_patterns(df, top_n=10):
    """Build column-wise TOP-N unique values with frequency counts"""
    patterns = {}
    for col in df.columns:
        try:
            value_counts = df[col].astype(str).value_counts().head(top_n)
            patterns[col] = value_counts
        except Exception:
            continue
    return patterns

def search_engine(df, query, mode="or", regex=False, fuzzy=False, not_term=None, xor_term=None):
    """Search engine core with AND/OR/NOT/XOR/regex/fuzzy support"""
    if not query:
        hacker_print("⚠️ Empty query. Please enter a valid keyword/regex.", RED)
        return

    try:
        if regex:
            mask = df.apply(lambda row: row.astype(str).str.contains(query, regex=True, case=False, na=False)).any(axis=1)
        elif fuzzy:
            def fuzzy_row(row):
                for val in row.astype(str):
                    if process.extractOne(query, [val], scorer=fuzz.partial_ratio)[1] >= 80:
                        return True
                return False
            mask = df.apply(fuzzy_row, axis=1)
        else:
            keywords = query.split()
            if mode == "and":
                mask = df.apply(lambda row: all(row.astype(str).str.contains(k, case=False, na=False).any() for k in keywords), axis=1)
            else:
                mask = df.apply(lambda row: any(row.astype(str).str.contains(k, case=False, na=False).any() for k in keywords), axis=1)

        results = df[mask]

        if not_term:
            results = results[~results.apply(lambda row: row.astype(str).str.contains(not_term, case=False, na=False)).any(axis=1)]

        if xor_term:
            xor_mask = results.apply(lambda row: (
                row.astype(str).str.contains(query, case=False, na=False).any() ^
                row.astype(str).str.contains(xor_term, case=False, na=False).any()
            ), axis=1)
            results = results[xor_mask]

        if results.empty:
            hacker_print(f"\n❌ No matches found for '{query}'.", RED)
        else:
            hacker_print("\n✅ Results:\n", GREEN)
            print(tabulate(results, headers="keys", tablefmt="fancy_grid", showindex=False))

            # Export option
            export = input(CYAN + "\n📂 Export results to Excel? [y/N]: " + RESET).strip().lower()
            if export == "y":
                filename = f"Damien_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                try:
                    results.to_excel(filename, index=False)
                    hacker_print(f"💾 Results exported to {filename}", GREEN)
                except Exception as e:
                    hacker_print(f"❌ Failed to export: {e}", RED)

    except re.error as e:
        hacker_print(f"⚠️ Regex error: {e}", RED)
    except Exception as e:
        hacker_print(f"❌ Unexpected error during search: {e}", RED)

# ====== MAIN ======
if __name__ == "__main__":
    banner()
    hacker_print(">> Damien Data Query Engine v2.1", GREEN, delay=0.01)
    hacker_print(">> Damien is ready... your data awaits ⚡", CYAN, delay=0.02)

    file_path = input(CYAN + "📂 Enter file path (CSV/XLS/XLSX): " + RESET).strip()

    if not os.path.exists(file_path):
        hacker_print(f"❌ File not found: {file_path}", RED)
        sys.exit(1)

    ext = os.path.splitext(file_path)[-1].lower()
    try:
        progress_bar("Scanning file system")
        if ext == ".csv":
            df = pd.read_csv(file_path)
        elif ext in [".xls", ".xlsx"]:
            df = pd.read_excel(file_path)
        else:
            hacker_print(f"❌ Unsupported format {ext}", RED)
            sys.exit(1)
        progress_bar("Parsing dataset")
    except Exception as e:
        hacker_print(f"❌ Failed to load file: {e}", RED)
        sys.exit(1)

    top_n_input = input(CYAN + "How many TOP patterns per column to display? (default 10): " + RESET).strip()
    top_n = int(top_n_input) if top_n_input.isdigit() else 10

    patterns = build_patterns(df, top_n=top_n)
    hacker_print(f"\n📊 Suggested patterns (TOP {top_n} per column):", GREEN)

    for col, values in patterns.items():
        hacker_print(f"\n{col}:", CYAN, delay=0.003)
        for val, count in values.items():
            hacker_print(f" - {val} ({count})", GREEN, delay=0.001)

    while True:
        query = input(CYAN + "\n🔍 Enter search (or 'exit'): " + RESET).strip()
        if query.lower() == "exit":
            hacker_print("\nDamien Says Bye...!!!", RED, delay=0.02)
            break

        words = query.split()
        if len(words) > 1:
            mode = input("Combine keywords with BOTH (and) or EITHER (or)? [and/or]: ").strip().lower()
            if mode not in ["and", "or"]:
                mode = "or"
        else:
            mode = "or"

        regex = input("Regex search? [y/N]: ").strip().lower() == "y"
        fuzzy = input("Fuzzy search? [y/N]: ").strip().lower() == "y"

        adv = input("Advanced filter (NOT/XOR)? [y/N]: ").strip().lower()
        not_term, xor_term = None, None
        if adv == "y":
            choice = input("Choose filter [1=NOT, 2=XOR]: ").strip()
            if choice == "1":
                not_term = input("Enter term to exclude (NOT): ").strip()
            elif choice == "2":
                xor_term = input("Enter XOR term: ").strip()

        search_engine(df, query, mode=mode, regex=regex, fuzzy=fuzzy, not_term=not_term, xor_term=xor_term)
