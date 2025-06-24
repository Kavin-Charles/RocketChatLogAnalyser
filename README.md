```
# Log Analyzer with Anomaly Detection & Payload Extraction

This project automates the analysis of log files to identify anomalies, classify suspicious lines, extract relevant payloads, and generate structured Excel reports.

---

## 📁 Project Structure

.
├── logs/          # Input log files (raw)
├── normalized/logs    # Normalized .txt versions of logs
├── main.py        # Main script to run analysis
└── anomalies.xlsx # (Generated) Output Excel report

---

## 🚀 Features

- **Zero-shot classification** (using `facebook/bart-large-mnli`) to tag log lines as:
  - `error`, `warning`, `normal`, `info`, or `security`
- **Keyword-based filtering** for early suspicion detection.
- **Error block grouping** with multi-line context.
- **Paste.rs integration**: Automatically uploads large payloads (> 3000 characters) and includes the link in the Excel report.
- **Grouped by FSR ID** if multiple errors relate to the same identifier.
- **Multi-threaded line filtering** for faster processing.
- **Saves results to `anomalies.xlsx`**, one sheet per date plus a summary.

---

## ▶️ How to Run

1. Place raw log files in the `logs/` folder.
2. Open a terminal in the project directory.
3. Run the script:

```bash
python main.py
```

4. Results will be saved in:
   - `normalized/logs` — contains `.txt` versions of the original files
   - `anomalies.xlsx` — final report with error blocks and payloads

---

## 📦 Requirements

Install the required Python packages:

```bash
pip install -r requirements.txt
```

---

## 📝 Notes

- Make sure your system has a GPU for faster classification (`torch.cuda.is_available()` will automatically use it).
- Paste.rs is used for large payloads — Internet access is required.
- File names should start with a date like `2025-06-24-...` to auto-extract sheet names.

---
```
