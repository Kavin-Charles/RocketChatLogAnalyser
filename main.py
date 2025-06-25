import re
import torch
import pandas as pd
from pathlib import Path
from transformers import pipeline
from datasets import Dataset
from concurrent.futures import ThreadPoolExecutor
from typing import List
import requests

device = 0 if torch.cuda.is_available() else -1

classifier = pipeline(
    "zero-shot-classification",
    model="facebook/bart-large-mnli",
    device=device
)

def upload_to_pasters(text: str) -> str:
    try:
        response = requests.post("https://paste.rs", data=text.encode('utf-8'), timeout=10)
        if response.ok:
            return response.text.strip()
        else:
            return ""
    except Exception:
        return ""

LABELS = ["normal", "error", "warning", "info", "security"]
THRESHOLD = 0.6
BATCH_SIZE = 32
EXCEL_PATH = "anomalies.xlsx"
KEYWORDS = re.compile(r"(error|fail|missing|exception|unauthorized|denied|invalid|crash)", re.IGNORECASE)

def is_suspicious(line: str) -> bool:
    return bool(KEYWORDS.search(line))

def extract_date(filename):
    match = re.match(r"(\d{4}-\d{2}-\d{2})", filename)
    return match.group(1) if match else "unknown"

def normalize_to_txt(file_path: Path, target_root: Path) -> Path | None:
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as src:
            content = src.read()
        relative = file_path.relative_to(file_path.parents[1])
        txt_name = file_path.name + ".txt"
        target_path = (target_root / relative.parent / txt_name)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if target_path.exists() else "w"

        with target_path.open(mode, encoding="utf-8") as dst:
            dst.write(content)
        return target_path
    except Exception:
        return None

def parallel_filter_lines(lines: List[str]):
    results = []

    def check(index_line):
        i, line = index_line
        return {"line_num": i, "text": line.strip()} if is_suspicious(line) else None

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(check, (i, line)) for i, line in enumerate(lines, 1)]
        for future in futures:
            res = future.result()
            if res:
                results.append(res)

    return results

def classify_lines_with_datasets(entries: List[dict]) -> List[dict]:
    dataset = Dataset.from_list(entries)

    def classify(batch):
        results = classifier(batch["text"], candidate_labels=LABELS)
        return {
            "label": [r["labels"][0] for r in results],
            "score": [round(r["scores"][0], 3) for r in results]
        }

    classified = dataset.map(classify, batched=True, batch_size=BATCH_SIZE)
    return classified.to_dict()

def extract_payload(start_index, fsr_ids, all_lines, is_api_failure):
    payload_lines = []
    s3_error = False
    look_above = False
    for offset in range(start_index, min(start_index + 10, len(all_lines))):
        line = all_lines[offset].lower()
        if "s3" in line and "status" in line and "403" in line:
            s3_error = True
            look_above = True
            break

    if is_api_failure or look_above:
        for offset in range(start_index - 1, max(0, start_index - 20), -1):
            line = all_lines[offset].strip()
            if any(kw in line.lower() for kw in ["payload", "request", "params", "data", "body", "{", "}"]):
                payload_lines.insert(0, line)
                if "}}" in line or "}}}" in line:
                    break
            elif payload_lines:
                break
    else:
        for offset in range(start_index + 1, min(start_index + 10, len(all_lines))):
            line = all_lines[offset].strip()
            if any(kw in line.lower() for kw in ["payload", "request", "params", "data", "body", "{", "}"]):
                payload_lines.append(line)
                if "}}" in line or "}}}" in line:
                    break
            elif payload_lines:
                break

    joined = "\n".join(payload_lines).lower()
    if any(fsr in joined for fsr in fsr_ids):
        return "\n".join(payload_lines)

    return ""

def extract_exception_payload(exception_lines, all_lines, error_start_idx, window_size=50):
    start_idx = None
    payload_lines = []
    error_text = " ".join(exception_lines).lower()
    is_id_related = '_id' in error_text

    for i in range(error_start_idx, max(0, error_start_idx - window_size), -1):
        line = all_lines[i].strip()
        if '[Object: null prototype]' in line or 'request' in line:
            temp_payload = []
            for j in range(i, min(len(all_lines), i + window_size)):
                temp_line = all_lines[j].rstrip()
                if (
                    j != i and (
                        re.search(r"(Exception|Traceback|Error|errorType|rejectedErrors|at\s)", temp_line) or
                        temp_line.strip() == ''
                    )
                ):
                    break
                temp_payload.append(temp_line)

            block_text = "\n".join(temp_payload).lower()

            if is_id_related and '_id' in block_text:
                return "\n".join(temp_payload)

            if not is_id_related and (
                any(k in block_text for k in ["to:", "from:", "subject", "body"]) and "false" in block_text
            ):
                return "\n".join(temp_payload)

    return None

def classify_and_filter(classified_data, all_lines):
    output = []
    used_lines = set()

    for entry in zip(
        classified_data["line_num"],
        classified_data["text"],
        classified_data["label"],
        classified_data["score"]
    ):
        line_num, line, label, score = entry
        start_index = line_num - 1

        if start_index in used_lines:
            continue

        error_block = []
        block_line_indices = []

        for j in range(start_index, len(all_lines)):
            line = all_lines[j].rstrip()
            if j != start_index and not (
                line.startswith(" ") or 
                re.match(r"(at |Traceback|File |\s*\.\.\.|^\s+$)", line)
            ):
                break

            if j == start_index and line.strip().startswith(("rejectedErrors:", "Error: Recipient command failed")):
                error_block = []
                break

            error_block.append(line)
            block_line_indices.append(j)

        if not error_block:
            continue

        used_lines.update(block_line_indices)
        full_error_text = "\n".join(error_block)

        if "errorType: 'Meteor.Error'" in full_error_text:
            if not any(k in full_error_text for k in ["Exception", "TypeError", "ReferenceError", "RangeError",
                                                       "SyntaxError", "at ", "errorClass ", "UnhandledPromiseRejection",
                                                       "Traceback", "Error on S3", "ENOTFOUND", "ECONNREFUSED",
                                                       "EAI_AGAIN", "ETIMEDOUT", "error.stack", "ERR!",
                                                       "EHOSTUNREACH", "ECONNRESET", "EPROTO"]):
                continue

        if label in ["error", "warning"] and score >= THRESHOLD:
            fsr_ids = set(re.findall(r"[pc]\d{4}-[a-z]+-\d+", full_error_text.lower()))
            is_api_failure = full_error_text.lower().startswith("api failure")
            is_exception = "exception" in full_error_text.lower() or "traceback" in full_error_text.lower() or "errorclass" in full_error_text.lower()

            if is_exception:
                payload = extract_exception_payload(
                    exception_lines=full_error_text.splitlines(),
                    all_lines=all_lines,
                    error_start_idx=start_index
                )
            else:
                payload = extract_payload(start_index, fsr_ids, all_lines, is_api_failure)

            if payload:
                if len(payload) > 3000:
                    paste_url = upload_to_pasters(payload)
                    payload = paste_url if paste_url else "[Payload too long; upload failed]"

            output.append({
                "line_num": line_num,
                "label": label,
                "score": score,
                "line": full_error_text,
                "payload": payload
            })

    return output

def summarize_file(lines):
    summary_lines = [line for line in lines if is_suspicious(line)]
    keywords_found = set(KEYWORDS.findall(' '.join(summary_lines)))
    return f"Total suspicious lines: {len(summary_lines)}. Keywords found: {', '.join(keywords_found)}"

def write_anomalies_to_excel(date, rows, summary, path=EXCEL_PATH):
    df = pd.DataFrame(rows)
    file_exists = Path(path).exists()
    mode = "a" if file_exists else "w"
    writer_args = dict(engine="openpyxl", mode=mode)
    if file_exists:
        writer_args["if_sheet_exists"] = "replace"
    with pd.ExcelWriter(path, **writer_args) as w:
        df.to_excel(w, sheet_name=date, index=False)
        if summary:
            pd.DataFrame([{"summary": summary}]).to_excel(w, sheet_name=f"{date}_summary", index=False)

def analyze_log_file(file_path: Path, original_name: str, original_ext: str):
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
    except Exception:
        return [], ""

    filtered_entries = parallel_filter_lines(all_lines)

    if not filtered_entries:
        return [], ""

    classified_data = classify_lines_with_datasets(filtered_entries)
    anomalies = classify_and_filter(classified_data, all_lines)
    summary = summarize_file(all_lines)

    return anomalies, summary

def analyze_folder(raw_folder="logs", output_folder="normalized", excel_file=EXCEL_PATH):
    input_root = Path(raw_folder)
    output_root = Path(output_folder)
    if not input_root.exists():
        return

    raw_files = [f for f in input_root.rglob("*") if f.is_file()]

    normalized_files = []
    file_map = {}
    for f in raw_files:
        original_name = f.stem
        original_ext = f.suffix
        txt_path = normalize_to_txt(f, output_root)
        if txt_path:
            normalized_files.append(txt_path)
            file_map[txt_path] = (original_name, original_ext)

    for txt_file in normalized_files:
        original_name, original_ext = file_map.get(txt_file, ("unknown", ""))
        date = extract_date(txt_file.name)
        anomalies, summary = analyze_log_file(txt_file, original_name, original_ext)
        if anomalies:
            write_anomalies_to_excel(date, anomalies, summary, excel_file)

if __name__ == "__main__":
    analyze_folder("logs", "normalized")
