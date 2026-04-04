import csv
import json
import io
import re
from pathlib import Path
from langchain.chat_models import init_chat_model


model = init_chat_model('mistral-small-2603')


def clean_json(text: str) -> str:
    # remove ```json ``` or ``` ```
    return re.sub(r"^```(?:json)?\n|\n```$", "", text.strip())


def fix_invalid_escapes(text: str) -> str:
    # Replace single backslashes not part of valid escape sequences
    return re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)


def parse_cwe_csv(source, output_path=None):
    """
    Parse a CWE CSV file (or string) into clean, structured JSON.

    Args:
        source (str | Path): Path to a .csv file, or raw CSV string.
        output_path (str | Path, optional): If provided, saves JSON to this path.

    Returns:
        list[dict]: List of cleaned CWE entries.

    Example:
        entries = parse_cwe_csv("cwe_data.csv", output_path="cwe_data.json")
        entries = parse_cwe_csv(raw_csv_string)
    """
    if isinstance(source, (str, Path)) and Path(source).exists():
        text = Path(source).read_text(encoding="utf-8")
    else:
        text = source

    reader = csv.DictReader(io.StringIO(text))
    entries = [_parse_row(row) for row in reader]

    if output_path:
        Path(output_path).write_text(json.dumps(entries, indent=2), encoding="utf-8")
        print(f"Saved {len(entries)} entries to {output_path}")

    return entries


def _parse_row(row):
    """Convert a single CSV row dict into a clean CWE entry."""
    description_raw = row["Description"].strip()
    extended_description_raw = row["Extended Description"].strip() or None
    potential_mitigations_raw = _parse_mitigations(row["Potential Mitigations"])

    resposne = model.invoke(f"""
        You are a cybersecurity expert.

        Given a CWE entry, generate fields for a knowledge base.

        Return STRICT JSON with:
        - description: one clear human-readable sentence explaining the issue
        - embedding_text: lowercase keywords/phrases for semantic search (no punctuation)
        - mitigations: 2-4 short actionable fixes as a JSON array of strings

        Rules:
        - Use concrete technical terms (user input, SQL query, HTML, file system, etc.)
        - Focus on how the vulnerability appears in code
        - Do NOT include CWE ID
        - Do NOT include explanations outside JSON
        - Do NOT return code blocks (no ```)

        Input:
        Description: {description_raw}
        Extended Description: {extended_description_raw}
        Potential Mitigations: {potential_mitigations_raw}

        Output:
        {{
        "description": "...",
        "embedding_text": "...",
        "mitigations": ["...", "..."]
        }}
    """)
    cleaned_text = clean_json(resposne.content)
    cleaned_text = fix_invalid_escapes(cleaned_text)

    try:
        cleaned_text = json.loads(cleaned_text)
    except json.JSONDecodeError as e:
        print("RAW OUTPUT:\n", cleaned_text)
        raise e
    if isinstance(cleaned_text["mitigations"], str):
        cleaned_text["mitigations"] = [
            m.strip() for m in cleaned_text["mitigations"].split(",")
        ]
    entry = {
        "id": f"CWE-{row['CWE-ID']}",
        "name": row["Name"].strip(),
        "embedding_text": cleaned_text['embedding_text'],
        "description": description_raw,
        "potential_mitigations": cleaned_text['mitigations'],
    }
    return {k: v for k, v in entry.items() if v not in (None, [], "")}
    

def _split_blocks(raw):
    """Split a ::KEY:VALUE:: encoded string into non-empty segments."""
    return [p for p in raw.split("::") if p.strip()]


def _parse_mitigations(raw):
    """Parse potential mitigations into [{phase, strategy?, description, effectiveness?}]."""
    items, current = [], {}
    for part in _split_blocks(raw):
        kv = part.split(":", 1)
        if len(kv) != 2:
            continue
        key, val = kv[0].strip(), kv[1].strip()
        if key == "PHASE":
            if current:
                items.append(current)
            current = {"phase": val}
        elif key == "STRATEGY" and current:
            current["strategy"] = val
        elif key == "DESCRIPTION" and current:
            current["description"] = val
        elif key == "EFFECTIVENESS" and current:
            current["effectiveness"] = val
    if current:
        items.append(current)
    return items


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cwe_parser.py input.csv [output.json]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else input_path.replace(".csv", ".json")

    results = parse_cwe_csv(input_path, output_path=output_path)
    print(f"Parsed {len(results)} CWE entries.")