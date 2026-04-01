import json
import re
from datetime import datetime, timezone


INPUT_FILE = "security_news_raw.json"
OUTPUT_FILE = "security_news_processed.json"


ATTACK_TYPE_PATTERNS = [
    ("supply_chain", [
        r"\bsupply chain\b",
        r"\bgithub actions\b",
        r"\bdependency confusion\b",
        r"\bpackage compromise\b",
        r"\btag compromise\b",
        r"\bsoftware supply chain\b"
    ]),
    ("phishing", [
        r"\bphishing\b",
        r"\baitm\b",
        r"\badversary-in-the-middle\b"
    ]),
    ("ransomware", [
        r"\bransomware\b",
        r"\bextortion\b",
        r"\bjackpotting\b"
    ]),
    ("data_breach", [
        r"\bdata breach\b",
        r"\bbreach\b",
        r"\bleak\b",
        r"\bexposed records\b"
    ]),
    ("cve", [
        r"\bcve-\d{4}-\d+\b",
        r"\bzero-day\b",
        r"\bvulnerability\b",
        r"\bexploit\b",
        r"\bpatch\b",
        r"\bprivilege escalation\b"
    ]),
    ("malware", [
        r"\bmalware\b",
        r"\btrojan\b",
        r"\bspyware\b",
        r"\badware\b",
        r"\bbackdoor\b"
    ]),
]


COUNTRY_PATTERNS = {
    "United States": [
        r"\bunited states\b",
        r"\bu\.s\.\b",
        r"\bu\.s\b",
        r"\busa\b",
        r"\bamerican\b",
        r"\bacross the us\b",
        r"\bin the us\b"
    ],
    "United Kingdom": [
        r"\bunited kingdom\b",
        r"\buk\b",
        r"\bbritain\b",
        r"\bbritish\b",
        r"\bengland\b"
    ],
    "Russia": [
        r"\brussia\b",
        r"\brussian\b"
    ],
    "China": [
        r"\bchina\b",
        r"\bchinese\b"
    ],
    "Singapore": [
        r"\bsingapore\b"
    ],
    "Israel": [
        r"\bisrael\b",
        r"\bisraeli\b"
    ],
    "Ukraine": [
        r"\bukraine\b",
        r"\bukrainian\b"
    ],
    "Germany": [
        r"\bgermany\b",
        r"\bgerman\b"
    ],
    "France": [
        r"\bfrance\b",
        r"\bfrench\b"
    ],
    "Netherlands": [
        r"\bnetherlands\b",
        r"\bdutch\b"
    ],
    "Canada": [
        r"\bcanada\b",
        r"\bcanadian\b"
    ],
    "India": [
        r"\bindia\b",
        r"\bindian\b"
    ],
    "Japan": [
        r"\bjapan\b",
        r"\bjapanese\b"
    ],
    "Iran": [
        r"\biran\b",
        r"\biranian\b"
    ],
    "North Korea": [
        r"\bnorth korea\b",
        r"\bnorth korean\b"
    ],
    "South Korea": [
        r"\bsouth korea\b",
        r"\bsouth korean\b"
    ],
    "Australia": [
        r"\baustralia\b",
        r"\baustralian\b"
    ]
}


def load_raw_data(file_path: str = INPUT_FILE) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def classify_attack_type(text: str) -> str:
    text = text.lower()

    for attack_type, patterns in ATTACK_TYPE_PATTERNS:
        for pattern in patterns:
            if re.search(pattern, text):
                return attack_type

    return "other"


def extract_mentioned_countries(text: str) -> list[str]:
    text = text.lower()
    matched_countries = []

    for country, patterns in COUNTRY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text):
                matched_countries.append(country)
                break

    return matched_countries


def transform_articles(raw_data: dict) -> list[dict]:
    ingestion_time = datetime.now(timezone.utc).isoformat()
    articles = raw_data.get("articles", [])

    processed_articles = []

    for article in articles:
        title = article.get("title") or ""
        description = article.get("description") or ""
        combined_text = f"{title} {description}"

        mentioned_countries = extract_mentioned_countries(combined_text)

        processed_article = {
            "source_name": article.get("source", {}).get("name"),
            "author": article.get("author"),
            "title": title,
            "description": description,
            "url": article.get("url"),
            "published_at": article.get("publishedAt"),
            "attack_type": classify_attack_type(combined_text),
            "mentioned_countries": mentioned_countries,
            "primary_geographic_context": mentioned_countries[0] if mentioned_countries else "Unknown",
            "ingestion_time": ingestion_time
        }

        processed_articles.append(processed_article)

    return processed_articles


def save_processed_data(data: list[dict], file_path: str = OUTPUT_FILE) -> None:
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main() -> None:
    raw_data = load_raw_data()
    processed_data = transform_articles(raw_data)
    save_processed_data(processed_data)

    print(f"Saved processed data to {OUTPUT_FILE}")
    print(f"Total processed articles: {len(processed_data)}")


if __name__ == "__main__":
    main()