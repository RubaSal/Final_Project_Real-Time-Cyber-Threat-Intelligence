import os
import json
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv


OUTPUT_FILE = "security_news_raw.json"


def load_api_key() -> str:
    load_dotenv()
    api_key = os.getenv("SECURITY_NEWS_API_KEY")

    if not api_key:
        raise ValueError("Missing SECURITY_NEWS_API_KEY in .env file")

    return api_key


def build_query_params(api_key: str) -> dict:
    from_date = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%d")

    return {
        "q": '("cyber attack" OR ransomware OR malware OR "data breach" OR CVE OR phishing) NOT pypi NOT package NOT library',
        "searchIn": "title,description",
        "language": "en",
        "sortBy": "relevancy",
        "from": from_date,
        "pageSize": 20,
        "apiKey": api_key,
    }


def fetch_security_news(params: dict) -> dict:
    url = "https://newsapi.org/v2/everything"
    response = requests.get(url, params=params, timeout=30)
    response.raise_for_status()
    return response.json()


def build_output(raw_data: dict, query: str) -> dict:
    return {
        "ingestion_time": datetime.now(timezone.utc).isoformat(),
        "source": "NewsAPI",
        "query": query,
        "total_results": raw_data.get("totalResults", 0),
        "articles": raw_data.get("articles", []),
    }


def save_to_file(data: dict, file_path: str = OUTPUT_FILE) -> None:
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main() -> None:
    try:
        api_key = load_api_key()
        params = build_query_params(api_key)
        raw_data = fetch_security_news(params)
        output_data = build_output(raw_data, params["q"])
        save_to_file(output_data)

        print(f"Saved response to {OUTPUT_FILE}")
        print(f"Total articles fetched: {len(output_data['articles'])}")

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    except ValueError as e:
        print(f"Configuration error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()