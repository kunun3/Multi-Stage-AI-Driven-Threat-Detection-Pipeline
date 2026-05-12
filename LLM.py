import time
import json
import requests
import urllib3
from elasticsearch import Elasticsearch, helpers

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GROQ_API_KEY = "your api key"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
SCORE_THRESHOLD = 60 

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=('<user>', '<pass>'),
    verify_certs=False,
    headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8"}
)

def call_llm(log_content):
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}

    # Normalize command for AI analysis
    cmd = log_content.get("CommandLine") or \
          log_content.get("commandline") or \
          log_content.get("process", {}).get("command_line", "N/A")

    relevant_info = {
        "message": log_content.get("message"),
        "cmd": cmd,
        "user": log_content.get("user", {}).get("name"),
        "score": log_content.get("security_score")
    }

    prompt = (
        f"You are a SOC Analyst. Analyze this Windows log: {json.dumps(relevant_info)}. "
        "Is this a real threat? Answer ONLY in JSON format: "
        "{\"malicious\": \"Yes/No\", \"comment\": \"one short sentence explaining why\"}"
    )

    data = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"}
    }

    try:
        resp = requests.post(GROQ_URL, headers=headers, json=data, timeout=10)
        content = resp.json()['choices'][0]['message']['content']
        return json.loads(content)
    except Exception as e:
        return {"malicious": "Error", "comment": "LLM analysis failed"}

def run_llm_worker():
    print(f"[*] Stage 2: LLM Worker Active...")
    
    while True:
        # Index updated to catch logs-test
        query = {
            "size": 5,
            "query": {
                "bool": {
                    "must": [{"range": {"security_score": {"gte": SCORE_THRESHOLD}}}],
                    "must_not": [{"exists": {"field": "ai_is_malicious"}}]
                }
            }
        }

        try:
            res = es.search(index="logs-system", body=query)
            hits = res['hits']['hits']

            if not hits:
                time.sleep(10)
                continue

            print(f"[i] High-risk activity detected! Sending {len(hits)} logs to Groq...")
            actions = []

            for hit in hits:
                ai_opinion = call_llm(hit['_source'])
                actions.append({
                    "_op_type": "update",
                    "_index": hit['_index'],
                    "_id": hit['_id'],
                    "doc": {
                        "ai_is_malicious": ai_opinion.get("malicious", "Unknown"),
                        "ai_comment": ai_opinion.get("comment", "No analysis available")
                    }
                })

            if actions:
                helpers.bulk(es, actions)
                print(f"[+] AI analysis complete for {len(actions)} logs.")

        except Exception as e:
            print(f"[!] LLM Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    run_llm_worker()
