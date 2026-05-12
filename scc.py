import time
import json
from elasticsearch import Elasticsearch, helpers
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=('<user>', '<pass>'),
    verify_certs=False,
    ssl_show_warn=False,
    headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8"}
)

# Broadened to catch 'logs-test' and others
SOURCE_INDEX = "logs-system"

def parse_and_score(log):
    try:
        # 1. Normalize Fields
        event_id = log.get("winlog", {}).get("event_id", log.get("event", {}).get("code", 0))
        user_name = str(log.get("user", {}).get("name", log.get("winlog", {}).get("user", {}).get("name", ""))).lower()
        
        # Check all possible command line field names
        cmd_line = str(log.get("CommandLine", 
                       log.get("commandline", 
                       log.get("process", {}).get("command_line", "")))).lower()
        
        message = str(log.get("message", "")).lower()
        
        # Combine text for keyword scanning
        all_text = f"{message} {cmd_line}"

        # 2. Check Admin Status
        user_sid = str(log.get("winlog", {}).get("user", {}).get("identifier", ""))
        is_admin = 1 if (user_name == "system" or user_sid == "S-1-5-18" or "admin" in user_name) else 0

        # 3. Keyword Scoring
        sus_keywords = {
            'mimikatz': 50, 'rubeus': 50, 'powershell': 20,
            'lsass': 40, 'asktgt': 50, 'ptt': 50
        }

        applied_keywords = [k for k in sus_keywords if k in all_text]
        keyword_score = sum(sus_keywords[k] for k in applied_keywords)

        total_score = keyword_score
        if is_admin: total_score += 15
        
        # Safe integer conversion for Event IDs
        try:
            eid = int(event_id)
            if eid in [10, 4104, 4698]: total_score += 20
        except:
            pass

        return {
            "security_score": total_score,
            "detection_reasons": applied_keywords,
            "is_admin_involved": is_admin,
            "processed_at": "2026-05-11"
        }
    except Exception as e:
        print(f"Error parsing log: {e}")
        return None

def run_worker():
    print(f"[*] Starting EMI Worker...")
    print(f"[*] Monitoring Index: {SOURCE_INDEX}")

    while True:
        # REMOVED the 10-minute range so it finds your 2020 logs
        query = {
            "query": {
                "bool": {
                    "must_not": [{"exists": {"field": "security_score"}}]
                }
            }
        }

        try:
            response = es.search(index=SOURCE_INDEX, body=query, size=100)
            hits = response['hits']['hits']

            if not hits:
                time.sleep(5)
                continue

            print(f"[i] Found {len(hits)} new logs to score...")
            actions = []

            for hit in hits:
                analysis = parse_and_score(hit['_source'])
                if analysis:
                    actions.append({
                        "_op_type": "update",
                        "_index": hit['_index'],
                        "_id": hit['_id'],
                        "doc": analysis
                    })

            if actions:
                helpers.bulk(es, actions)
                print(f"[+] Successfully enriched {len(actions)} logs.")

        except Exception as e:
            print(f"[!] Worker Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    run_worker()
