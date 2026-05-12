from elasticsearch import Elasticsearch

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=('elastic', 'RZ*TUyj0AlRyGpdNI2g6'),
    verify_certs=False,
    headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8"}
)

# Replace 'security_score' with the column you want to delete
column_to_remove = "security_score"
index_name = "logs-system"

query = {
    "script": {
        "source": f"ctx._source.remove('{column_to_remove}')",
        "lang": "painless"
    },
    "query": {
        "exists": {
            "field": column_to_remove
        }
    }
}

response = es.update_by_query(index=index_name, body=query)
print(f"[+] Removed column from {response['updated']} documents.")
