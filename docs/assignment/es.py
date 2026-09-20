"""連到本機 Elasticsearch 的小工具。

這個檔案不用改，直接 import 就好：

    from es import fetch_all

先跑一次確認環境沒問題：

    uv run es.py        # 應該印出 196081
"""
import requests

ES   = "http://localhost:9200"
HOST = "winlogbeat-apt29-host-day1"


def search(body, index=HOST):
    """送一個查詢，回傳原始 JSON 回應。"""
    r = requests.post(f"{ES}/{index}/_search", json=body, timeout=60)
    r.raise_for_status()
    return r.json()


def fetch_all(query, fields, index=HOST):
    """把符合條件的紀錄全部抓下來，回傳 list of dict。"""
    body = {"size": 10000, "_source": fields, "query": query}
    return [h["_source"] for h in search(body, index)["hits"]["hits"]]


if __name__ == "__main__":
    body = {"size": 0, "track_total_hits": True, "query": {"match_all": {}}}
    print(search(body)["hits"]["total"]["value"])    # 應該印出 196081
