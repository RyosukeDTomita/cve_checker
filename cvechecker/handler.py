# coding: utf-8
"""_summary_
CVE情報を取得するLambda関数

Returns:
    _type_: _description_
"""
import requests
from datetime import datetime, timedelta, timezone
import logging
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def run(event, context):
    """_summary_
    事実上のmain関数
    """

    # NVD REST API URL
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY = os.environ.get("NVD_API_KEY")
    # CloudWatch Logsにログを出力
    current_time = datetime.now().time()
    logger.info("Your cron function ran at " + str(current_time))

    print("Fetching recent CVEs from NVD...")
    cve_items = fetch_recent_cves(url=NVD_API_URL, api_key=NVD_API_KEY, days=7)  # 過去7日間のCVEを取得

    if cve_items:
        print(f"Retrieved {len(cve_items)} recent CVEs:")
        display_cves(cve_items)
    else:
        print("No recent CVEs found.")


def fetch_recent_cves(url: str, api_key: str, days: int) -> list:
    """
    最近追加されたCVEを取得
    :param days: 過去何日分のCVEを取得するか (int)
    :return: 取得したCVEリスト (list)
    """
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    all_cves = []
    start_index = 0
    results_per_page = 10

    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }
    headers = {
        "apiKey": api_key
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        cve_items = data.get("vulnerabilities", [])
        for item in cve_items:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            published_date = cve.get("published", "N/A")
            vuln_status = cve.get("vulnStatus", "N/A")
            reference_uri = [ref.get("url", "N/A") for ref in cve.get("references", [])]
            description = cve.get("descriptions", [{}])[0].get("value", "N/A")
            impact_score = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
            all_cves.append({
                "id": cve_id,
                "published": published_date,
                "vuln_status": vuln_status,
                "reference_uri": reference_uri,
                "impact_score": impact_score,
                "description": description
            })
        start_index += results_per_page
    except requests.RequestException as e:
        print(f"Error fetching CVEs: {e}")

    return all_cves


def display_cves(cve_items):
    """
    CVE情報を表示
    :param cve_items: CVE情報のリスト
    """
    for cve in cve_items:
        cve_id = cve["id"]
        published_date = cve["published"]
        vuln_status = cve["vuln_status"]
        reference_uri = cve["reference_uri"]
        description = cve["description"]
        impact_score = cve["impact_score"]

        print(f"CVE ID: {cve_id}")
        print(f"Description: {description}")
        print(f"Published Date: {published_date}")
        print(f"Vulnerability Status: {vuln_status}")
        print(f"reference uri: {reference_uri}")
        print(f"Impact Score: {impact_score}")
        print("-" * 50)


if __name__ == "__main__":
    run(None, None)
