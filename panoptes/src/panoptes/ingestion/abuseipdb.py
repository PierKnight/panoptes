from __future__ import annotations

import json

from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging

from requests.exceptions import RequestException

log = logging.get(__name__)

from typeguard import typechecked

@typechecked
class AbuseIPDB(BaseHTTPClient):
    """
    A class to interact with the AbuseIPDB API for checking IP addresses.
    This class provides methods to check if an IP address has been reported and to retrieve reports for a list of IP addresses.
    """
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key
        super().__init__(timeout=10)
        # These categories may change over time, so please check them from time to time.
        # https://www.abuseipdb.com/categories
        self.__report_categories = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }


    def check_ip(self, ip: str) -> dict:
        """
        Check if an IP address has been reported using the AbuseIPDB API.
        Args:
            ip (str): The IP address to check.
        Returns:
            dict: A dictionary containing the response from the AbuseIPDB API, which includes:
                - data: Contains information about the IP address, including reports.
                - reports: A list of reports for the given IP address.
        """
        url = f'{self.BASE_URL}/check'

        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '365',      # Unfortunately, the API does not allow to check reports older than 365 days
            'verbose': True             # This will return more detailed information about the reports
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        response = self._get(
            url,
            headers=headers,
            params=querystring
        )

        # Formatted output
        decoded_response = response.json()

        return decoded_response


    def get_reports_from_check_ip(self, ip: str) -> list:
        """
        Get reports for a specific IP address by checking it against the AbuseIPDB API.
        Args:
            ip (str): The IP address to check.
        Returns:
            list: A list of reports for the given IP address, where each report contains:
                - reportedAt: The date and time when the IP was reported.
                - comment: The comment associated with the report.
                - categories: A list of categories that the report falls under.
        """
        if not ip:
            log.error("IP address is empty or None.")
            return []
        decoded_response = self.check_ip(ip)

        reports = list()

        for report in decoded_response["data"]["reports"]:
            reported_at = report["reportedAt"]
            comment = report["comment"]
            # Simply convert categories numbers to labels
            categories = [self.__report_categories[category_number] for category_number in report["categories"]]

            reports.append({
                "reportedAt": reported_at,
                "comment": comment,
                "categories": categories
            })

        return reports


    def get_abused_ips_reports(self, ips: list[str]) -> dict:
        """
        Check a list of IP addresses for reports and return a dictionary with the IP addresses as keys and the reports as values.
        Args:
            ips (list[str]): A list of IP addresses to check.
        Returns:
            dict: A dictionary where keys are IP addresses and values are lists of reports for those IPs.
                  Only IPs with reports will be included in the dictionary.
        """
        abused_ips_reports = dict()
        for ip in ips:
            report = self.get_reports_from_check_ip(ip)
            if len(report) > 0:
                abused_ips_reports[ip] = report
        return abused_ips_reports