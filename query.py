#!/usr/bin/env python3

DOCUMENTATION = """
---
module: policy_on_r7_report.py

short_description: Retrieves CVEs discovered by Rapid7 Vulnerability
                   Management and assigns IPS rules to instances managed by
                   Cloud One Workload Security.

description:
    - "TODO"

options:
    none

author:
    - Markus Winkler (markus_winkler@trendmicro.com)
"""

EXAMPLES = """
./policy_on_r7_report.py
"""

RETURN = """
TODO
"""

import pprint
import requests
import json
from requests.api import post
import yaml
import pprint
import requests
import logging
from datetime import datetime, timedelta

_LOGGER = logging.getLogger(__name__)

def collect() -> dict:
    """
    Queries for events with a given set of filters

    Parameters
    ----------
    none

    Raises
    ------
    Exception

    Returns
    -------
    {

    }
    """

    # API credentials are mounted to /etc
    c1_url=open('/etc/workload-security-credentials/c1_url', 'r').read()
    api_key=open('/etc/workload-security-credentials/api_key', 'r').read()

    pprint.pprint(c1_url)
    pprint.pprint(api_key)

    # Define your metrics here
    result = {}
    # startTime = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    startTime = (datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
    endTime = datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=999).strftime("%Y-%m-%dT%H:%M:%SZ")

    cluster_name = "playground"
    decision = "deny"
    mitigation = "log"
    namespace = "prometheus"
    policy = "relaxed_playground"

    url = "https://" + c1_url + "/api/container/events/evaluations?" \
        + "limit=" + str(25) \
        + "&policyName=" + policy \
        + "&fromTime=" + startTime \
        + "&toTime=" + endTime
    post_header = {
        "Content-Type": "application/json",
        "api-secret-key": api_key,
        "api-version": "v1",
    }

    response = requests.get(
        url, headers=post_header, verify=True
    ).json()

    # Error handling
    if "message" in response:
        if response.get('message', "") == "Invalid API Key":
            _LOGGER.error("API error: {}".format(response['message']))
            raise ValueError("Invalid API Key")

    if len(response.get('events', {})) > 0:
        for event in response.get('events', {}):
            if event.get('clusterName', "") == cluster_name \
            and event.get('decision', "") == decision \
            and event.get('mitigation', "") == mitigation \
            and event.get('namespace', "") == namespace:
                pprint.pprint(event['reasons'])

    _LOGGER.debug("Container Security Events Received")

if __name__ == '__main__':
    collect()