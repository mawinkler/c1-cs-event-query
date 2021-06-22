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

import argparse
import requests
import json
from requests.api import post
import yaml
import pprint
import sys
import requests
import logging
from prettytable import PrettyTable
from datetime import datetime, timedelta

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format='%(asctime)s %(levelname)s (%(threadName)s) [%(funcName)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

def collect(cluster_name, decision, mitigation, namespace, policy):
    """
    Queries for events with a given set of filters and prints out a table per
    event type discovered.

    Parameters
    ----------
    -c, --cluster_name      Cluster name.
    -d, --decision          Decision by the policy. Defaults to 'deny'.
    -m, --mitigation        Mitigation by the policy. Defaults to 'log'.
    -n, --namespace         Namespace in scope. Defaults to 'all'.
    -p, --policy            Policy to evaluate.

    Raises
    ------
    Exception

    Returns
    -------
    Tables
    """

    # API credentials are mounted to /etc
    c1_url=open('/etc/workload-security-credentials/c1_url', 'r').read()
    api_key=open('/etc/workload-security-credentials/api_key', 'r').read()

    # startTime = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    startTime = (datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    endTime = datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=999).strftime("%Y-%m-%dT%H:%M:%SZ")

    cursor = ""
    results = []
    loops=0
    # while True:
    url = "https://" + c1_url + "/api/container/events/evaluations?" \
        + "cursor=" + cursor \
        + "&limit=" + str(25) \
        + "&policyName=" + policy \
        + "&fromTime=" + startTime \
        + "&toTime=" + endTime
    post_header = {
        "Content-Type": "application/json",
        "api-secret-key": api_key,
        "api-version": "v1",
    }

    try:
        response = requests.get(
            url, headers=post_header, verify=True
        )
        response.raise_for_status()
    except requests.exceptions.Timeout as err:
        raise SystemExit(err)
    except requests.exceptions.RequestException as err:
        # catastrophic error. bail.
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        raise SystemExit(err)

    response = response.json()
    # Error handling
    if "message" in response:
        if response.get('message', "") == "Invalid API Key":
            _LOGGER.error("API error: {}".format(response['message']))
            raise ValueError("Invalid API Key")

    # Parse the response
    events_count = len(response.get('events', {}))
    _LOGGER.info("Number of events: {}".format(events_count))
    if events_count > 0:
        for event in response.get('events', {}):
            if event.get('clusterName', "") == cluster_name \
            and event.get('decision', "") == decision \
            and event.get('mitigation', "") == mitigation \
            and (event.get('namespace', "") == namespace \
                or namespace == 'all'):

                reasons = event.get('reasons', {})
                for reason in reasons:
                    resources = reason['resources']
                    for resource in resources:
                        result = {
                            "type": reason.get('type', 'n/a'),
                            "namespace": event.get('namespace', ""),
                            "container": resource.get('container', 'n/a'),
                            "pod": resource.get('object', 'n/a'),
                            "image": resource.get('image', 'n/a'),
                            "rule": reason.get('rule', 'n/a')
                        }
                        if result not in results:
                            results.append(result)
    # cursor = response.get('next', '')
    # loops += 1
    # print(loops, len(results), cursor)
    # if cursor == "":
    #     break
    
    # Sort results by pod name
    results = sorted(results, key=lambda k: k['pod']) 

    if len(results) > 0:
        # Generate a list of event types
        types = []
        for result in results:
            type = result.get('type', 'n/a')
            if type not in types:
                types.append(type)

        # Print the tables
        for type in types:
            x = PrettyTable()
            x.field_names = ['namespace', 'pod', 'image', 'container', 'rule']
            for c in x.field_names:
                x.align[c] = "l"
            for result in results:
                if result.get('type', 'n/a') == type:
                    x.add_row([
                        result.get('namespace', 'n/a'),
                        result.get('pod', 'n/a'),
                        result.get('image', 'n/a'),
                        result.get('container', 'n/a'),
                        result.get('rule', 'n/a')
                    ])
            print("\nEvent Type: {}\n{}".format(type.upper(), x))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cluster_name", type=str, help="Cluster name.")
    parser.add_argument("-d", "--decision", nargs='?', default='deny', type=str, help="Decision by the policy. Defaults to 'deny'.")
    parser.add_argument("-m", "--mitigation", nargs='?', default='log', type=str, help="Mitigation by the policy. Defaults to 'log'.")
    parser.add_argument("-n", "--namespace", nargs='?', default='all', type=str, help="Namespace in scope. Defaults to 'all'.")
    parser.add_argument("-p", "--policy", type=str, help="Policy to evaluate.")
    args = parser.parse_args()

    if args.cluster_name == None:
        raise SystemExit("You need to specify a cluster by name.")
    if not args.policy:
        raise SystemExit("You need to specify a policy.")
    
    collect(args.cluster_name, args.decision, args.mitigation, args.namespace, args.policy)