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

def collect(c1_url, api_key, cluster_name, decision, mitigation, namespace, policy):
    """
    Queries for events with a given set of filters and prints out a table per
    event type discovered.

    Parameters
    ----------
    c1_url          Cloud One API endpoint
    api_key         API-Key
    cluster_name    Cluster name.
    decision        Decision by the policy.
    mitigation      Mitigation by the policy.
    namespace       Namespace in scope.
    policy          Policy to evaluate.

    Raises
    ------
    Exception

    Returns
    -------
    Array with images violating the policy
    """

    # startTime = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    # The interval for continuous rescans of the cluster is 30 minutes by default
    startTime = (datetime.utcnow() - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    endTime = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    _LOGGER.info(f"Start time: {startTime}")
    _LOGGER.info(f"End time: {endTime}")

    cursor = ""
    results = []
    loops=0
    while True:
            # + "cursor=" + cursor \
        url = "https://" + c1_url + "/api/container/events/evaluations?" \
            + "&limit=" + str(100) \
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
                                "timestamp": event.get('timestamp', 'n/a'),
                                "type": reason.get('type', 'n/a'),
                                "namespace": event.get('namespace', ""),
                                "container": resource.get('container', 'n/a'),
                                "pod": resource.get('object', 'n/a'),
                                "image": resource.get('image', 'n/a'),
                                "rule": reason.get('rule', 'n/a')
                            }
                            if result not in results:
                                results.append(result)
        cursor = response.get('next', '')
        loops += 1
        # print(loops, len(results), cursor)
        if cursor == "":
            break
        if loops > 0:
            break
    
    results_count = len(results)
    _LOGGER.info("Number of filtered reasons: {}".format(results_count))

    # Sort results by pod name
    results = sorted(results, key=lambda k: k['pod']) 
    images = []

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
            x.field_names = ['timestamp', 'namespace', 'pod', 'image', 'container', 'rule']
            for c in x.field_names:
                x.align[c] = "l"
            for result in results:
                if result.get('type', 'n/a') == type:
                    x.add_row([
                        datetime.strptime(
                            result.get('timestamp', 'n/a'),
                            '%Y-%m-%dT%H:%M:%S.%fZ'
                        ).strftime("%H:%M:%S"),
                        result.get('namespace', 'n/a'),
                        result.get('pod', 'n/a'),
                        result.get('image', 'n/a'),
                        result.get('container', 'n/a'),
                        result.get('rule', 'n/a')
                    ])
                    if result.get('image', None) not in images:
                        images.append(result.get('image', None))
            print("\nEvent Type: {}\n{}".format(type.upper(), x))
    else:
        _LOGGER.info("No evaluations found.")
    
    return images

def get_policy(c1_url, api_key, policy_name):
    """
    Retrieves the policy with a given name.

    Parameters
    ----------
    c1_url          Cloud One API endpoint
    api_key         API-Key
    policy_name     Name of the policy to return

    Raises
    ------
    Exception

    Returns
    -------
    Policy
    """

    url = "https://" + c1_url + "/api/container/policies?" \
        + "&limit=" + str(100)
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
    policies_count = len(response.get('policies', {}))
    _LOGGER.info("Number of policies: {}".format(policies_count))
    result = {}
    if policies_count > 0:
        for policy in response.get('policies', {}):
            if policy.get('name', "") == policy_name:
                result = policy
                break

    if result == {}:
        _LOGGER.info("Policy {} not found".format(policy))
        raise ValueError("Policy {} not found".format(policy))

    return policy

def update_policy(c1_url, api_key, namespace, policy, image_exceptions, namespaces=True):
    """
    Retrieves the policy with a given name.

    Parameters
    ----------
    c1_url          Cloud One API endpoint
    api_key         API-Key
    policy_name     Name of the policy to return

    Raises
    ------
    Exception

    Returns
    -------
    Policy

    TODO:
    Create 'namespaced' if not existing
    Create 'namespaced.namespaces.namespace' if not existing
    """

    if not policy.get('namespaced', False):
        _LOGGER.info("Not a namespaced policy")
    
    ruleset_id = 0
    for namespaced in policy.get('namespaced', False):
        if namespace in namespaced.get('namespaces', False):
            exceptions = namespaced.get('exceptions', False)
            for exception in exceptions:
                for image_exception in image_exceptions:
                    if image_exception == exception.get('statement', False).get('value', False):
                        image_exceptions.remove(image_exception)
                        _LOGGER.info("Exception for {} already exists".format(image_exception))
            _LOGGER.info("Adding image exceptions for {}".format(image_exceptions))
            for image in image_exceptions:
                exceptions.append(
                    {
                        "action": "log",
                        "mitigation": "log",
                        "type": "image",
                        "enabled": True,
                        "statement": {
                            "key": "contains",
                            "value": image
                        }
                    }
                )
            break
        else:
            _LOGGER.info("No namespaced policy found for {}".format(namespace))
        ruleset_id += 1

    # Set exceptions
    policy['namespaced'][ruleset_id]['exceptions'] = exceptions

    # Update policy
    _LOGGER.info("Updating policy for namespace {}".format(namespace))
    url = "https://" + c1_url + "/api/container/policies/" \
        + policy.get('id', False)
    post_header = {
        "Content-Type": "application/json",
        "api-secret-key": api_key,
        "api-version": "v1",
    }

    policy.pop('id', None)
    policy.pop('name', None)
    policy.pop('updated', None)
    policy.pop('created', None)

    try:
        response = requests.post(
            url, headers=post_header, data=json.dumps(policy), verify=True
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
    
    # API credentials are mounted to /etc
    c1_url=open('/etc/workload-security-credentials/c1_url', 'r').read()
    api_key=open('/etc/workload-security-credentials/api_key', 'r').read()

    images = collect(c1_url, api_key, args.cluster_name, args.decision, args.mitigation, args.namespace, args.policy)
    policy = get_policy(c1_url, api_key, args.policy)
    policy = update_policy(c1_url, api_key, args.namespace, policy, images)

    _LOGGER.info("Done")
