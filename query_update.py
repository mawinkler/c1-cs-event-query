#!/usr/bin/env python3
"""
---
module: query_update.py

short_description: Queries evaluation events from Container Security and
                   optionally updates the policy to whitelist images in a
                   given namespace.

description:
    - Intention of this script is to support in policy fine tuning when
      deploying Container Security on prepopulated clusters.
    - In many cases, existing workload on the cluster might not be
      compliant to the configured policy. Therefore, some images are needed
      to be whitelisted.
    - This script queries the evaluation events from the past 30 minutes and
      prints tables with the violations devided into reported event types.
    - It can optionally create exclusions within the clusters policy, whereby
      by default the exclusions will be namespaced.

configuration:
    Create the following files below /etc/workload-security-credentials/:
    c1_url - cloudone.trendmicro.com:443
    api_key - your API key

usage:
    query_update.py [-h] -c CLUSTER_NAME -p POLICY [-d [{deny,log}]] [-m [{block,log}]] [-n [NAMESPACE]] [-un] [-uc]

    examples:   query_update.py -c playground -p relaxed_playground
                query_update.py -c playground -p relaxed_playground -n falco
                query_update.py -c playground -p relaxed_playground -n falco -un
                query_update.py -c playground -p relaxed_playground -n falco -uc

    optional arguments:
    -h, --help            show this help message and exit
    -d [{deny,log}], --decision [{deny,log}]
                            decision by the policy. default: deny
    -m [{block,log}], --mitigation [{block,log}]
                            mitigation by the policy. default: log
    -n [NAMESPACE], --namespace [NAMESPACE]
                            namespace in scope. default: all
    -un, --update-namespaced
                            policy will be updated namespaced with exceptions for the violating images
    -uc, --update-cluster-wide
                            policy will be updated cluster-wide with exceptions for the violating images

    required arguments:
    -c CLUSTER_NAME, --cluster-name CLUSTER_NAME
                            Cluster name
    -p POLICY, --policy POLICY
                            Cluster policy

author:
    - Markus Winkler (markus_winkler@trendmicro.com)

todo:
    - Switch to describe policy when evaluating the policy
    - Fix paging in collect
"""

import pprint
import argparse
import json
import sys
import logging
from argparse import RawDescriptionHelpFormatter
from datetime import datetime, timedelta
import requests
from prettytable import PrettyTable

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format='%(asctime)s %(levelname)s (%(threadName)s) [%(funcName)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

def collect(url, key, cluster_name, decision, mitigation, namespace, policy_name):
    """
    Queries for events with a given set of filters and prints out a table per
    event type discovered.

    Parameters
    ----------
    url                 Cloud One API endpoint
    key                 API-Key
    cluster_name        Cluster name.
    decision            Decision by the policy.
    mitigation          Mitigation by the policy.
    namespace           Namespace in scope.
    policy_name         Policy to evaluate.

    Raises
    ------
    Exception

    Returns
    -------
    Array with images violating the policy
    """

    # The interval for continuous rescans of the cluster is 30 minutes by default
    start_time = (datetime.utcnow() - timedelta(minutes=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    _LOGGER.info("Start time: %s", start_time)
    _LOGGER.info("End time: %s", end_time)

    cursor = ""
    results = []
    loops = 0
    while True:
            # + "cursor=" + cursor \
        url = "https://" + url + "/api/container/events/evaluations?" \
            + "&limit=" + str(100) \
            + "&policyName=" + policy_name \
            + "&fromTime=" + start_time \
            + "&toTime=" + end_time
        post_header = {
            "Content-Type": "application/json",
            "api-secret-key": key,
            "api-version": "v1",
        }

        try:
            response = requests.get(
                url, headers=post_header, verify=True
            )
            response.raise_for_status()
        except requests.exceptions.Timeout as err:
            raise SystemExit(err)
        except requests.exceptions.HTTPError as err:
            raise SystemExit(err)
        except requests.exceptions.RequestException as err:
            # catastrophic error. bail.
            raise SystemExit(err)

        response = response.json()
        # Error handling
        if "message" in response:
            if response.get('message', "") == "Invalid API Key":
                _LOGGER.error("API error: %s", response['message'])
                raise ValueError("Invalid API Key")

        # Parse the response
        events_count = len(response.get('events', {}))
        _LOGGER.info("Number of events: %d", events_count)
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
                                "timestamp": event.get('timestamp', None),
                                "type": reason.get('type', None),
                                "namespace": event.get('namespace', ""),
                                "container": resource.get('container', None),
                                "pod": resource.get('object', None),
                                "image": resource.get('image', None),
                                "rule": reason.get('rule', None)
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
    _LOGGER.info("Number of filtered reasons: %d", results_count)

    # Sort results by pod name
    results = sorted(results, key=lambda k: k['pod'])
    images = []

    if len(results) > 0:
        # Generate a list of event types
        event_types = []
        for result in results:
            event_type = result.get('type', None)
            if event_type not in event_types:
                event_types.append(event_type)

        # Print the tables
        for event_type in event_types:
            table = PrettyTable()
            table.field_names = ['timestamp', 'namespace', 'pod', 'image', 'container', 'rule']
            for column in table.field_names:
                table.align[column] = "l"
            for result in results:
                if result.get('type', None) == event_type:
                    table.add_row([
                        datetime.strptime(
                            result.get('timestamp', None),
                            '%Y-%m-%dT%H:%M:%S.%fZ'
                        ).strftime("%H:%M:%S"),
                        result.get('namespace', 'n/a'),
                        result.get('pod', 'n/a'),
                        result.get('image', 'n/a'),
                        result.get('container', 'n/a'),
                        result.get('rule', 'n/a')
                    ])
                    if result.get('image', None) not in images \
                    and result.get('image', None) is not None:
                        images.append(result.get('image', None))
            print("\nEvent Type: {}\n{}".format(event_type.upper(), table))
    else:
        _LOGGER.info("No evaluations found.")

    return images

def get_policy(url, key, policy_name):
    """
    Retrieves the policy with a given name.

    Parameters
    ----------
    url                 Cloud One API endpoint
    key                 API-Key
    policy_name         Name of the policy to return

    Raises
    ------
    Exception

    Returns
    -------
    Policy
    """

    url = "https://" + url + "/api/container/policies?" \
        + "&limit=" + str(100)
    post_header = {
        "Content-Type": "application/json",
        "api-secret-key": key,
        "api-version": "v1",
    }

    try:
        response = requests.get(
            url, headers=post_header, verify=True
        )
        response.raise_for_status()
    except requests.exceptions.Timeout as err:
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        raise SystemExit(err)
    except requests.exceptions.RequestException as err:
        # catastrophic error. bail.
        raise SystemExit(err)

    response = response.json()
    # Error handling
    if "message" in response:
        if response.get('message', "") == "Invalid API Key":
            _LOGGER.error("API error: %s", response['message'])
            raise ValueError("Invalid API Key")

    # Parse the response
    policies_count = len(response.get('policies', {}))
    _LOGGER.info("Number of policies: %s", policies_count)
    configured_policy = {}
    if policies_count > 0:
        for policy in response.get('policies', {}):
            if policy.get('name', "") == policy_name:
                configured_policy = policy
                break

    if configured_policy == {}:
        _LOGGER.error("Policy %s not found", policy_name)
        raise ValueError("Policy {} not found".format(policy_name))

    return configured_policy

def update_policy(url, key, configured_policy, image_exceptions,
                  namespace='default', namespaced_policy=True):
    """
    Updates the policy with a given name.

    Parameters
    ----------
    url                 Cloud One API endpoint
    key                 API-Key
    policy              The policy to update
    image_exceptions    The image names for the exceptions
    namespace           The namespace of the images
    namespaced_policy   By default, create a namespaced policy

    Raises
    ------
    Exception
    """

    if namespaced_policy:
        _LOGGER.info("Updating namespaced policy")
        # Check, if policy is already namespaced
        if not configured_policy.get('namespaced', False):
            configured_policy['namespaced'] = [{
                "name": namespace.replace('-', '_'),
                "namespaces": [
                    namespace
                ],
                "rules": configured_policy['default']['rules']
            }]
            _LOGGER.info("Policy %s is now a namespaced policy for namespace %s",
                         configured_policy.get('name'), namespace)

        # Check, if namespaced policy already covers the namespace
        namespace_existing = False
        for namespaced in configured_policy.get('namespaced', False):
            if namespace in namespaced.get('namespaces', False):
                namespace_existing = True
                break
        if not namespace_existing:
            configured_policy['namespaced'].append({
                "name": namespace.replace('-', '_'),
                "namespaces": [
                    namespace
                ],
                "rules": configured_policy['default']['rules']
            })
            _LOGGER.info("Namespaced policy for namespace %s added", namespace)

        # Check, if all exceptions for the given list of images is set to the policy
        ruleset_id = 0
        for namespaced in configured_policy.get('namespaced', False):
            if namespace in namespaced.get('namespaces', False):
                exceptions = namespaced.get('exceptions', False)
                if not exceptions:
                    exceptions = []
                for exception in exceptions:
                    for image_exception in image_exceptions:
                        if image_exception == exception.get('statement', False).get('value', False):
                            image_exceptions.remove(image_exception)
                            _LOGGER.info("Exception for %s already exists", image_exception)
                for image in image_exceptions:
                    _LOGGER.info("Adding image exception for %s", image)
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
            ruleset_id += 1

        # Set exceptions
        configured_policy['namespaced'][ruleset_id]['exceptions'] = exceptions
    else:
        _LOGGER.info("Updating cluster-wide policy")
        # Check, if all exceptions for the given list of images is set to the policy
        exceptions = configured_policy.get('default', False).get('exceptions', False)
        if not exceptions:
            exceptions = []
        for exception in exceptions:
            for image_exception in image_exceptions:
                if image_exception == exception.get('statement', False).get('value', False):
                    image_exceptions.remove(image_exception)
                    _LOGGER.info("Exception for %s already exists", image_exception)
        for image in image_exceptions:
            _LOGGER.info("Adding image exception for %s cluster-wide", image)
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
        # Set exceptions
        configured_policy['default']['exceptions'] = exceptions

    # Update policy
    _LOGGER.info("Updating policy for namespace %s", namespace)
    url = "https://" + url + "/api/container/policies/" \
        + configured_policy.get('id', False)
    post_header = {
        "Content-Type": "application/json",
        "api-secret-key": key,
        "api-version": "v1",
    }

    configured_policy.pop('id', None)
    configured_policy.pop('name', None)
    configured_policy.pop('updated', None)
    configured_policy.pop('created', None)

    try:
        response = requests.post(
            url, headers=post_header, data=json.dumps(configured_policy), verify=True
        )
        # print(response.text)
        response.raise_for_status()
    except requests.exceptions.Timeout as err:
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        raise SystemExit(err)
    except requests.exceptions.RequestException as err:
        # catastrophic error. bail.
        raise SystemExit(err)

    response = response.json()
    # Error handling
    if "message" in response:
        if response.get('message', "") == "Invalid API Key":
            _LOGGER.error("API error: %s", response['message'])
            raise ValueError("Invalid API Key")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="examples:    query_update.py -c playground -p relaxed_playground\n"
        "             query_update.py -c playground -p relaxed_playground -n falco\n"
        "             query_update.py -c playground -p relaxed_playground -n falco -un\n"
        "             query_update.py -c playground -p relaxed_playground -n falco -uc",
        formatter_class=RawDescriptionHelpFormatter)
    required_arguments = parser.add_argument_group('required arguments')
    required_arguments.add_argument(
        "-c", "--cluster-name",
        type=str, required=True, help="Cluster name"
    )
    required_arguments.add_argument(
        "-p", "--policy",
        type=str, required=True, help="Cluster policy"
    )
    parser.add_argument(
        "-d", "--decision",
        nargs='?', default='deny', choices=['deny', 'log'], type=str,
        help="decision by the policy. default: deny"
    )
    parser.add_argument(
        "-m", "--mitigation", nargs='?', default='log', choices=['block', 'log'], type=str,
        help="mitigation by the policy. default: log"
    )
    parser.add_argument(
        "-n", "--namespace", nargs='?', default='all', type=str,
        help="namespace in scope. default: all"
    )
    parser.add_argument(
        "-un", "--update-namespaced", action='store_true',
        help="policy will be updated namespaced with exceptions for the violating images"
    )
    parser.add_argument(
        "-uc", "--update-cluster-wide", action='store_true',
        help="policy will be updated cluster-wide with exceptions for the violating images"
    )
    args = parser.parse_args()

    if (args.update_namespaced or args.update_cluster_wide) and args.namespace == 'all':
        raise SystemExit("error: updating the policy requires a defined namespace")

    # API credentials are mounted to /etc
    c1_url = open('/etc/workload-security-credentials/c1_url', 'r').read()
    api_key = open('/etc/workload-security-credentials/api_key', 'r').read()

    _LOGGER.info("Collecting evaluation events")
    violating_images = collect(c1_url, api_key,
                               args.cluster_name, args.decision, args.mitigation,
                               args.namespace, args.policy)
    if args.update_namespaced:
        policy_cs = get_policy(c1_url, api_key, args.policy)
        update_policy(c1_url, api_key, policy_cs, image_exceptions=violating_images,
                      namespace=args.namespace, namespaced_policy=True)
    if args.update_cluster_wide:
        policy_cs = get_policy(c1_url, api_key, args.policy)
        update_policy(c1_url, api_key, policy_cs, image_exceptions=violating_images,
                      namespaced_policy=False)

    _LOGGER.info("Done")
