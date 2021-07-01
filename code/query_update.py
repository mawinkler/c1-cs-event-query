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
    query_update.py [-h] -c CLUSTER_NAME \
                         -p POLICY \
                        [-d [{deny,log}]] [-m [{block,log}]] \
                        [-n [NAMESPACE]] [-un] [-uc]

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
                            policy will be updated namespaced with exceptions
                            for the violating images
    -uc, --update-cluster-wide
                            policy will be updated cluster-wide with exceptions
                            for the violating images

    required arguments:
    -c CLUSTER_NAME, --cluster-name CLUSTER_NAME
                            Cluster name
    -p POLICY, --policy POLICY
                            Cluster policy

author:
    - Markus Winkler (markus_winkler@trendmicro.com)

todo:
    - Switch to describe policy when evaluating the policy
    - Fix paging in collect_events
"""

import argparse
import json
import sys
import logging
from argparse import RawDescriptionHelpFormatter
from datetime import datetime, timedelta
import requests
from prettytable import PrettyTable

from helper_functions import EventFunctions, PolicyFunctions

# Globals
_LOGGER = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format='%(asctime)s %(levelname)s (%(threadName)s) [%(funcName)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# API credentials are mounted to /etc
c1_url = open('/etc/workload-security-credentials/c1_url', 'r').read()
api_key = open('/etc/workload-security-credentials/api_key', 'r').read()

event_functions = EventFunctions(c1_url, api_key)
policy_functions = PolicyFunctions(c1_url, api_key)


def print_tables(reasons):
    """
    Prints out a table per event type discovered.

    Parameters
    ----------
    reasons             The reasons for the events.

    Raises
    ------
    Exception

    Returns
    -------
    None
    """

    if len(reasons) > 0:
        # Generate a list of event types
        event_types = []
        for reason in reasons:
            event_type = reason.get('type', None)
            if event_type not in event_types:
                event_types.append(event_type)

        # Print the tables
        for event_type in event_types:
            table = PrettyTable()
            table.field_names = ['namespace', 'pod', 'image', 'container', 'rule']
            for column in table.field_names:
                table.align[column] = "l"
            for reason in reasons:
                if reason.get('type', None) == event_type:
                    table.add_row([
                        reason.get('namespace', 'n/a'),
                        reason.get('pod', 'n/a'),
                        reason.get('image', 'n/a'),
                        reason.get('container', 'n/a'),
                        reason.get('rule', 'n/a')
                    ])
            print("\nEvent Type: {}\n{}".format(event_type.upper(), table))
    else:
        _LOGGER.info("No evaluations found.")

def policy_add_exceptions(image_exceptions,
                          namespace='default',
                          namespaced_policy=True):
    """
    Updates the policy with a given name.

    Parameters
    ----------
    image_exceptions    The image names for the exceptions
    namespace           The namespace of the images
    namespaced_policy   By default, create a namespaced policy

    Raises
    ------
    Exception
    """

    configured_policy = policy_functions.get_policy()

    if namespaced_policy:
        _LOGGER.info("Updating namespaced policy")
        # Check, if policy is already namespaced
        if not policy_functions.is_namespaced():
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
        if not policy_functions.has_namespace(namespace):
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

    policy_functions.set_policy(configured_policy)


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

    _LOGGER.info("Collecting evaluation event reasons")
    reasons = event_functions.collect_reasons(args.cluster_name, args.decision, args.mitigation, args.namespace, args.policy)
    _LOGGER.info("Extracting image names")
    violating_images = event_functions.extract_images(reasons)

    if args.update_namespaced or args.update_cluster_wide:
        policy_functions.pull_policy(args.policy)
        if args.update_namespaced:
            policy_add_exceptions(image_exceptions=violating_images,
                                  namespace=args.namespace,
                                  namespaced_policy=True)
        if args.update_cluster_wide:
            policy_add_exceptions(image_exceptions=violating_images,
                                  namespaced_policy=False)
        _LOGGER.info("Updating policy")
        policy_functions.push_policy()

    print_tables(reasons)

    _LOGGER.info("Done")
