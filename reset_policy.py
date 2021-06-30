#!/usr/bin/env python3
"""
---
module: reset_update.py

short_description: TODO

description:
    - TODO

configuration:
    Create the following files below /etc/workload-security-credentials/:
    c1_url - cloudone.trendmicro.com:443
    api_key - your API key

usage:
    TODO

author:
    - Markus Winkler (markus_winkler@trendmicro.com)

todo:
    - TODO
"""

import pprint
import argparse
import json
import sys
import logging
from argparse import RawDescriptionHelpFormatter
import requests

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format='%(asctime)s %(levelname)s (%(threadName)s) [%(funcName)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_policy(c1_url, key, policy_name):
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

    url = "https://" + c1_url + "/api/container/policies?" \
        + "&limit=" + str(25)
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
        print(response.text)
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        print(response.text)
        raise SystemExit(err)
    except requests.exceptions.RequestException as err:
        # catastrophic error. bail.
        print(response.text)
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

def reset_policy(c1_url, key, configured_policy):
    """
    Resets all rules ti log and enabled.

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

    # Reset all rules to log and enable them
    _LOGGER.info("Resetting cluster-wide policy definition")
    rule_id = 0
    for rule in configured_policy.get('default', False).get('rules', False):
        configured_policy['default']['rules'][rule_id]['action'] = 'log'
        configured_policy['default']['rules'][rule_id]['mitigation'] = 'log'
        configured_policy['default']['rules'][rule_id]['enabled'] = True
        rule_id += 1

    # Check, if policy is namespaced
    if configured_policy.get('namespaced', False):
        # Reset all namespaced rules to log and enable them
        namespaced_id = 0
        for namespaced in configured_policy.get('namespaced', False):
            _LOGGER.info("Resetting namespaced policy definition for %s",
                         namespaced.get('name', False))
            rule_id = 0
            for rule in namespaced.get('rules', False):
                configured_policy['namespaced'][namespaced_id]['rules'][rule_id]['action'] = 'log'
                configured_policy['namespaced'][namespaced_id]['rules'][rule_id]['mitigation'] = 'log'
                configured_policy['namespaced'][namespaced_id]['rules'][rule_id]['enabled'] = True
                rule_id += 1
            namespaced_id += 1

    # Update policy
    _LOGGER.info("Updating policy")
    url = "https://" + c1_url + "/api/container/policies/" \
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
        description="examples:    reset_policy.py -p relaxed_playground\n",
        formatter_class=RawDescriptionHelpFormatter)
    required_arguments = parser.add_argument_group('required arguments')
    required_arguments.add_argument(
        "-p", "--policy",
        type=str, required=True, help="Cluster policy"
    )
    args = parser.parse_args()

    # API credentials are mounted to /etc
    c1_url = open('/etc/workload-security-credentials/c1_url', 'r').read()
    api_key = open('/etc/workload-security-credentials/api_key', 'r').read()

    policy_cs = get_policy(c1_url, api_key, args.policy)
    reset_policy(c1_url, api_key, policy_cs)

    _LOGGER.info("Done")
