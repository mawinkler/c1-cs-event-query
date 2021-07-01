#!/usr/bin/env python3
"""
---
module: helper_functions.py

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

import json
import sys
import logging
import requests
from datetime import datetime, timedelta

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format='%(asctime)s %(levelname)s (%(threadName)s) [%(funcName)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

class EventFunctions:
    """Some function to help dealing with events"""

    def __init__(self, c1_url, api_key):
        self.c1_url = c1_url
        self.api_key = api_key

    def collect_reasons(this, cluster_name, decision, mitigation, namespace, policy_name):
        """
        Queries for events with a given set of filters and returns a filtered list of
        reasons.

        Parameters
        ----------
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
        Array with reasons violating the policy
        """

        # The interval for continuous rescans of the cluster is 60 minutes by default
        start_time = (datetime.utcnow() - timedelta(minutes=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        _LOGGER.info("Start time: %s", start_time)
        _LOGGER.info("End time: %s", end_time)

        cursor = ""
        results = []
        while True:
            url = "https://" + this.c1_url + "/api/container/events/evaluations?" \
                + "next=" + cursor \
                + "&limit=" + str(25) \
                + "&policyName=" + policy_name \
                + "&fromTime=" + start_time \
                + "&toTime=" + end_time
            post_header = {
                "Content-Type": "application/json",
                "api-secret-key": this.api_key,
                "api-version": "v1",
            }

            try:
                response = requests.get(
                    url, headers=post_header, verify=True
                )
                response.encoding = response.apparent_encoding
                response.raise_for_status()
            except requests.exceptions.Timeout as err:
                _LOGGER.error(response.text)
                raise SystemExit(err)
            except requests.exceptions.HTTPError as err:
                _LOGGER.error(response.text)
                raise SystemExit(err)
            except requests.exceptions.RequestException as err:
                # catastrophic error. bail.
                _LOGGER.error(response.text)
                raise SystemExit(err)

            response = response.json()
            # Error handling
            if "message" in response:
                if response.get('message', "") == "Invalid API Key":
                    _LOGGER.error("API error: %s", response['message'])
                    raise ValueError("Invalid API Key")

            # Parse the response
            events_count = len(response.get('events', {}))
            _LOGGER.debug("Number of events in result set: %d", len(results))
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
                                _LOGGER.debug("Event in scope at timestamp %s",
                                            event.get('timestamp', None))
                                result = {
                                    "type": reason.get('type', None),
                                    "namespace": event.get('namespace', ""),
                                    "container": resource.get('container', None),
                                    "pod": resource.get('object', None),
                                    "image": resource.get('image', None),
                                    "rule": reason.get('rule', None)
                                }
                                if result not in results:
                                    results.append(result)
            cursor = response.get('next', "")
            if cursor == "":
                break

        # Sort results by pod name
        results = sorted(results, key=lambda k: k['pod'])
        
        _LOGGER.info("Number of filtered reasons: %d", len(results))

        return results

    def extract_images(this, reasons):
        """
        Extracts mentioned images from a given set of reasons

        Parameters
        ----------
        reasons             The reasons for the events.

        Raises
        ------
        Exception

        Returns
        -------
        Array with images violating the policy
        """

        # Sort reasons by pod name
        reasons = sorted(reasons, key=lambda k: k['pod'])
        images = []

        if len(reasons) > 0:
            # Generate a list of event types
            event_types = []
            for reason in reasons:
                event_type = reason.get('type', None)
                if event_type not in event_types:
                    event_types.append(event_type)

            # Print the tables
            for event_type in event_types:
                for reason in reasons:
                    if reason.get('type', None) == event_type:
                        if reason.get('image', None) not in images \
                        and reason.get('image', None) is not None:
                            images.append(reason.get('image', None))
        else:
            _LOGGER.info("No evaluations found.")

        _LOGGER.info("Number of violating images: %d", len(images))

        return images

class PolicyFunctions:
    """Some functions to help dealing with policies"""

    def __init__(self, c1_url, api_key):
        self.c1_url = c1_url
        self.api_key = api_key

    def is_namespaced(self, policy):
        return policy.get('namespaced', False)
        
    def get_policy(self, policy_name):
        """
        Retrieves the policy with a given name.

        Parameters
        ----------
        policy_name         Name of the policy to return

        Raises
        ------
        Exception

        Returns
        -------
        Policy
        """

        url = "https://" + self.c1_url + "/api/container/policies?" \
            + "&limit=" + str(25)
        post_header = {
            "Content-Type": "application/json",
            "api-secret-key": self.api_key,
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
        _LOGGER.info("Total number of policies: %s", policies_count)
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

    def reset_policy(self, configured_policy):
        """
        Resets all rules ti log and enabled.

        Parameters
        ----------
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
        rule_count = len(configured_policy.get('default', False).get('rules', False))

        for rule_id in range(rule_count):
            configured_policy['default']['rules'][rule_id]['action'] = 'log'
            configured_policy['default']['rules'][rule_id]['mitigation'] = 'log'
            configured_policy['default']['rules'][rule_id]['enabled'] = True

        # Check, if policy is namespaced
        if configured_policy.get('namespaced', False):
            # Reset all namespaced rules to log and enable them
            namespaced_id = 0
            for namespaced in configured_policy.get('namespaced', False):
                _LOGGER.info("Resetting namespaced policy definition for %s",
                             namespaced.get('name', False))
                rule_count = len(namespaced.get('rules', False))
                for rule_id in range(rule_count):
                    configured_policy['namespaced'][namespaced_id]['rules'][rule_id]['action'] = 'log'
                    configured_policy['namespaced'][namespaced_id]['rules'][rule_id]['mitigation'] = 'log'
                    configured_policy['namespaced'][namespaced_id]['rules'][rule_id]['enabled'] = True
                namespaced_id += 1

        # Update policy
        _LOGGER.info("Updating policy")
        url = "https://" + self.c1_url + "/api/container/policies/" \
            + configured_policy.get('id', False)
        post_header = {
            "Content-Type": "application/json",
            "api-secret-key": self.api_key,
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