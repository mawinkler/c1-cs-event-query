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

import argparse
import sys
import logging
from argparse import RawDescriptionHelpFormatter

from helper_functions import PolicyFunctions

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format='%(asctime)s %(levelname)s (%(threadName)s) [%(funcName)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


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
    c1_url = open('/etc/cloudone-credentials/c1_url', 'r').read()[:-1]
    api_key = open('/etc/cloudone-credentials/api_key', 'r').read()[:-1]

    policy_functions = PolicyFunctions(c1_url, api_key)

    policy_functions.pull_policy(args.policy)
    policy_functions.reset_policy()
    policy_functions.push_policy()

    _LOGGER.info("Done")
