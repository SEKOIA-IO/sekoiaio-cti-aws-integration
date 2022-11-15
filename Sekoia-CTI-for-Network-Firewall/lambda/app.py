import json
import requests
import boto3
import os
import logging


def handler(event, context):

    # Set logging
    log_level = os.environ.get("LOG_LEVEL")
    if not log_level:
        log_level = "INFO"
    logging.getLogger().setLevel(log_level)

    # Get Parameter
    logging.getLogger().info("Getting ENV variables")
    API_KEY = os.environ.get("API_KEY")

    # Get SEKOIA.IO CTI
    logging.getLogger().info("Preparing request to SEKOIA.IO")
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_KEY}"}
    endpoint = "https://app.sekoia.io/v1/edl-gateway/domain-name"

    logging.getLogger().info("Requesting CTI from SEKOIA.IO")
    r = requests.get(f"{endpoint}", headers=headers)
    feed_list = r.text.split("\n")
    feed_list.pop()  # Last item is empty
    logging.getLogger().debug(f"Feed_list: {feed_list}")
    logging.getLogger().info(f"Feed_list length: {len(feed_list)}")
    feed_set = set(feed_list)
    logging.getLogger().debug(f"Feed_set: {feed_set}")
    logging.getLogger().info(f"Feed_set length: {len(feed_set)}")
    feed_list_unique = list(feed_set)
    logging.getLogger().debug(f"Feed_list_unique: {feed_list_unique}")
    logging.getLogger().info(f"Feed_list_unique length: {len(feed_list_unique)}")
    feed_list_unique_without_unicode = [indicator for indicator in feed_list_unique if "xn--" not in indicator]
    logging.getLogger().info(f"Feed_list_unique_without_unicode: {feed_list_unique_without_unicode}")
    logging.getLogger().info(f"Feed_list_unique_without_unicode length: {len(feed_list_unique_without_unicode)}")

    # Update Firewall Network
    logging.getLogger().info("Starting to update Firewall Network")
    rule_group_name = "SekoiaCTIDomainNameRuleGroup"
    netfw = boto3.client("network-firewall")
    logging.getLogger().info(f"Describing {rule_group_name}")
    response = netfw.describe_rule_group(RuleGroupName=rule_group_name, Type="STATEFUL")
    update_token = response["UpdateToken"]
    logging.getLogger().debug(f"UpdateToken: {update_token}")
    logging.getLogger().info(f"Updating {rule_group_name}")
    response = netfw.update_rule_group(
        UpdateToken=update_token,
        RuleGroupName=rule_group_name,
        RuleGroup={
            "RulesSource": {
                "RulesSourceList": {
                    "Targets": feed_list_unique_without_unicode,
                    "TargetTypes": ["TLS_SNI"],
                    "GeneratedRulesType": "DENYLIST",
                }
            }
        },
        Type="STATEFUL",
    )
    logging.getLogger().info("Updating {rule_group_name} is a success")
