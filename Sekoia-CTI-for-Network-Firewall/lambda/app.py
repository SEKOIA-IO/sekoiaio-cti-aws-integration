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
    # We filter all domain name containing "_" because AWS Network Firewall consider them invalid.
    filtered_feed_list = [indicator for indicator in feed_list if "_" not in indicator]
    logging.getLogger().debug(f"Feed_list_unique_without_unicode: {filtered_feed_list}")
    logging.getLogger().info(f"Feed_list_unique_without_unicode length: {len(filtered_feed_list)}")

    # Update Network Firewall
    logging.getLogger().info("Starting to update Firewall Network")
    rule_group_name = "SekoiaCTIDomainNameRuleGroup"
    netfw = boto3.client("network-firewall")
    logging.getLogger().info(f"Describing {rule_group_name}")
    response = netfw.describe_rule_group(RuleGroupName=rule_group_name, Type="STATEFUL")
    update_token = response["UpdateToken"]
    logging.getLogger().debug(f"UpdateToken: {update_token}")
    logging.getLogger().info(f"Updating {rule_group_name}")
    # We limit to 30000 first indicators due to AWS Network Firewall limitation.
    response = netfw.update_rule_group(
        UpdateToken=update_token,
        RuleGroupName=rule_group_name,
        RuleGroup={
            "RulesSource": {
                "RulesSourceList": {
                    "Targets": filtered_feed_list[:30000],
                    "TargetTypes": ["TLS_SNI"],
                    "GeneratedRulesType": "DENYLIST",
                }
            }
        },
        Type="STATEFUL",
    )
    logging.getLogger().info("Updating {rule_group_name} is done.")
