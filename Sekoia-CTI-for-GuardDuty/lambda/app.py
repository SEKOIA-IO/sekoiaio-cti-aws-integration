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
    BUCKET_NAME = os.environ.get("BUCKET_NAME")
    BUCKET_ENDPOINT = os.environ.get("BUCKET_ENDPOINT")

    # Get SEKOIA.IO CTI
    logging.getLogger().info("Preparing request to SEKOIA.IO")
    headers = {"Accept": "application/txt", "Authorization": f"Bearer {API_KEY}"}
    endpoint_ipv4 = "https://app.sekoia.io/v1/edl-gateway/ipv4"

    logging.getLogger().info("Requesting CTI from SEKOIA.IO")
    r = requests.get(f"{endpoint_ipv4}", headers=headers)
    logging.getLogger().info(f"Request result: {r.status_code}")
    feed = r.text
    file_name = "sekoia-cti-ipv4.txt"
    logging.getLogger().info(f"Writing CTI file to /tmp/{file_name}")
    with open(f"/tmp/{file_name}", "w") as fo:
        fo.write(feed)

    # Push to S3
    s3 = boto3.client("s3")
    logging.getLogger().info("Uploading CTI file to S3")
    s3.upload_file(f"/tmp/{file_name}", BUCKET_NAME, file_name)

    # Update GuardDuty
    logging.getLogger().info("Starting to update GuardDuty")
    location = f"https://s3.amazonaws.com/{BUCKET_NAME}/{file_name}"
    ThreatIntel_name = "SEKOIA Threat Intel"
    guardduty = boto3.client("guardduty")
    logging.getLogger().info("Listing GuardDuty Detectors")
    response = guardduty.list_detectors()

    if len(response["DetectorIds"]) == 0:
        raise Exception("Failed to read GuardDuty info. Please check if the service is activated")

    detector_id = response["DetectorIds"][0]
    logging.getLogger().info(f"Detector_id:{detector_id}")

    try:
        found = False
        response = guardduty.list_threat_intel_sets(DetectorId=detector_id)
        logging.getLogger().info("Listing for Sekoia ThreatIntelSet")
        logging.getLogger().info(f"Response: {response}")

        for setId in response["ThreatIntelSetIds"]:
            response = guardduty.get_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=setId)
            logging.getLogger().info(f"Getting {ThreatIntel_name}")
            logging.getLogger().info(f"Response: {response}")
            if ThreatIntel_name == response["Name"]:
                found = True
                logging.getLogger().info("Updating GuardDuty ThreatIntelSets")
                response = guardduty.update_threat_intel_set(
                    Activate=True,
                    DetectorId=detector_id,
                    Location=location,
                    Name=ThreatIntel_name,
                    ThreatIntelSetId=setId,
                )
                logging.getLogger().info(f"Response: {response}")
                break

        if not found:
            raise

        logging.getLogger().info("Ending in success!")

    except Exception as error:
        logging.getLogger().error(f"Ending in error: {error}")
