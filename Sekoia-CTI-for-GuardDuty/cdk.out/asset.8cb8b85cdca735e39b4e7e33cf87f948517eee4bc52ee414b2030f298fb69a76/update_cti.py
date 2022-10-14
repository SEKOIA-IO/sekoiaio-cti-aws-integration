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
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_KEY}"}
    endpoint_ipv4 = "https://app.sekoia.io/v1/aws-gateway/ipv4"

    logging.getLogger().info("Requesting CTI from SEKOIA.IO")
    r = requests.get(f"{endpoint_ipv4}", headers=headers)
    feed = r.text
    file_name="sekoia-cti-ipv4.txt"
    logging.getLogger().info(f"Writing CTI file to /tmp/{file_name}")
    with open(f"/tmp/{file_name}", "w") as fo:
        fo.write(feed)

    # Push to S3
    s3 = boto3.client("s3")
    logging.getLogger().info("Uploading CTI file to S3")
    s3.upload_file(file_name, BUCKET_NAME, file_name)

    
    # Update GuardDuty
    location = f"https://s3.amazonaws.com/{BUCKET_NAME}/{file_name}"
    ThreatIntel_name = "SEKOIA Threat Intel"
    guardduty = boto3.client('guardduty')
    response = guardduty.list_detectors()

    if len(response['DetectorIds']) == 0:
        raise Exception('Failed to read GuardDuty info. Please check if the service is activated')

    detector_id = response["DetectorIds"][0]
    try:
        response = guardduty.create_threat_intel_set(
            Activate=True,
            DetectorId=detectorId,
            Location=location,
            Name=ThreatIntel_name
        )
    except Exception as error:
        if "name already exists" in error.message:
            found = False
            response = guardduty.list_threat_intel_sets(DetectorId=detectorId)
            for setId in response['ThreatIntelSetIds']:
                response = guardduty.get_threat_intel_set(DetectorId=detectorId, ThreatIntelSetId=setId)
                if (ThreatIntel_name == response['Name']):
                    found = True
                    response = guardduty.update_threat_intel_set(
                        Activate=True,
                        DetectorId=detectorId,
                        Location=location,
                        Name=ThreatIntel_name,
                        ThreatIntelSetId=setId
                    )
                    break

            if not found:
                raise

        elif "AWS account limits" in error.message:
            #--------------------------------------------------------------
            # Limit reached. Try to rotate the oldest one
            #--------------------------------------------------------------
            oldestDate = None
            oldestID = None
            response = guardduty.list_threat_intel_sets(DetectorId=detectorId)
            for setId in response['ThreatIntelSetIds']:
                response = guardduty.get_threat_intel_set(DetectorId=detectorId, ThreatIntelSetId=setId)
                tmpName = response['Name']

                if tmpName.startswith('TF-'):
                    setDate = datetime.strptime(tmpName.split('-')[-1], "%Y%m%d")
                    if oldestDate == None or setDate < oldestDate:
                        oldestDate = setDate
                        oldestID = setId

            if oldestID != None:
                response = guardduty.update_threat_intel_set(
                    Activate=True,
                    DetectorId=detectorId,
                    Location=location,
                    Name=ThreatIntel_name,
                    ThreatIntelSetId=oldestID
                )
            else:
                raise

        else:
            raise 
