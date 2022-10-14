import json
import requests
import boto3
import os

def handler(event, context):

    # Get Parameter
    API_KEY = os.environ.get("API_KEY")
    BUCKET_NAME = os.environ.get("BUCKET_NAME")
    BUCKET_ENDPOINT = os.environ.get("BUCKET_ENDPOINT")

    # Get SEKOIA.IO CTI
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_KEY}"}
    endpoint_ipv4 = "app.sekoia.io/v1/aws-gateway/ipv4"

    r = requests.get(f"{endpoint_ipv4}", headers=headers)
    feed = r.text
    file_name=sekoia-cti-ipv4.txt
    with open(file_name, "w") as fo:
        fo.write(feed)

    # Push to S3
    s3 = boto3.client("s3")
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
