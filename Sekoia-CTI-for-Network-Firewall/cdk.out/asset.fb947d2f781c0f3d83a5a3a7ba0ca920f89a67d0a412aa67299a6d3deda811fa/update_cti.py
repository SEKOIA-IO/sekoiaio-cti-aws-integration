import json
import requests
import boto3

def handler(event, context):
    print('request: {}'.format(json.dumps(event)))
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/plain'
        },
        'body': 'Hello! Welcome everybody, you have hit {}\n'.format(event['path'])
    }
