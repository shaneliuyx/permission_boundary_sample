import json
import os
import boto3
import re


def get_policy_body(arn, version_id=None):
    """ Return IAM Policy JSON body """
    if version_id:
        version = iam.PolicyVersion(arn, version_id)
    else:
        policy = iam.Policy(arn)
        version = policy.default_version
    return version.document


def get_create_arn(event):
    try:
        if event['detail']['configurationItemDiff']['changeType'] == 'CREATE':
            return(event['detail']['configurationItem']['ARN'])
    except:
        return("")


def get_delete_arn(event):
    try:
        if event['detail']['configurationItemDiff']['changeType'] == 'DELETE':
            return(event['detail']['configurationItem']['ARN'])
    except:
        return("")


def create_table(table_name):
    client = boto3.client('dynamodb')
    dynamodb = boto3.resource('dynamodb')
    response = client.list_tables()
    if not(table_name in response['TableNames']):
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {
                    'KeyType': 'HASH',
                    'AttributeName': 'resource_id'
                },
                {
                    'KeyType': 'RANGE',
                    'AttributeName': 'resource_arn'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'resource_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'resource_arn',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 2,
                'WriteCapacityUnits': 2
            }
        )
        # Wait until the table creation complete.
        table.meta.client.get_waiter('table_exists').wait(TableName='Employee')
        return table
    else:
        return (dynamodb.Table(table_name))


def initialize():
    table_name1 = 'add_resourceArn'
    add_resource_table = create_table(table_name1)
    table_name2 = 'delete_resourceArn'
    delete_resource_table = create_table(table_name2)
    # return add_resource_table, delete_resource_table


def write_to_db(table, id, arn):
    if arn:
        client = boto3.client('dynamodb')
        client.put_item(TableName=table, Item={'resource_id': {
                        'S': id, }, 'resource_arn': {'S': arn}})


def extract_id(t):
    if t:
        pattern = r"[-\w]*$"
        match = re.findall(pattern, t)
        return match[0]


def lambda_handler(event, context):
    print (event)
    add_arn = ''
    add_id = ''
    delete_id = ''
    delete_arn = ''
    initialize()
    add_arn = get_create_arn(event)
    add_id = extract_id(add_arn)
    write_to_db('add_resourceArn', add_id, add_arn)
    delete_arn = get_delete_arn(event)
    delete_id = extract_id(delete_arn)
    write_to_db("delete_resourceArn", delete_id, delete_arn)
