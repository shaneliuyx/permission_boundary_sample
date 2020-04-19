from __future__ import print_function  # Python 2/3 compatibility
import boto3
import json
import decimal
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import re
import os


def get_task_from_queue(queue_name):
    sqs_client = boto3.client('sqs')
    try:
        response = sqs_client.get_queue_url(QueueName=queue_name)
    except:
        print ("The queue (%s) does not exist" % queue_name)
        return []
    queue_url = response['QueueUrl']

    messages = []

    while True:
        resp = sqs_client.receive_message(QueueUrl=queue_url, AttributeNames=[
                                          'All'], MaxNumberOfMessages=10)
        #print (resp)

        try:
            messages.extend(resp['Messages'])
        except KeyError:
            break

        entries = [{'Id': msg['MessageId'], 'ReceiptHandle': msg['ReceiptHandle']}
                   for msg in resp['Messages']]

        resp = sqs_client.delete_message_batch(
            QueueUrl=queue_url, Entries=entries)

        if len(resp['Successful']) != len(entries):
            raise RuntimeError(f"Failed to delete messages: entries={entries!r} resp={resp!r}")

    return messages


def put_task_to_queue(task, queue):
    sqs = boto3.client('sqs')
    try:
        response = sqs.get_queue_url(QueueName=queue)
    except:
        response = sqs.create_queue(QueueName=queue)
    queue_url = response['QueueUrl']
    response = sqs.send_message(
        QueueUrl=queue_url, MessageBody=json.dumps(task))


def get_policy_body(arn, version_id=None):
    """ Return IAM Policy JSON body """
    iam = boto3.resource('iam')
    if version_id:
        version = iam.PolicyVersion(arn, version_id)
    else:
        policy = iam.Policy(arn)
        version = policy.default_version
    return version.document


def add_resource_to_policy_doc(resource_arn, policy_arn):
    temp_list = []
    temp_list.append(resource_arn)
    body = get_policy_body(policy_arn)
    for sta in body['Statement']:
        if sta['Effect'] == 'Deny':
            if type(sta['Resource']) == str:
                temp_list.append(sta['Resource'])
            else:
                for element in sta['Resource']:
                    temp_list.append(element)
            sta['Resource'] = temp_list

    client = boto3.client('iam')

    # delete previous version policy
    response = client.list_policy_versions(PolicyArn=policy_arn)
    for item in response['Versions']:
        if item['IsDefaultVersion'] == False:
            version_id = item['VersionId']
            client.delete_policy_version(
                PolicyArn=policy_arn, VersionId=version_id)

    # add new version policy
    response = client.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=json.dumps(body), SetAsDefault=True)

    # delete previous version policy
    response = client.list_policy_versions(PolicyArn=policy_arn)
    for item in response['Versions']:
        if item['IsDefaultVersion'] == False:
            version_id = item['VersionId']
            client.delete_policy_version(
                PolicyArn=policy_arn, VersionId=version_id)

    print("Add resource to policy: %s" % resource_arn)
    print ("New policy:\n: %s" % json.dumps(body))


def remove_resource_from_policy_doc(resource_id, resource_arn, policy_arn):
    remove_success = False
    temp_list = []
    body = get_policy_body(policy_arn)
    if resource_id:
        for sta in body['Statement']:
            if sta['Effect'] == 'Deny':
                if type(sta['Resource']) == str:
                    if (re.search(resource_id, sta['Resource'], re.IGNORECASE)):
                        remove_success = True
                    else:
                        temp_list.append(element)
                else:
                    for element in sta['Resource']:
                        if (re.search(resource_id, element, re.IGNORECASE)):
                            remove_success = True
                        else:
                            temp_list.append(element)
                sta['Resource'] = temp_list
    elif resource_arn:
        for sta in body['Statement']:
            if sta['Effect'] == 'Deny':
                if type(sta['Resource']) == str:
                    if sta['Resource'] != resource_arn:
                        temp_list.append(element)
                    else:
                        remove_success = True
                else:
                    for element in sta['Resource']:
                        if element != resource_arn:
                            temp_list.append(element)
                        else:
                            remove_success = True
                sta['Resource'] = temp_list

    client = boto3.client('iam')
    # delete previous version policy
    response = client.list_policy_versions(PolicyArn=policy_arn)
    for item in response['Versions']:
        if item['IsDefaultVersion'] == False:
            version_id = item['VersionId']
            client.delete_policy_version(
                PolicyArn=policy_arn, VersionId=version_id)

    # add new version policy
    response = client.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=json.dumps(body), SetAsDefault=True)

    # delete previous version policy
    response = client.list_policy_versions(PolicyArn=policy_arn)
    for item in response['Versions']:
        if item['IsDefaultVersion'] == False:
            version_id = item['VersionId']
            client.delete_policy_version(
                PolicyArn=policy_arn, VersionId=version_id)
    if remove_success:
        print("Remove resource from policy: %s" % resource_arn)
        print ("New policy:\ %s" % json.dumps(body))
    else:
        print ("Cannot find resource arn (%s) in policy document!" % resource_arn)


def get_arn_from_db(id, table_name):
    arn = ''
    # Helper class to convert a DynamoDB item to JSON.

    class DecimalEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, decimal.Decimal):
                if o % 1 > 0:
                    return float(o)
                else:
                    return int(o)
            return super(DecimalEncoder, self).default(o)

    dynamodb = boto3.resource("dynamodb")

    table = dynamodb.Table(table_name)

    try:
        response = table.query(
            KeyConditionExpression=Key('resource_id').eq(id))
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        item = response['Items']
        if item != []:
            print("GetItem succeeded:")
            print(json.dumps(item, indent=4, cls=DecimalEncoder))
            return response['Items'][0]['resource_arn'], response['Items'][0]
        else:
            print("Item does not exist")
            return ("", "")


def delete_arn_from_db(key, table_name):

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    try:
        response = table.delete_item(Key=key)
    except ClientError as e:
        if e.response['Error']['Code'] == "ConditionalCheckFailedException":
            print(e.response['Error']['Message'])
        else:
            raise
    else:
        print("DeleteItem succeeded")


def lambda_handler(event, context):
    queue_name = os.environ['QUEUE']
    policy_arn = os.environ['POLICY_ARN']
    tasks = get_task_from_queue(queue_name)
    task = {}
    for message in tasks:
        msg_body = json.loads(message['Body'])
        action = msg_body['action']
        id = msg_body['id']

        if action == 'add':
            arn, key = get_arn_from_db(id, 'add_resourceArn')
            if arn:
                add_resource_to_policy_doc(arn, policy_arn)
                delete_arn_from_db(key, 'add_resourceArn')
                #print ("Successfully add arn (%s) to policy" % arn)
        if action == 'remove':
            arn, key = get_arn_from_db(id, 'delete_resourceArn')
            if arn:
                remove_resource_from_policy_doc(id, arn, policy_arn)
                delete_arn_from_db(key, 'delete_resourceArn')
                #print ("Successfully remove arn (%s) ftom policy" % arn)
        if (action != '') & (arn == ''):
            task['action'] = action
            task['id'] = id
            put_task_to_queue(task, queue_name)
            print ("Cannot find resource (%s) arn, put it in queue " % id)
