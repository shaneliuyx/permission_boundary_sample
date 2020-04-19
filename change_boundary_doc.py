from __future__ import print_function  # Python 2/3 compatibility
import re
import json
import boto3
import botocore
import zlib
import base64
import decimal
import os

from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError


def get_resourceId_or_arn(event):
    # Find resource type from event message, for example: if resource type is instance, we can find it from instanceId.
    # All resource types in event message  will be saved in candidate_match.
    # Event name = api call+resource type. For example, RunInstance, CreateSecurityGroup, etc.
    # If we run RunInstance, we need to get instanceId, if we run CreateSecurityGroup, we need to get groupId.
    # The Id name is saved in "candidate"
    arn = ''
    action = ''
    resourceId = ''
    api_call = event['eventName']
    print("===>get_resourceId_or_arn:api_call: ", api_call)
    #print (api_call)
    if (re.search('create', api_call, re.IGNORECASE)):
        action = 'add'
    elif re.search('run', api_call, re.IGNORECASE):
        action = 'add'
    else:
        action = 'remove'


# Find resource ID from responseElements
    pattern = r"(\w*)Id"
    text = json.dumps(event['responseElements'])
    print("===>get_resourceId_or_arn:responseElements: ", text)
    candidate_match = re.findall(pattern, text)
    for term in candidate_match:
        if re.search(term, api_call, re.IGNORECASE):
            candidate = term + 'Id'
            if candidate == "versionId":  # verionid is useless, and verion does not have arn
                return action, resourceId, arn

            else:
                pattern1 = "\"" + candidate + '": '
                pattern2 = r'"([\w:/-]*)"'
                pattern = pattern1 + pattern2
                candidate_match = re.findall(pattern, text)
                if candidate_match:
                    resourceId = candidate_match[0]
                    print("===>get_resourceId_or_arn:resourceId: ", resourceId)
# If there is no resource ID, find a resource name instead
    if resourceId == "":
        pattern = r"(\w*)Name"
        #text = json.dumps(event['requestParameters'])
        #print ("===>get_resourceId_or_arn:responseElements: ",text )
        candidate_match = re.findall(pattern, text)
        for term in candidate_match:
            if re.search(term, api_call, re.IGNORECASE):
                candidate = term + 'Name'
                # logStreanm and LogGroup are useless, they do not have arn
                if (candidate == "logGroupName") or (candidate == "logStreamName"):
                    return action, resourceId, arn

                else:
                    pattern1 = "\"" + candidate + '": '
                    pattern2 = r'"([\w:/-]*)"'
                    pattern = pattern1 + pattern2
                    candidate_match = re.findall(pattern, text)
                    if candidate_match:
                        resourceId = candidate_match[0]
                        print("===>get_resourceId_or_arn:resourceId: ", resourceId)
                        arn = resourceId

   # if resourceId=="":
    arn_pattern1 = 'arn": '
    arn_pattern2 = r'"([\w:/-]*)"'
    arn_pattern = arn_pattern1 + arn_pattern2
    candidate_match_arn = re.findall(
        arn_pattern, text, re.IGNORECASE)
    if candidate_match_arn:
        arn = candidate_match_arn[0]
        print("===>get_resourceId_or_arn:arn: ", arn)
        # if arn !='':
        #    return action, resourceId, arn
# if we cannot find resource ID from responseElements, we try to find it from requestParameters
    if resourceId == "":
        text = json.dumps(event['requestParameters'])
        print("===>get_resourceId_or_arn:requestParameters: ", text)
        #print (event['requestParameters'] )
        candidate_match = re.findall(pattern, text)
        for term in candidate_match:
            if re.search(term, api_call, re.IGNORECASE):
                candidate = term + 'Id'
                if candidate == "versionId":  # verionid is useless, and verion does not have arn
                    return action, resourceId, arn
                else:
                    pattern1 = "\"" + candidate + '": '
                    pattern2 = r'"([\w:/-]*)"'
                    pattern = pattern1 + pattern2
                    #print("pattern:", pattern)
                    candidate_match = re.findall(pattern, text)
                    if candidate_match:
                        resourceId = candidate_match[0]
                        print("===>get_resourceId_or_arn:resourceId: ", resourceId)
# If there is no resource ID, find a resource name instead
    if resourceId == "":
        pattern = r"(\w*)Name"
        #text = json.dumps(event['requestParameters'])
        #print ("===>get_resourceId_or_arn:responseElements: ",text )
        candidate_match = re.findall(pattern, text)
        for term in candidate_match:
            if re.search(term, api_call, re.IGNORECASE):
                candidate = term + 'Name'
                # logStreanm and LogGroup are useless, they do not have arn
                if (candidate == "logGroupName") or (candidate == "logStreamName"):
                    return action, resourceId, arn

                else:
                    pattern1 = "\"" + candidate + '": '
                    pattern2 = r'"([\w:/-]*)"'
                    pattern = pattern1 + pattern2
                    candidate_match = re.findall(pattern, text)
                    if candidate_match:
                        resourceId = candidate_match[0]
                        print("===>get_resourceId_or_arn:resourceId: ", resourceId)

    if resourceId == '':
        arn_pattern1 = 'arn": '
        arn_pattern2 = r'"([\w:/-]*)"'
        arn_pattern = arn_pattern1 + arn_pattern2
        candidate_match_arn = re.findall(
            arn_pattern, text, re.IGNORECASE)
        if candidate_match_arn:
            arn = candidate_match_arn[0]
            print("===>get_resourceId_or_arn:arn: ", arn)
            # if arn !='':
            #print (action, resourceId, arn)
            # return action, resourceId, arn

    """ if (arn == '') & (resourceId == ''):
        if re.search('url', text, re.IGNORECASE):
            pattern = r'([\w_]+)"$'
            candidate_match = re.findall(pattern, text)
            if candidate_match:
                resourceId = candidate_match[0] """
    return action, resourceId, arn


def get_cloudtrail_event(event):
    data = base64.b64decode(event['awslogs']['data'])
    data = zlib.decompress(data, 16 + zlib.MAX_WBITS)
    cloudtrail_event = json.loads(data)
    return cloudtrail_event


def get_message_from_cloudtrail_event(log_event):
    message = log_event['message']
    message = json.loads(message)
    new_message = {}
    new_message['eventName'] = message['eventName']
    new_message['responseElements'] = message['responseElements']
    new_message['requestParameters'] = message['requestParameters']
    return (new_message)


def get_policy_body(arn, version_id=None):
    """ Return IAM Policy JSON body """
    iam = boto3.resource('iam')
    if version_id:
        version = iam.PolicyVersion(arn, version_id)
    else:
        policy = iam.Policy(arn)
        version = policy.default_version
    return version.document


def generate_restrict_action(arn):
    read_only_access_arn = "arn:aws-cn:iam::aws:policy/ReadOnlyAccess"
    body = get_policy_body(url_only_access_arn)
    read_only_action = body['Statement'][0]["Action"]
    service = arn.split(':')[2]
    result = []
    for action in read_only_action:
        if service == action.split(':')[0]:
            result.append(action)
    return result


def add_resource_to_policy_doc(resource_arn, policy_arn):

    #
    #   body template:
    #   {
    #    "Version": "2012-10-17",
    #    "Statement": [{
    #        "Sid": "Restrict read-only policy on specified resources",
    #        "Effect": "Deny",
    #        "NotAction": ["iam:Generate*","iam:Get*","iam:List*","iam:Simulate*"]
    #        "Resource": ["arn:aws-cn:iam::238303532267:role/service-role/permission_boundary-role-37wg6jor"]
    #                }]
    #    }

    #   based on resource arn, generate read-only actions
    new_action = generate_restrict_action(resource_arn)

    temp_list = []
    temp_list.append(resource_arn)
    body = get_policy_body(policy_arn)
    for sta in body['Statement']:
        if sta['Effect'] == 'Deny':
            if type(sta['Resource']) == str:
                temp_list.append(sta['Resource'])
            else:
                temp_list = list(set(temp_list) | set(sta['Resource']))
            if type(sta['NotAction']) == str:
                temp = []
                temp.append(sta['NotAction'])
                sta['NotAction'] = temp
            sta['Resource'] = temp_list  # update resource list
            # update action list and remove duplication
            sta['NotAction'] = list(set(sta['NotAction']) | set(new_action))

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
    print("New policy:\n: %s" % json.dumps(body))


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
    # generate NotAction list based on resources
    new_action = []
    for item in sta['Resource']:
        new_action = list(set(new_action) | set(
            (generate_restrict_action(item))))
    sta['NotAction'] = new_action

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
        print("New policy\n: %s" % json.dumps(body))
    else:
        print("Cannot find resource arn (%s) in policy document!" % resource_arn)


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
            print("Item does not exist in DB")
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


def put_task_to_queue(task, queue):
    sqs = boto3.client('sqs')
    try:
        response = sqs.get_queue_url(QueueName=queue)
    except:
        response = sqs.create_queue(QueueName=queue)
    queue_url = response['QueueUrl']
    response = sqs.send_message(
        QueueUrl=queue_url, MessageBody=json.dumps(task))


def lambda_handler(event, context):
    print("Got an event:\n")
    print(event)
    # need to set policy ARN
    queue_name = os.environ['QUEUE']
    policy_arn = os.environ['POLICY_ARN']
    # policy_arn = 'arn:aws-cn:iam::238303532267:policy/test_boundary_policy'
    # queue = 'pb_cloudtrail'
    policy_doc = get_policy_body(policy_arn)
    cloudtrail_event = get_cloudtrail_event(event)
    print("\n Decrypted event:\n")
    print(cloudtrail_event)
    for log_event in cloudtrail_event['logEvents']:
        arn = ''
        key = ''
        task = {}
        trail_message = get_message_from_cloudtrail_event(log_event)
        action, id, arn = get_resourceId_or_arn(trail_message)
        print("handler->action:id:arn => ", action, ":", id, ":", arn)
        if (arn != ''):
            if action == 'add':
                add_resource_to_policy_doc(arn, policy_arn)
            if action == 'remove':
                remove_resource_from_policy_doc(id, arn, policy_arn)
            return
        if (id != ''):
            if action == 'add':
                arn, key = get_arn_from_db(id, 'add_resourceArn')
                if arn:
                    add_resource_to_policy_doc(arn, policy_arn)
                    delete_arn_from_db(key, 'add_resourceArn')
            if action == 'remove':
                try:
                    arn, key = get_arn_from_db(id, 'delete_resourceArn')
                except:
                    print("Cannot find  %s from DB " % id)
                remove_resource_from_policy_doc(id, arn, policy_arn)
                try:
                    delete_arn_from_db(key, 'delete_resourceArn')
                except:
                    print("Cannot delete %s from DB" % key)
            if (action != '') & (arn == ''):
                task['action'] = action
                task['id'] = id
                put_task_to_queue(task, queue_name)
                print("Cannot find resource (%s) arn, put it in queue " % id)
