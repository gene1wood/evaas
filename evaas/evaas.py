import base64
import json
import logging
import os
import time

import boto3
import boto3.dynamodb.conditions

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)

MIN_SECONDS_BETWEEN_VERIFICATION_EMAILS = 15
EMAIL_TEXT_TEMPLATE = '''{welcome}

{please activate}
{activate}: {verification url}

{automated email}'''
EMAIL_HTML_TEMPLATE = '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <title>{service name}</title>
</head>

<body style="-ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; margin: 0; padding: 0;">
<table align="center" border="0" cellpadding="0" cellspacing="0" width="310" style="-webkit-text-size-adjust: 100%; border-collapse: collapse; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 310px; margin: 0 auto;">

<!--Logo-->
<!--
<tr style="page-break-before: always">
  <td align="center" id="firefox-logo" style="padding: 20px 0;">
    <img src="http://examle.com/example.gif" height="95" width="88" alt="" style="-ms-interpolation-mode: bicubic;" />
  </td>
</tr>
-->

<!--Header Area-->
<tr style="page-break-before: always">
  <td valign="top">
    <h1 style="font-family: sans-serif; font-weight: normal; margin: 0 0 24px 0; text-align: center;">{welcome}</h1>
    <p class="primary" style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0 0 24px 0; text-align: center;">{please activate}</p>
  </td>
</tr>

<!--Button Area-->
<tr height="50">
  <td align="center" valign="top">
    <table border="0" cellpadding="0" cellspacing="0" height="100%" width="100%" id="email-button" style="-webkit-text-size-adjust: 100%; border-collapse: collapse; mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: #0095dd; border-radius: 4px; height: 50px; width: 310px !important;">
      <tr style="page-break-before: always">
        <td align="center" valign="middle" id="button-content" style="font-family: sans-serif; font-weight: normal; text-align: center; margin: 0; color: #ffffff; font-size: 20px; line-height: 100%;">
          <!--[if mso]>
          <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="{verification url}" style="width:280px;height:40px;v-text-anchor:middle;" arcsize="10%" stroke="f" fillcolor="#0095DD">
            <w:anchorlock/>
            <center>
          <![endif]-->
          <a href="{verification url}" id="button-link" style="font-family:sans-serif; color: #fff; display: block; padding: 15px; text-decoration: none; width: 280px;">{activate}</a>
          <!--[if mso]>
          </center>
          </v:roundrect>
          <![endif]-->
        </td>
      </tr>
    </table>
  </td>
</tr>
<!--Button Area-->
<tr style="page-break-before: always">
  <td border="0" cellpadding="0" cellspacing="0" height="100%" width="100%">
    <br/>
    <p width="310" class="secondary" style="font-family: sans-serif; font-weight: normal; margin: 0 0 24px 0; text-align: center; color: #8A9BA8; font-size: 11px; line-height: 13px; width: 310px !important; word-wrap: break-word; word-break: break-all">{alternatively}<a href="{verification url}" style="color: #0095dd; text-decoration: none; width: 310px !important; display:block;"><br/><font style="word-break:break-all;">{verification url}</font></a></p>
    <p class="secondary" style="font-family: sans-serif; font-weight: normal; margin: 0; text-align: center; color: #8A9BA8; font-size: 11px; line-height: 13px; width: 310px !important; word-wrap:break-word">{automated email}</p>
  </td>
</tr>

</table>

<div itemscope itemtype="https://schema.org/EmailMessage">
  <div itemprop="potentialAction" itemscope itemtype="https://schema.org/ViewAction">
    <link itemprop="target" href="{verification url}"/>
    <meta itemprop="name" content="{verify email}"/>
    <meta itemprop="url" content="{verification url}"/>
  </div>
  <meta itemprop="description" content="{verify your email}"/>
</div>

</body>
</html>'''
VERIFICATION_RESULT_TEMPLATE='''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <title>{title}</title>
</head>

<body style="-ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; margin: 0; padding: 0;">
<table align="center" border="0" cellpadding="0" cellspacing="0" width="310" style="-webkit-text-size-adjust: 100%; border-collapse: collapse; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 310px; margin: 0 auto;">

<!--Logo-->
<!--
<tr style="page-break-before: always">
  <td align="center" id="firefox-logo" style="padding: 20px 0;">
    <img src="http://examle.com/example.gif" height="95" width="88" alt="" style="-ms-interpolation-mode: bicubic;" />
  </td>
</tr>
-->

<!--Header Area-->
<tr style="page-break-before: always">
  <td valign="top">
    <h1 style="font-family: sans-serif; font-weight: normal; margin: 0 0 24px 0; text-align: center;">{result}</h1>
    <p class="primary" style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0 0 24px 0; text-align: center;">{result text}</p>
  </td>
</tr>

<!--
<tr style="page-break-before: always">
  <td border="0" cellpadding="0" cellspacing="0" height="100%" width="100%">
    <br/>
    <p width="310" class="secondary" style="font-family: sans-serif; font-weight: normal; margin: 0 0 24px 0; text-align: center; color: #8A9BA8; font-size: 11px; line-height: 13px; width: 310px !important; word-wrap: break-word; word-break: break-all">footer title</p>
    <p class="secondary" style="font-family: sans-serif; font-weight: normal; margin: 0; text-align: center; color: #8A9BA8; font-size: 11px; line-height: 13px; width: 310px !important; word-wrap:break-word">footer text</p>
  </td>
</tr>
-->
</table>
</body>
</html>'''


USER_LOCALE = 'en'
EMAIL_LOCALIZATION_STRINGS = {'en':
                              {'verify your account': 'Verify your account',
                               'welcome': 'Welcome!',
                               'please activate': 'Please activate your account by confirming this email address.',
                               'activate': 'Activate now',
                               'alternatively': 'Alternatively :',
                               'automated email': 'This is an automated email; if you received it in error, no action is required.',
                               'verify email': 'Verify Email',
                               'verify your email': 'Verify your email to finish your registration'}
                              }


class PythonObjectEncoder(json.JSONEncoder):
    """Custom JSON Encoder that allows encoding of un-serializable objects
    For object types which the json module cannot natively serialize, if the
    object type has a __repr__ method, serialize that string instead.
    Usage:
        >>> example_unserializable_object = {'example': set([1,2,3])}
        >>> print(json.dumps(example_unserializable_object,
                             cls=PythonObjectEncoder))
        {"example": "set([1, 2, 3])"}
    """

    def default(self, obj):
        if isinstance(obj,
                      (list, dict, str, unicode,
                       int, float, bool, type(None))):
            return json.JSONEncoder.default(self, obj)
        elif hasattr(obj, '__repr__'):
            return obj.__repr__()
        else:
            return json.JSONEncoder.default(self, obj.__repr__())


class ClientException(Exception):
    def __init__(self, *args):
        self.args = args
        # AWS API Gateway Integration Response Regex : ClientError :.*
        self.prefix = "ClientError : %s"

    def __str__(self):
        if len(self.args) == 1:
            return str(self.prefix % self.args[0])
        else:
            return str(self.args)

class ServerException(Exception):
    def __init__(self, *args):
        self.args = args
        # AWS API Gateway Integration Response Regex : ServerError :.*
        self.prefix = "ServerError : %s"

    def __str__(self):
        if len(self.args) == 1:
            return str(self.prefix % self.args[0])
        else:
            return str(self.args)

def sanitize_service_name(service_name):
    # TODO Sanitize the service_name
    return service_name

def filter_dict(dictionary):
    return {key: dictionary[key]
            for key
            in dictionary.keys()
            if dictionary[key] not in [None, '']}

def create_rp(event, context):
    if 'body' not in event:
        raise ServerException('"body" object missing')
    if 'email' not in event['body']:
        raise ClientException('"email" parameter missing')
    if 'X-Forwarded-For' not in event:
        raise ServerException('"X-Forwarded-For" parameter missing')
    # TODO : Allow RPs to register a callback URL where EVaaS can notify that a user has verified

    service_name = event['body']['service_name'] if 'service_name' in event['body'] else None
    region = context.invoked_function_arn.split(':')[3]

    # Check for existing RP record
    dynamodb = boto3.resource('dynamodb', region_name=region)
    rps_table = dynamodb.Table('evaas_rps')
    response = rps_table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key('rp_email').eq(event['body']['email']),
        Select='COUNT'
    )
    if response['Count'] > 0:
        raise ClientException(
            'rp_email %s is already registered. Please provide '
            '"current_api_key" to update.' % event['body']['email'])

    # TODO : Accommodate RPs that have lost their API key while preventing abusive
    # spam of an RP email with new API key validation requests

    new_api_key = base64.urlsafe_b64encode(os.urandom(32))

    response = rps_table.put_item(
        Item=filter_dict({
            'rp_email': event['body']['email'],
            'service_name': service_name,
            'ip': event['X-Forwarded-For'],
            'api_key': new_api_key,
            'status': 'Pending'
        })
    )

    ses_client = boto3.client('ses')
    response = ses_client.verify_email_identity(
        EmailAddress=event['body']['email']
    )

    return {'api_key': new_api_key}


def update_rp(event, context):
    pass


def check_api_key(api_key, region):
    # Lookup the api key
    dynamodb = boto3.resource('dynamodb', region_name=region)
    rps_table = dynamodb.Table('evaas_rps')
    response = rps_table.query(
        IndexName='api_key',
        KeyConditionExpression=boto3.dynamodb.conditions.Key('api_key').eq(api_key),
        Select='ALL_ATTRIBUTES'
    )

    if response['Count'] < 1:
        raise ClientException('api_key %s is not registered.' % api_key)

    # Assume that there are not more than 1 record with the apikey
    rp = response['Items'][0]
    logger.info('response is %s' % response)
    logger.info('rp is %s' % rp)

    if 'status' not in rp:
        raise ServerException(
            'RP %s found but no status is set.' % rp['rp_email'])

    # If the status hasn't been settled, check again
    if rp['status'] in ['Pending', 'TemporaryFailure']:
        ses_client = boto3.client('ses')
        # Validate they're verified
        response = ses_client.get_identity_verification_attributes(
            Identities=[rp['rp_email']]
        )
        verification_attributes = response['VerificationAttributes']
        if rp['rp_email'] not in verification_attributes:
            raise ServerException(
                'RP %s not present in SES.' % rp['rp_email'])
        new_status = verification_attributes[rp['rp_email']]['VerificationStatus']
        # If the status has changed, update the record
        if new_status != rp['status']:
            response = rps_table.update_item(
                Key={'rp_email': rp['rp_email']},
                UpdateExpression='SET #s = :s',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': new_status}
            )
        rp['status'] = new_status

    # Check that the RP is verified
    if rp['status'] == 'Pending':
        raise ClientException(
            'RP email {email} still pending verification. '
            'Check for the AWS SES email sent to {email}'.format(
                email=rp['rp_email']))
    if rp['status'] == 'TemporaryFailure':
        raise ServerException(
            'AWS SES reports {status} for verification of RP '
            'email {email}. Please confirm that the link in the verification '
            'email from SES has been clicked and try again later'.format(
                status=rp['status'], email=rp['rp_email']))
    if rp['status'] == 'Failed':
        raise ClientException(
            'AWS SES reports {status} for verification of RP '
            'email {email}. As {email} has indicated that they do not want to '
            'allow verification, this email address will not be able to be '
            'used as a sender. Please register a new RP with a different email '
            'address'.format(status=rp['status'], email=rp['rp_email']))
    if rp['status'] != 'Success':
        raise ServerException(
            'Unknown AWS SES verification status for {email} '
            'of {status}.'.format(status=rp['status'], email=rp['rp_email']))

    return rp


def create_user(event, context):
    if 'body' not in event:
        raise ServerException('"body" object missing')
    if 'email' not in event['body']:
        raise ClientException('"email" parameter missing')
    if 'api_key' not in event:
        raise ClientException('"api_key" parameter missing')
    if 'X-Forwarded-For' not in event:
        raise ServerException('"X-Forwarded-For" parameter missing')
    if 'stage' not in event:
        raise ServerException('"stage" parameter missing')
    if 'api_id' not in event:
        raise ServerException('"api_id" parameter missing')

    region = context.invoked_function_arn.split(':')[3]
    rp = check_api_key(event['api_key'], region)

    dynamodb = boto3.resource('dynamodb', region_name=region)
    users_table = dynamodb.Table('evaas_users')
    response = users_table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.And(
            boto3.dynamodb.conditions.Key('user_email').eq(event['body']['email']),
            boto3.dynamodb.conditions.Key('rp_email').eq(rp['rp_email'])),
        Select='ALL_ATTRIBUTES'
    )

    if (response['Count'] == 1):
        # We've already seen this user for this rp
        user = response['Items'][0]
        if user['status'] == 'Pending':
            seconds_elapsed = (
                int(time.time()) - user['date_sent'])
            if seconds_elapsed < MIN_SECONDS_BETWEEN_VERIFICATION_EMAILS:
                raise ClientException(
                    'Verification email to {email} was sent '
                    '{seconds_elapsed} seconds ago. Please wait for 15 seconds '
                    'before requesting a new verification email be sent'.format(
                        email=event['body']['email'],
                        seconds_elapsed=seconds_elapsed))
        if user['status'] == 'Failed':
            return {'status': 'Failed'}
        if user['status'] == 'Rejected':
            return {'status': 'Rejected'}
        if user['status'] == 'Success':
            return {'status': 'Success'}
        if user['status'] == 'Verified':
            return {'status': 'Verified'}

    token = base64.urlsafe_b64encode(os.urandom(32))
    # TODO : Deal with case where we create a CNAME to the domain name
    verification_url = 'https://{domain}/{stage}/tokens/{token}'.format(
        domain='{api_id}.execute-api.{region}.amazonaws.com'.format(
            api_id=event['api_id'],
            region=region),
        stage=event['stage'],
        token=token
    )

    # TODO : Create localized versions of email content
    ses_client = boto3.client('ses')
    date_sent = int(time.time())
    email_strings = EMAIL_LOCALIZATION_STRINGS[USER_LOCALE].copy()
    # TODO : Gracefully deal with missing service name
    email_strings.update({'verification url': verification_url,
                          'service name': sanitize_service_name(rp['service_name']) if 'service_name' in rp else ''})
    response = ses_client.send_email(
        Source=rp['rp_email'],
        Destination={
            'ToAddresses': [
                event['body']['email']
            ]
        },
        Message={
            'Subject': {
                'Data': email_strings['verify your account']
            },
            'Body': {
                'Text': {
                    'Data': EMAIL_TEXT_TEMPLATE.format(**email_strings)
                },
                'Html': {
                    'Data': EMAIL_HTML_TEMPLATE.format(**email_strings)
                }
            }
        }
    )

    message_id = response['MessageId']
    # TODO : Consider moving to a model where RPs delegate authorization instead
    # of just validating their email
    # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html

    tokens_table = dynamodb.Table('evaas_tokens')
    response = tokens_table.update_item(
        Key={'token': token},
        UpdateExpression='SET rp_email = :rp_email, '
        'user_email = :user_email, '
        '#status = :status',
        ExpressionAttributeNames={'#status': 'status'},
        ExpressionAttributeValues={':user_email': event['body']['email'],
                                   ':rp_email': rp['rp_email'],
                                   ':status': 'Unverified'}
    )

    response = users_table.update_item(
        Key={'user_email': event['body']['email'],
             'rp_email': rp['rp_email']},
        UpdateExpression='SET #status = :status, '
            'message_id = list_append(if_not_exists(message_id, :empty_list), :message_id), '
            'date_sent = :date_sent',
        ExpressionAttributeNames={'#status': 'status'},
        ExpressionAttributeValues={':status': 'Pending',
                                   ':empty_list': [],
                                   ':message_id': [message_id],
                                   ':date_sent': date_sent}
    )
    return {'email':event['body']['email'],
            'status': 'Created'}


def verify_user(event, context):
    if 'token' not in event:
        raise ClientException('"token" missing')

    region = context.invoked_function_arn.split(':')[3]
    dynamodb = boto3.resource('dynamodb', region_name=region)
    tokens_table = dynamodb.Table('evaas_tokens')
    response = tokens_table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key('token').eq(event['token']),
        Select='ALL_ATTRIBUTES'
    )

    if (response['Count'] == 0):
        return VERIFICATION_RESULT_TEMPLATE.format(
            **{'title': 'Token not found',
               'result': 'Token not found',
               'result text': 'Unfortunately, that token was not found in our system. Please check your verification email and try again.'})
        # raise         ClientException('"token" does not exist')
    token = response['Items'][0]

    if 'status' in token and token['status'] == 'Verified':
        return VERIFICATION_RESULT_TEMPLATE.format(
            **{'title': 'Token already verified',
               'result': 'Token already verified',
               'result text': 'That token has already been verified. You should be able to access the service now.'})

    rps_table = dynamodb.Table('evaas_rps')
    response = rps_table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key('rp_email').eq(token['rp_email']),
        Select='ALL_ATTRIBUTES'
    )

    if response['Count'] < 1:
        raise ServerException(
            'token found but RP email not present in rps table')

    rp = response['Items'][0]

    users_table = dynamodb.Table('evaas_users')
    response = users_table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.And(
            boto3.dynamodb.conditions.Key('user_email').eq(token['user_email']),
            boto3.dynamodb.conditions.Key('rp_email').eq(token['rp_email'])),
        Select='ALL_ATTRIBUTES'
    )

    if (response['Count'] == 0):
        raise ServerException('token found in tokens table but associated user {user_email} from RP '
            '{rp_email} not found in users table'.format(**token))

    response = users_table.update_item(
        Key={'user_email': token['user_email'],
             'rp_email': token['rp_email']},
        UpdateExpression='SET #status = :status',
        ExpressionAttributeNames={'#status': 'status'},
        ExpressionAttributeValues={':status': 'Success'}
    )

    # TODO : Call RP callback indicating user verified their token

    response = tokens_table.update_item(
        Key={'token': event['token']},
        UpdateExpression='SET #status = :status',
        ExpressionAttributeNames={'#status': 'status'},
        ExpressionAttributeValues={':status': 'Verified'}
    )

    response = users_table.update_item(
        Key={'user_email': token['user_email'],
             'rp_email': token['rp_email']},
        UpdateExpression='SET #status = :status',
        ExpressionAttributeNames={'#status': 'status'},
        ExpressionAttributeValues={':status': 'Verified'}
    )

    return VERIFICATION_RESULT_TEMPLATE.format(**{'title': rp['service_name'] if 'service_name' in rp else '',
                                                  'result': 'Email address verified',
                                                  'result text': 'Your email address has been successfully verified'})


def check_user(event, context):
    if 'email' not in event:
        raise ClientException('"email" parameter missing')
    if 'api_key' not in event:
        raise ClientException('"api_key" parameter missing')
    if 'X-Forwarded-For' not in event:
        raise ServerException('"X-Forwarded-For" parameter missing')
    if 'stage' not in event:
        raise ServerException('"stage" parameter missing')
    if 'api_id' not in event:
        raise ServerException('"api_id" parameter missing')
    region = context.invoked_function_arn.split(':')[3]
    rp = check_api_key(event['api_key'], region)

    dynamodb = boto3.resource('dynamodb', region_name=region)
    users_table = dynamodb.Table('evaas_users')
    response = users_table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.And(
            boto3.dynamodb.conditions.Key('user_email').eq(event['email']),
            boto3.dynamodb.conditions.Key('rp_email').eq(rp['rp_email'])),
        Select='ALL_ATTRIBUTES'
    )

    if (response['Count'] == 1):
        # User found
        user = response['Items'][0]
        return {'status': user['status']}
    else:
        return {'status': 'Not registered'}


def lambda_handler(event, context):
    logger.info('Event: %s' % json.dumps(event))
    logger.info('Context: %s' %
                json.dumps(vars(context), cls=PythonObjectEncoder))
    result = {}
    if 'resource_path' not in event:
        raise ServerException('"resource_path" missing')

    if event['resource_path'] == '/rps':
        if event['http_method'] == 'PUT':
            if 'current_api_key' in event:
                result = update_rp(event, context)
            else:
                result = create_rp(event, context)
    elif event['resource_path'] == '/users':
        if event['http_method'] == 'PUT':
            result = create_user(event, context)
        if event['http_method'] == 'GET':
            result = check_user(event, context)
    elif event['resource_path'].startswith('/tokens/'):
        if event['http_method'] == 'GET':
            result = verify_user(event, context)
    return result
