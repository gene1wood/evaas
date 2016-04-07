#!/usr/bin/env python

import boto3
from botocore.vendored import requests
import StringIO
import random
from zipfile import ZipFile
import time
import yaml


class ApiGatewayBuilder():
    def __init__(self):
        self.region = self.__get_region()
        self.account_id = self.__get_account_id()

    @staticmethod
    def __get_account_id():
        try:
            # We're running in an ec2 instance, get the account id from the
            # instance profile ARN
            return requests.get(
                'http://169.254.169.254/latest/meta-data/iam/info/',
                timeout=1).json()['InstanceProfileArn'].split(':')[4]
        except:
            pass

        try:
            # We're not on an ec2 instance but have api keys, get the account
            # id from the user ARN
            return boto3.client('iam').get_user()['User']['Arn'].split(':')[4]
        except:
            pass

        return False

    @staticmethod
    def __get_region():
        try:
            # We're running in an ec2 instance, get the account id from the
            # instance profile ARN
            return requests.get(
                'http://169.254.169.254/latest/meta-data/iam/info/',
                timeout=1).json()['InstanceProfileArn'].split(':')[3]
        except:
            pass

        try:
            # We're not on an ec2 instance but have api keys, get the account
            # id from the session
            return boto3.session.Session().region_name
        except:
            pass

        return False

    @staticmethod
    def create_dynamo_db():
        dynamodb = boto3.resource('dynamodb')
        rps_table = dynamodb.create_table(
            TableName='evaas_rps',
            KeySchema=[
                {
                    'AttributeName': 'rp_email',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'api_key',
                    'KeySchema': [
                        {
                            'AttributeName': 'api_key',
                            'KeyType': 'HASH'  # Partition key
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    },
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 1,
                        'WriteCapacityUnits': 1
                    }
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'rp_email',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'api_key',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 1,
                'WriteCapacityUnits': 1
            }
        )

        users_table = dynamodb.create_table(
            TableName='evaas_users',
            KeySchema=[
                {
                    'AttributeName': 'user_email',
                    'KeyType': 'HASH'  # Partition key
                },
                {
                    'AttributeName': 'rp_email',
                    'KeyType': 'RANGE'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'user_email',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'rp_email',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 1,
                'WriteCapacityUnits': 1
            }
        )

        tokens_table = dynamodb.create_table(
            TableName='evaas_tokens',
            KeySchema=[
                {
                    'AttributeName': 'token',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'token',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 1,
                'WriteCapacityUnits': 1
            }
        )

    def create_lambda_execution_iam_role(self):
        assume_role_policy = '''{
          "Version": "2012-10-17",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "lambda.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        }'''
        policy = '''{
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
              ],
              "Resource": "arn:aws:logs:*:*:*"
            },
            {
              "Effect": "Allow",
              "Action": [
                "dynamodb:Query",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem"
              ],
              "Resource": "arn:aws:dynamodb:*:*:table/evaas_*"
            },
            {
              "Effect": "Allow",
              "Action": [
                "dynamodb:DeleteItem"
              ],
              "Resource": "arn:aws:dynamodb:*:*:table/evaas_tokens"
            },
            {
              "Effect": "Allow",
              "Action": [
                "ses:VerifyEmailIdentity",
                "ses:GetIdentityVerificationAttributes",
                "ses:SendEmail"
              ],
              "Resource": "*"
            }
          ]
        }'''
        role_name = 'evaas_lambda_role'
        client = boto3.client('iam')
        response = client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_role_policy
        )
        role_arn = response['Role']['Arn']
        response = client.put_role_policy(
            RoleName=role_name,
            PolicyName='evaas_lambda_policy',
            PolicyDocument=policy
        )
        return role_arn

    def create_lambda_function(self, role_arn):
        zip_contents = StringIO.StringIO()
        with ZipFile(zip_contents, 'w') as z:
            z.write('evaas.py')
        client = boto3.client('lambda')
        response = client.create_function(
            FunctionName='EVaaS',
            Runtime='python2.7',
            Role=role_arn,
            Handler='evaas.lambda_handler',
            Code={
                'ZipFile': zip_contents.getvalue()
            },
            Description='Email Verification as a Service',
            Timeout=10,
        )

    def import_api_swagger(self):
        client = boto3.client('apigateway')
        with open('evaas_swagger.yaml', 'r') as f:
            swagger = yaml.load(f)
        for path in swagger['paths'].keys():
            for method in swagger['paths'][path].keys():
                if ('x-amazon-apigateway-integration' in swagger['paths'][path][method] and 'uri' in
                        swagger['paths'][path][method]['x-amazon-apigateway-integration']):
                    swagger['paths'][path][method]['x-amazon-apigateway-integration']['uri'] = (
                        swagger['paths'][path][method]['x-amazon-apigateway-integration']['uri'].replace(
                            '123456789012', self.account_id))

        # Requires botocore 1.4.9
        # https://github.com/boto/botocore/commit/d400d47bebead69279b200bcd62fd7d7f55cfaf1
        response = client.import_rest_api(
            body=yaml.dump(swagger)
        )
        return response['id']

    def grant_lambda_permissions(self, api_id):
        client = boto3.client('lambda')
        for path in ['GET/users',
                     'PUT/users',
                     'GET/tokens/*',
                     'PUT/rps']:
            response = client.add_permission(
                FunctionName='EVaaS',
                StatementId='%032x' % random.randrange(16 ** 32),
                Action='lambda:InvokeFunction',
                Principal='apigateway.amazonaws.com',
                SourceArn='arn:aws:execute-api:{region}:{account_id}:{api_id}/*/{path}'.format(
                    region=self.region,
                    account_id=self.account_id,
                    api_id=api_id,
                    path=path
                )
            )

    @staticmethod
    def deploy_api(api_id):
        client = boto3.client('apigateway')
        response = client.create_deployment(
            restApiId=api_id,
            stageName='prod',
            stageDescription='Production'
        )

    def build(self):
        self.create_dynamo_db()

        role_arn = self.create_lambda_execution_iam_role()
        print("Sleeping while IAM Role is created")
        time.sleep(10)
        self.create_lambda_function(role_arn)

        api_id = self.import_api_swagger()
        self.grant_lambda_permissions(api_id)
        self.deploy_api(api_id)
        return {'api_id': api_id}


def main():
    builder = ApiGatewayBuilder()
    print(builder.build())


if __name__ == "__main__":
    main()
