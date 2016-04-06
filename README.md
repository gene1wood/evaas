# EVaaS

## Summary

Email Verification as a Service is a service that verifies a user's control
of a given email address. It does this through a combination of AWS services,
specifically API Gateway, Lambda, DynamoDB and Simple Email Service.


## Testing on the command line

### Setup your variables

```
rpemail=rp@example.com
useremail=user+1@exmaple.com
urlencodeduseremail=user%2B1%40example.com
servicename="My RP"
apiid=skacymyqag
stage=prod
```

### Create RP

    curl -H "Content-Type: application/json" -X PUT -d "{\"email\":\"$rpemail\", \"service_name\": \"$servicename\"}" https://$apiid.execute-api.us-west-2.amazonaws.com/$stage/rps

Which results in the translated payload to lambda of

```
{
  "body" : {"email": "rp@example.com", "service_name": "My RP"},
  "resource_path" : "/rps",
  "http_method" : "PUT",
  "X-Forwarded-For": "203.0.113.100",
  "stage": "prod",
  "api_id": "ab1cd23e45"
}
```

    apikey=whatever_you_got_from_the_previous_call

### Verify RP

Click the AWS SES Verification link in the RPs email

### Create User

    curl -H "Content-Type: application/json" -H "Api-Key: $apikey" -X PUT -d "{\"email\":\"$useremail\"}" https://$apiid.execute-api.us-west-2.amazonaws.com/$stage/users

Which results in the translated payload to lambda of

```
{
  "body" : {"email": "user+1@exmaple.com"},
  "resource_path" : "/users",
  "http_method" : "PUT",
  "X-Forwarded-For": "203.0.113.100",
  "stage": "prod",
  "api_id": "ab1cd23e45",
  "api_key": "gccIPN8bgVAP_xHzZ6RCk1_4fAzho6TQOKJoEB-0l4c="
}
```

### Verify User

Click the EVaaS verify link in the users email or call it with curl by setting the token

    token=whatever_is_in_the_users_evaas_email
    curl https://$apiid.execute-api.us-west-2.amazonaws.com/$stage/tokens/$token

Which results in the translated payload to lambda of

```
{
  "resource_path" : "/tokens/{token}",
  "http_method" : "GET",
  "X-Forwarded-For": "203.0.113.100",
  "token": "3auDZMnO6-jfLtiEb_atstB7aES65PKGEVfJDi2tMQU="
}
```


### Check User

    curl -H "Content-Type: application/json" -H "Api-Key: $apikey" https://$apiid.execute-api.us-west-2.amazonaws.com/$stage/users?email=$urlencodeduseremail

Which results in the translated payload to lambda of

```
{
  "resource_path" : "/users",
  "http_method" : "GET",
  "X-Forwarded-For": "203.0.113.100",
  "stage": "prod",
  "api_id": "ab1cd23e45",
  "email": "user+1@exmaple.com",
  "api_key": "gccIPN8bgVAP_xHzZ6RCk1_4fAzho6TQOKJoEB-0l4c="
}
```

