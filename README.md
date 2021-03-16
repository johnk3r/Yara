Yara rules to detect some threats affecting Latin America.

index="botsv3" sourcetype="aws:cloudtrail" eventName=GetSessionToken
| eval end_date = responseElements.credentials.expiration
| eval end_date = strptime(end_date, "%b %d, %Y %H:%M:%S %z") 
| eval init_date = strptime(eventTime, "%Y-%m-%dT%H:%M:%S.%N") 
| table init_date end_date
