Yara rules to detect some threats affecting Latin America.


[23:09, 3/15/2021] Higor: index="botsv3" sourcetype="aws:cloudtrail" eventName=GetSessionToken
| eval end_date = strptime(responseElements.credentials.expiration, "%b %d, %Y %H:%M:%S %p")
| eval init_date = strptime(eventTime, "%Y-%m-%dT%H:%M:%S.%N") 
| table init_date, end_date
[23:09, 3/15/2021] Higor: o problema é no end_date
[23:10, 3/15/2021] Higor: fazendo isso:
index="botsv3" sourcetype="aws:cloudtrail" eventName=GetSessionToken
| table responseElements.credentials.expiration

me retorna isso:
Jul 27, 2018 5:16:39 PM
