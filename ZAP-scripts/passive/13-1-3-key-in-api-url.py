"""

Script testing 13.1.3 control from OWASP ASVS 4.0:
'Verify API URLs do not expose sensitive information, such as the API key,
session tokens etc.'

Note: this script is almost identical to 3-1-1-token-in-url.py except, it contains strings related to api keys as well.

The script will raise an alert if the following are found in the URL:
	1. strings: "PHPSESSID", "JSESSIONID", "CFID", "CFTOKEN", "ASP.NET_SESSIONID", "ID", "COOKIE", "JWT", "SESSION", "KEY", "API"]
	2. actual token value from application (if sent) 

"""
import ast

#check response body for valid token and return it
#return None if no token is found
def getToken(msg):
  token = None
  try:
    body = str(msg.getResponseBody())
    token = ast.literal_eval(body).get('authentication').get('token')#evaluate response body to find token {authetication: {token: ****}}
  except:
    pass
  return token

def scan(ps, msg, src):

  #alert parameters
  alertRisk= 2
  alertConfidence = 1
  alertTitle = "13.1.3 Verify API URLs do not expose sensitive information."
  alertDescription = "Verify API URLs do not expose sensitive information, such as the API key, session tokens etc."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
  alertSolution = "Please review the following url for session tokens or api keys: " + url
  alertEvidence = url 
  cweID = 116
  wascID = 0
  
  tokens = ["PHPSESSID", "JSESSIONID", "CFID", "CFTOKEN", "ASP.NET_SESSIONID", "ID", "COOKIE", "JWT", "SESSION", "KEY", "API"]

  #if valid token is found, make it uppercase
  app_token = getToken(msg)
  if (app_token is not None):
    tokens.append(app_token.upper())
  
  #loop through tokens list and raise alert if it appears in the URL
  for t in tokens:
    if (t in url.upper()): #compare against uppercase URL to avoid case sensitivity
      alertParam = t
      ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
