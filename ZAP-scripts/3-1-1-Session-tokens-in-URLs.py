"""
Script testing 3.1.1 control from OWASP ASVS 4.0:
'Verify the application never reveals session tokens in URL parameters or error messages.'

The script looks for the string 'token', 'jwt', 'session' and 'cookie' in the URL. If it is found it raises an alert. 
"""
import re

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.

  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "3.1.1 Verify the application never reveals session tokens in URL parameters or error messages."
  alertDescription = ["The URL reveals a session token. ","Error page reveals a session token."]
  alertRisk = 0
  alertReliability = 1
  param = str(msg.getRequestHeader().getURI().getQuery())
  alertSolution = ["Store the token in a header or in the message body of the request.","Change the configuration of the server's error pages not to reveal session tokens."]
  alertParam = "Token param in the URL"
  alertInfo = "Control failure"
  cweID = 598
  wascID = 0

  # Search for regex match
  pattern = re.compile(r"(?i)token|jwt|cookie|session")
  code = str(msg.getResponseHeader().getStatusCode())
  errorCode = re.compile(r"[4-5][0-9]{2}")
  if (re.search(pattern,param)):
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription[0], 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], param, cweID, wascID, msg);
  if (re.search(errorCode,code)):
    body = msg.getResponseBody().toString()
    if (re.search(pattern,body)):
      ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription[1], 
        msg.getRequestHeader().getURI().toString(), 
        "Token param in the error page", "", alertInfo, alertSolution[1], "", cweID, wascID, msg);   