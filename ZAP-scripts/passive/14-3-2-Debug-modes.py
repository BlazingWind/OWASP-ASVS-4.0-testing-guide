"""
Script testing 14.3.2 control from OWASP ASVS 4.0:
'Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles,  and unintended security disclosures.'

The script searches the body of the response for words such as 'debug', 'medio' and raises an alert if it did find them.
"""
import re

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.
  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "14.3.2 Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles,  and unintended security disclosures."
  alertDescription = "Debug mode often allows for much more functionality and employs poorer security practices. It should not be present in production. The script searches the body of the response for words such as 'debug', 'medio' and raises an alert if it did find them."
  alertRisk = 0
  alertReliability = 1
  body = msg.getResponseBody().toString()
  alertSolution = ["Ensure that the application does not contain any leftover debug code",""]
  alertParam = "'debug', 'medio' in body of the response"
  alertInfo = "Control failure"
  cweID = 497
  wascID = 0
  
  pattern = re.compile(r"(?i)debug|medio")
  # Search for regex match 
  words = re.search(pattern,body)
  
  # Test the request and/or response here
  if words:
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePositive, 1: suspicious, 2: warning
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], "", cweID, wascID, msg);
