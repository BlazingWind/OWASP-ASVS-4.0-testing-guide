"""
Script testing 14.4.6 control from OWASP ASVS 4.0:
'Verify that a suitable "Referrer-Policy" header is included, such as "no-referrer" or "same-origin".'

The script looks for Referrer-Policy header and if there are none found, the control is failed. 
Additionally, the script tests if the CSP is configured with either of the directives: 'no-referrer' or 'same-origin'.
"""
import re

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.
  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "14.4.6 Verify that a suitable 'Referrer-Policy' header is included, such as 'no-referrer' or 'same-origin'."
  alertDescription = "HTTP requests may include Referrer header, which may expose sensitive information. Referrer-Policy restiricts how much information is sent in the Referer header."
  alertRisk = 0
  alertReliability = 1
  header = str(msg.getResponseHeader().getHeader("Referrer-Policy"))
  alertSolution = ["Add Referrer-Policy header to the server's configuration.","Ensure that Referrer-Policy is configured with either of the directives: 'no-referrer' or 'same-origin'."]
  alertParam = "Referrer-Policy header"
  alertInfo = "Control failure"
  cweID = 116
  wascID = 0

  # Search for regex match 
  pattern = re.compile(r"'no-referrer'|'same-origin'")
  directives = re.search(pattern,header)
  
  # Test the request and/or response here
  if (header == "None"):
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePositive, 1: suspicious, 2: warning
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], header, cweID, wascID, msg);
  elif not directives:
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[1], header, cweID, wascID, msg);
