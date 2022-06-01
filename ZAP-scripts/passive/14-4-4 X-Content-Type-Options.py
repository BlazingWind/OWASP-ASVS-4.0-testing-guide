"""
Script testing 14.4.4 control from OWASP ASVS 4.0:
'Verify that all responses contain X-Content-Type-Options: nosniff.'

The script looks for X-Content-Type-Options header and if there are none found, the control is failed. 
"""

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.

  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "14.4.4 Verify that all responses contain X-Content-Type-Options: nosniff."
  alertDescription = "X-Content-Type-Options: nosniff is a protection against MIME sniffing vulnerabilities, e.g. XSS"
  alertRisk = 0
  alertReliability = 1
  headerXCTO = str(msg.getResponseHeader().getHeader("X-Content-Type-Options"))
  alertSolution = "Add header X-Content-Type-Options: nosniff to the server's configuration."
  alertParam = "X-Content-Type-Options header"
  alertInfo = "Control failure"
  cweID = 116
  wascID = 0

  # Test the request and/or response here
  if (headerXCTO == "None"):
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePositive, 1: suspicious, 2: warning
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution, headerXCTO, cweID, wascID, msg);
