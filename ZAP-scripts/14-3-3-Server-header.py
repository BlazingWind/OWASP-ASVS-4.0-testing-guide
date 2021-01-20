"""
Script testing 14.3.3 control from OWASP ASVS 4.0:
'Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components.'

The script looks for  headers: 'Server' and 'X-Powered-By' and if there are any found, the control is failed. 
Sometimes the two headers do not give out detailed information about the system components, but the script assumes that 
"""

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.

  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = '14.3.3 Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components.'
  alertDescription = "Headers such as 'Server' and 'X-Powered-By' may expose detailed version information about the underlaying software on the webserver."
  alertRisk = 0
  alertReliability = 1
  headerXPoweredBy = str(msg.getResponseHeader().getHeader("X-Powered-By"))
  headerServer = str(msg.getResponseHeader().getHeader("Server"))
  alertSolution = "Suppress Server and X-Powered-By headers on your servers."
  alertParam = ["X-Powered-By header","Server header"]
  alertInfo = "If the headers"
  cweID = 200
  wascID = 13
  
  # Test the request and/or response here
  if (headerXPoweredBy != "None"):
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePositive, 1: suspicious, 2: warning
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam[0], "", alertInfo, alertSolution, headerXPoweredBy, cweID, wascID, msg);
  if (headerServer != "None"):
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam[1], "", alertInfo, alertSolution, headerServer, cweID, wascID, msg);
