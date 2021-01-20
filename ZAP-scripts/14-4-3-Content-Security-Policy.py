"""
Script testing 14.4.3 control from OWASP ASVS 4.0:
'Verify that a content security policy (CSPv2) is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript injection vulnerabilities.'

The script looks for CSP header and if there are none found, the control is failed. 
Additionally, the script test if the CSP is configured with the directives: 'unsafe-inline', 'unsafe-eval' and wildcards.
"""
import re

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.

  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "14.4.3 Verify that a content security policy (CSPv2) is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript injection vulnerabilities."
  alertDescription = "Content-Security-Policy is an HTTP header that helps detect, mitigate and report on many kinds of data injection attacks including XSS and clickjacking."
  alertRisk = 0
  alertReliability = 1
  header = str(msg.getResponseHeader().getHeader("Content-Security-Policy"))
  alertSolution = ["Add CSP header to the server's configuration.","Ensure that CSP is not configured with the directives: 'unsafe-inline', 'unsafe-eval' and wildcards."]
  alertParam = "Content-Security-Policy header"
  alertInfo = "Control failure"
  cweID = 1021
  wascID = 0

  # Search for regex match
  pattern = re.compile(r"'unsafe-inline|'unsafe-eval'|\*")
  directives = re.search(pattern,header)

  if (header == "None"):
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], header, cweID, wascID, msg);
  elif directives:
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[1], header, cweID, wascID, msg);

