"""
Script testing 14.4.5 control from OWASP ASVS 4.0:
'Verify that HTTP Strict Transport Security headers are included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800; includeSubdomains.'

The script looks for HSTS header and if there are none found, the control is failed. 
Additionally, the script test if the HSTS is configured with the directives: max-age=15724800; includeSubdomains. If it is not, the control is failed.
"""
import re

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.

  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "14.4.5 Verify that HTTP Strict Transport Security headers are included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800; includeSubDomains."
  alertDescription = "HTTP Strict-Transport-Security HSTS header is used to tell a browser that a website should only be accessed using HTTPS."
  alertRisk = 0
  alertReliability = 1
  headerHSTS = str(msg.getResponseHeader().getHeader("Strict-Transport-Security"))
  alertSolution = ["Add HSTS header to the server's configuration.","Ensure that HSTS is using directives max-age=15724800; includeSubDomains. Max age should be at least 15724800, but a longer time is preferred."]
  alertParam = "Strict-Transport-Security header"
  alertInfo = "Control failure"
  cweID = 523
  wascID = 0

  # Search for regex match for max-age equals at least 15724800 or more AND include Subdomains directive
  pattern = re.compile(".*(?i)max-age=(15724[8-9][0-9]{2}|1572[5-9][0-9]{3}|157[3-9][0-9]{4}|15[8-9][0-9]{5}|1[6-9][0-9]{6}|[2-9][0-9]{7}|[1-9][0-9]{8}|[1-9][0-9]{8}).*includeSubDomains.*")
  directives = re.search(pattern,headerHSTS)

  # Test the request and/or response here
  if (headerHSTS == "None"):
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePositive, 1: suspicious, 2: warning
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], headerHSTS, cweID, wascID, msg);
  elif not directives:
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[1], headerHSTS, cweID, wascID, msg);

