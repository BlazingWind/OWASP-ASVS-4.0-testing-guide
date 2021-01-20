"""
Script testing 14.4.7 control from OWASP ASVS 4.0:
'Verify that a suitable X-Frame-Options or Content-Security-Policy: frame-ancestors header is in use for sites where content should not be embedded in a third-party site."

The script will raise an alert if 'X-Frame-Options' header or Content-Security-Policy header with directive frame-ancestors is not present. 
Additionally, the script tests if the CSP header uses a wildcard, which renders the header useless.
"""
import re

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.
  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "14.4.7 Verify that a suitable X-Frame-Options or Content-Security-Policy: frame-ancestors header is in use for sites where content should not be embedded in a third-party site."
  alertDescription = "X-Frame-Options header and Content-Security-Policy: frame-ancestors header are used to tell a browser whether it is allowed render a page in <frame>,<iframe>, or <object>. It protects against clickjacking by not allowing rendering of a page in a frame."
  alertRisk = 0
  alertReliability = 1
  headerXFO = str(msg.getResponseHeader().getHeader("X-Frame-Options"))
  headerCSP = str(msg.getResponseHeader().getHeader("Content-Security-Policy"))
  headerCT = str(msg.getResponseHeader().getHeader("Content-Type"))
  alertSolution = ["Add  X-Frame-Options or Content-Security-Policy: frame-ancestors header to the server's configuration.","Ensure that  Content-Security-Policy: frame-ancestors header does not use a wildcard in its configuration'."]
  alertParam = "X-Frame-Options or Content-Security-Policy: frame-ancestors header header"
  alertInfo = "Control failure"
  cweID = 346
  wascID = 0
  # Search for regex match 
  patternTypes = re.compile(r"text/.*")
  contentType = re.search(patternTypes, headerCT)

  if contentType:
    patternFrame = re.compile(r"frame-ancestors")
    patternWildcard = re.compile(r"frame-ancestors.*\*.*\;")
    directives = re.search(patternFrame,headerCSP)
    wildcard = re.search(patternWildcard, headerCSP)
    if (headerXFO == "None") and not directives:
      ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
        msg.getRequestHeader().getURI().toString(), 
        alertParam, "", alertInfo, alertSolution[0], headerXFO, cweID, wascID, msg);
    elif wildcard:
      ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
        msg.getRequestHeader().getURI().toString(), 
        alertParam, "", alertInfo, alertSolution[1], headerCSP, cweID, wascID, msg);
