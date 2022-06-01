"""
Helper script testing 4.1.2 control from OWASP ASVS 4.0:
'Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized.'

The script looks for hidden fileds in the html of the website
"""

import re

def scan(ps, msg, src):
  alertTitle = "4.1.2 Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized."
  alertDescription = "Among others, hidden fields should not be used for access control."
  alertRisk = 0
  alertReliability = 1
  header = str(msg.getResponseHeader().getHeader("Content-Type"))
  alertSolution = ["Use access control that is not accessible to users.", ""]
  alertInfo = "Review if hidden fields are used for access control, befor assessing control's success."
  cweID = 639
  wascID = 0

  # Search for regex match 
  patternType = re.compile(r"text/.*|.*\+xml.*|application/xml.*")

  # Test the request and/or response here


  if (re.search(patternType,header)):
    body = msg.getResponseBody().toString()
    regexHidden = re.compile(r"type\s*=\s*['\"]?hidden['\"]?") #regex found in Hidden field passive tag rule in ZAP
    matchHidden = regexHidden.findall(body)
    for match in matchHidden:
      ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
        msg.getRequestHeader().getURI().toString(), 
        str(match), "", alertInfo, alertSolution[0], match, cweID, wascID, msg);       
