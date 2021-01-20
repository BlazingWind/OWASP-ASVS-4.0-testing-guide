"""
Script testing 14.2.3 control from OWASP ASVS 4.0:
'Verify that if application assets, such as JavaScript libraries, CSS stylesheets or web fonts, are hosted externally on a content delivery network (CDN) or external provider, Subresource Integrity (SRI) is used to validate the integrity of the asset.'

The script checks if integrity attribute is present in <script> and <link> elements for scripts and CSS loaded externally. If not present, it will raise an alert.
"""

import re

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.
  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "14.2.3 Verify that if application assets, such as JavaScript libraries, CSS stylesheets or web fonts, are hosted externally on a content delivery network (CDN) or external provider, Subresource Integrity (SRI) is used to validate the integrity of the asset."
  alertDescription = "Resources loaded from external providers should be checked against their hashes before they are loaded. SRI is used to check that a file that is loaded has not been tampered with. "
  alertRisk = 0
  alertReliability = 1
  body = msg.getResponseBody().toString()
  alertSolution = ["Ensure that third party Javascript has integrity and crossorigin attributes", "Ensure that third party CSS has integrity and crossorigin attributes"]
  alertParam = ["Missing Integrity attribute in script tag","Missing Integrity attribute in link rel='stylesheet' tag"]
  alertInfo = "Control failure"
  cweID = 714 
  wascID = 0

  # Search for regex match 
  regexScript = re.compile(r"<script[^>]*><\/script>") 
  regexCSS = re.compile(r"(?i)\<\s?link\s?rel=[\"|\']stylesheet[\"|\'][^\>]*\>") 
  regexIntegrity = re.compile(r" ?integrity ?= ?(\'|\") ?sha ?(256|384|512) ?- ?[a-zA-Z0-9\/=+]+ ?(\'|\")")
  regexURI = re.compile(r" ?= ?(\'|\") ?(https|http|//)")
  # Test the request and/or response here
  matchScript = regexScript.findall(body)
  matchCSS = regexCSS.findall(body)

  for match in matchScript:
    scriptPath = regexURI.search(match)
    if scriptPath:
      scriptIntegrity = regexIntegrity.search(match)
      if not scriptIntegrity:
        ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
          msg.getRequestHeader().getURI().toString(), 
          alertParam[0], "", alertInfo, alertSolution[0], match, cweID, wascID, msg);
  for match2 in matchCSS:
    cssPath = regexURI.search(match2)
    if cssPath:
      cssIntegrity = regexIntegrity.search(match2)
      if not cssIntegrity:
        ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
          msg.getRequestHeader().getURI().toString(), 
          alertParam[1], "", alertInfo, alertSolution[1], match2, cweID, wascID, msg);        
