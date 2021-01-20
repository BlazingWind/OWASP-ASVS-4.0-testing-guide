"""
Script testing 14.4.1 control from OWASP ASVS 4.0:
'Verify that every HTTP response contains a content type header specifying a safe character set (e.g., UTF-8, ISO 8859-1).' 
Since the creators of ASVS are updating this requirement in the next version of ASVS to: 
“Verify that every HTTP response contains a Content-Type header. text/*, /+xml and application/xml content types should also specify a safe character set (e.g., UTF-8, ISO-8859-1).” 
the script will raise an alert if 'Content-Type' header is present and if the header specifies a safe charset for text/*, /+xml and application/xml content types.
"""
import re

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.
  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "14.4.1 Verify that every HTTP response contains a content type header specifying a safe character set (e.g., UTF-8, ISO 8859-1)."
  alertDescription = "The header Content-Type denotes what the content is encoded in. Declaring it hinders XSS attacks leveraging different encodings than the server expects."
  alertRisk = 0
  alertReliability = 1
  header = str(msg.getResponseHeader().getHeader("Content-Type"))
  alertSolution = ["Ensure that Content-Type is included in the response.","Ensure that Content-Type header with text/*, /+xml and application/xml content types specifies a safe character set (e.g., UTF-8, ISO-8859-1)."]
  alertParam = "Content-Type header"
  alertInfo = "Control failure"
  cweID = 173
  wascID = 0

  patternType = re.compile(r"text/.*|.*\+xml.*|application/xml.*")
  patternCharset = re.compile(r"(?i).*UTF-8.*|.*ISO-8859-1.*")

  if (header == "None"):
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], header, cweID, wascID, msg);
  elif (re.search(patternType,header)):
    charsets = re.search(patternCharset,header)
    if not charsets:
      ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
        msg.getRequestHeader().getURI().toString(), 
        alertParam, "", alertInfo, alertSolution[1], header, cweID, wascID, msg);
