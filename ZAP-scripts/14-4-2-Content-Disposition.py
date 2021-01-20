"""
Script testing 14.4.3 control from OWASP ASVS 4.0:
'Verify that all API responses contain Content-Disposition: attachment; filename="api.json" (or other appropriate filename for the content type).'

The script looks for Content-Disposition header and if there are none found, the control is failed. 
"""
import re

def scan(ps, msg, src):
  alertTitle = '14.4.2 Verify that all API responses contain Content-Disposition: attachment; filename="api.json" (or other appropriate filename for the content type).'
  alertDescription = "Content-disposition header in an API response is used to automatically give a name to a file downloaded by a user."
  alertRisk = 0
  alertReliability = 1
  header = str(msg.getResponseHeader().getHeader("Content-Disposition"))
  alertSolution = ["Add Content-Disposition header to the server's configuration.","Add 'attachment' directive to the header."]
  alertParam = "Content-Disposition header"
  alertInfo = "Control failure"
  cweID = 116
  wascID = 0

  # Search for regex match
  pattern = re.compile(r"attachment")
  directives = re.search(pattern,header)

  if (header == "None"):
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], header, cweID, wascID, msg);
  elif not directives:
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[1], header, cweID, wascID, msg);


