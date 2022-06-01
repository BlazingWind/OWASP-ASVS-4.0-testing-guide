"""
Helper script for 5.1.1 control from OWASP ASVS 4.0:
'Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (GET, POST, cookies, headers, or environment variables).'

The script looks for any parameters in URLs and in POST form fields and raises an alert on all parameters it has found.
"""
import re

def scan(ps, msg, src):

  alertTitle = "5.1.1 Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (GET, POST, cookies, headers, or environment variables)."
  alertDescription = "HTTP parameter pollution tests how the applications responds to multiple parameters with the same name. "
  param = msg.getParamNames()
  alertRisk = 0
  alertReliability = 1
  alertSolution = "Ensure proper input validation and input encoding."
  alertParam = "Query in URL or POST message"
  alertInfo = "Review parameters in the URL and POST form fields to assess control's success"
  cweID = 235
  wascID = 0

  if param:
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution, str(param), cweID, wascID, msg);