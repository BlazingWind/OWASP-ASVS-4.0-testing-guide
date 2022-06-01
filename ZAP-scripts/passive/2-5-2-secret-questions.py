"""

Script testing 5.2.4 control from OWASP ASVS 4.0:
'Verify password hints or knowledge-based authentication (so called 'secret questions') are not present.'

The script will raise an alert if 'secret question' is found in the response body.

"""

def scan(ps, msg, src):

  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "2.5.2 Verify password hints or knowledge-based authentication (so called 'secret questions') are not present."
  alertDescription = "Verify password hints or knowledge-based authentication (so called 'secret questions') are not present."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html"
  alertSolution = "Avoid using password hints and knowledge-based questions for account recovery."
  alertEvidence = "" 
  cweID = 640
  wascID = 0
  
  parameters = ["secret question", "security question", "secretquestion", "securityquestion"]

  try:
    #get response body
    body = str(msg.getResponseBody())

    for p in parameters:
      #if p is in response body, raise alert
      if (body != "None" and (p in body.lower())):
        alertEvidence = p + " was found."
        ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
        url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
  except UnicodeEncodeError:
    pass
