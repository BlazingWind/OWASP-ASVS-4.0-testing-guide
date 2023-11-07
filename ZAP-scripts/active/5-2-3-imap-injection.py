"""

Script testing 5.2.3 control from OWASP ASVS 4.0:
'Verify that the application sanitizes user input before passing to mail systems
to protect against SMTP or IMAP injection.'


This script will inject a payload to see if it is returned in the response body without being sanatized or escaped or,
causes the server to return an error.

"""

def scanNode(sas, msg):
  pass

def scan(sas, msg, param, value):
  #alert parameters
  alertRisk= 3
  alertConfidence = 2
  alertTitle = "5.2.3 Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection."
  alertDescription = "Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection"
  alertSolution = ""
  alertEvidence = "" 
  cweID = 147
  wascID = 0
 
  common_imap_elements = ["imap attack", "", "\\", "'", "@", "#", "!", "|", '"']


  # Copy requests before reusing them
  msg = msg.cloneRequest();
  sas.sendAndReceive(msg, False, False);
  
  attack = ""
  for element in common_imap_elements:
    attack += element
      
    # setParam (message, parameterName, newValue)
    sas.setParam(msg, param, attack);

    # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    sas.sendAndReceive(msg, False, False);

    code = str(msg.getResponseHeader().getStatusCode()) # get status code

    #check if attack payload is reflected back in the response body or server errror, if so raise alert
    try: # use try/except to avoid parsing issues from invalid response bodies
      body = str(msg.getResponseBody())
      if (attack in body):
        alertAttack = attack
        alertEvidence = attack + " found in Response Body"
        sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
        url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
      elif (code == '500'): #check for server error code (500)
        alertAttack = attack
        alertEvidence = "Status Code: " + code + "\n" + "Attack triggered server error."
        sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
        url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
          
    except:
      pass
