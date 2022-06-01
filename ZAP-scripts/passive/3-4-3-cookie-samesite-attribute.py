"""

Script testing 3.4.3 control from OWASP ASVS 4.0:
Verify that cookie-based session tokens utilize the 'SameSite' attribute to limit exposure to cross-site request forgery attacks.


The script will raise an alert if 'SameSite' attribute is not present. 

"""

def scan(ps, msg, src):

  #find "Set-Cookie" header
  headerCookie = str(msg.getResponseHeader().getHeader("Set-Cookie"))

  #alert parameters
  alertRisk= 1
  alertConfidence = 2
  alertTitle = "3.4.3 Verify that cookie-based session tokens utilize the 'SameSite' attribute."
  alertDescription = "SameSite prevents the browser from sending this cookie along with cross-site requests. The main goal is to mitigate the risk of cross-origin information leakage. It also provides some protection against cross-site request forgery attacks. Possible values for the flag are none, lax, or strict."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/SameSite"
  alertSolution = "Add 'SameSite' attribute when sending cookie."
  alertEvidence = "" 
  cweID = 16
  wascID = 0

  #if "Set-Cookie" header does not have "samesite" attribute, raise alert    
  if ((headerCookie != "None") and "samesite" not in headerCookie.lower()):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
