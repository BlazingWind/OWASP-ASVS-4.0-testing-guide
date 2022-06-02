"""

Script testing 3.4.2 control from OWASP ASVS 4.0:
Verify that cookie-based session tokens have the 'HttpOnly' attribute set.

The script will raise an alert if 'HttpOnly' attribute is not present. 

"""

def scan(ps, msg, src):

  #find "Set-Cookie" header
  headerCookie = str(msg.getResponseHeader().getHeader("Set-Cookie"))

  #alert parameters
  alertRisk= 1
  alertConfidence = 2
  alertTitle = "3.4.2 Verify that cookie-based session tokens have the 'HttpOnly' attribute set."
  alertDescription = "If the HttpOnly flag (optional) is included in the HTTP response header, the cookie cannot be accessed through client side script (again if the browser supports this flag). As a result, even if a cross-site scripting (XSS) flaw exists, and a user accidentally accesses a link that exploits this flaw, the browser (primarily Internet Explorer) will not reveal the cookie to a third party."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/HttpOnly"
  alertSolution = "Add 'HttpOnly' attribute when sending cookie."
  alertEvidence = "" 
  cweID = 1004
  wascID = 0
  
  #if "Set-Cookie" header does not have "httponly" attribute, raise alert  
  if ((headerCookie != "None") and "httponly" not in headerCookie.lower()):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
