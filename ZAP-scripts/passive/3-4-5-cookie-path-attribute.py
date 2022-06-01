"""

Script testing 3.4.5 control from OWASP ASVS 4.0:
Verify that if the application is published under a domain name with other applications that set or use 
session cookies that might disclose the session cookies, set the path attribute in cookie-based session 
tokens using the most precise path possible.

"""

def scan(ps, msg, src):

  #find "Set-Cookie" header
  headerCookie = str(msg.getResponseHeader().getHeader("Set-Cookie"))

  #alert parameters
  alertRisk= 1
  alertConfidence = 2
  alertTitle = "3.4.5 Verify that cookie-based session tokens utilize the 'Path' attribute."
  alertDescription = "Verify that if the application is published under a domain name with other applications that set or use session cookies that might disclose the session cookies, set the path attribute in cookie-based session tokens using the most precise path possible."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes"
  alertSolution = "If the application is published under a domain name with other applications, include the 'Path' Cookie attribute with the most specific path"
  alertEvidence = "" 
  cweID = 16
  wascID = 0

  #if "Set-Cookie" header does not have "Path" attribute, raise alert    
  if ((headerCookie != "None") and "path=" not in headerCookie.lower()):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
