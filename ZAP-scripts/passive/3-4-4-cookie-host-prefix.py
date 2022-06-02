"""

Script testing 3.4.4 control from OWASP ASVS 4.0:

Verify that cookie-based session tokens use the "__Host-" prefix so cookies are only sent to the host that initially set the cookie.

The script will raise an alert if "__Host-" prefix and secure attribute attribute are not present. 

"""

def scan(ps, msg, src):

  #find "Set-Cookie" header
  setCookie = str(msg.getResponseHeader().getHeader("Set-Cookie"))
  cookie = setCookie.lower()

  #alert parameters
  alertRisk= 1
  alertConfidence = 2
  alertTitle = "3.4.4 Verify that cookie-based session tokens use the __Host- prefix."
  alertDescription = "3.4.4 Verify that cookie-based session tokens use the __Host- prefix so cookies are only sent to the host that initially set the cookie."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes#:~:text=Host%20Prefix&text=The%20cookie%20must%20be%20set%20from%20a%20URI%20considered%20secure,every%20request%20to%20the%20host."
  alertSolution = "Rename cookie to include __Host- prefix if applicable."
  alertEvidence = "" 
  cweID = 16
  wascID = 0
 
  #boolean value to check if the cookie contains the host prefix and secure attribute
  no_prefix_and_no_secure = "__host-" not in cookie and ("secure" not in cookie)

  
  #if no_prefix_and_no_secure is true, raise alert    
  if ((cookie != "None") and no_prefix_and_no_secure):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
