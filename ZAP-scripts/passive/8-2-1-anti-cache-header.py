"""

Script testing 8.2.1 control from OWASP ASVS 4.0:
'Verify the application sets sufficient anti-caching headers so that sensitive
data is not cached in modern browsers.'

The script will raise an alert if 'Cache-Control' and 'Pragma' headers are not present. 
 
"""

def scan(ps, msg, src):

  #find "Cache-Control" and "Pragma" headers
  header_cache = str(msg.getResponseHeader().getHeader("Cache-Control"))
  header_pragma = str(msg.getResponseHeader().getHeader("Pragma"))

  #alert parameters
  alertRisk= 1
  alertConfidence = 2
  alertTitle = "8.2.1 Verify the application sets sufficient anti-caching headers."
  alertDescription = "Verify the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses"
  alertSolution = "Add anti caching headers to HTTP response (Cache-Control, Pragma)."
  alertEvidence = "" 
  cweID = 525
  wascID = 0
  
  #if 'Cache-Control' and 'Pragma' headers are not present
  if (header_cache == "None" and header_pragma == "None"):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
