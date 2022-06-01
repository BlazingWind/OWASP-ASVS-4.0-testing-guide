"""
Credit to BlazingWind on github for this script https://github.com/BlazingWind/OWASP-ASVS-4.0-testing-guide/blob/main/ZAP-scripts/4-2-2-CSRF-tokens.py

Helper script testing 4.2.2 and 13.2.3 controls from OWASP ASVS 4.0:

'Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality.'

'Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: double submit cookie pattern, CSRF nonces, or Origin request header checks.'

The script assesses if the webpage uses csrf tokens in post forms.
"""
import re

def scan(ps, msg, src):
  #Passively scans the message sent/received through ZAP.
  #Args:
  #  ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
  #  msg (HttpMessage): The HTTP message being scanned.
  #  src (Source): The HTML source of the message (if any). 

  alertTitle = "4.2.2 Verify that the application or framework enforces a strong anti-CSRF mechanism"
  alertDescription = "The script assesses if the webpage uses csrf tokens in post forms." + "\n" + "4.2.2 Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality." +"\n" + "13.2.3 Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: double submit cookie pattern, CSRF nonces, or Origin request header checks."

  alertRisk = 1
  alertReliability = 1
  headerCT = str(msg.getResponseHeader().getHeader("Content-Type"))
  alertSolution = ["Add synchronizer tokens to post froms for better protection against CSRF.",""]
  alertInfo = "Check if the application uses any other CSRF protection before assessing the control"
  cweID = 352
  wascID = 0
  # Search for regex match 
  patternTypes = re.compile(r"text/.*")
  contentType = re.search(patternTypes, headerCT)
#\<\s*form\s*method=\s*['\"]?POST['\"]?[^>]*>(?s:.(?<!\<\/form\>))*\<\/form\>
#\<\s*form\s*method=\s*['\"]?POST['\"]?[^>]*>((\s*.*)(?<!\<\/form\>))\<\/form\>
#(?is)\<\s*form\s*method=\s*['\"]?POST['\"]?[^>]*>.*\<\/form\>
#\<\s*form\s*method=\s*['\"]?POST['\"]?[^>]*>(\n(?<!\<\/form\>)|.(?<!\<\/form\>))*\<\/form\>

  # match only text types
  if contentType:
    patternPost = re.compile(r"(?is)<form.*POST[^>]*>.*\<\/form\>")
    patternToken = re.compile(r" name\s*=\s*['\"]?token['\"]?")
    body = msg.getResponseBody().toString()
  # search for POST forms
    matchPost = re.findall(patternPost, body)
    if matchPost:
      for match in matchPost:
  # search for CSRF tokens in the form
        if not (re.search(patternToken, match)):
          try:#for error that occurs with str(match)
            ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
            msg.getRequestHeader().getURI().toString(), 
            "No CSRF token found", "", alertInfo, alertSolution[0], str(match), cweID, wascID, msg);
          except:
            pass
