"""
Credit to BlazingWind on Github for this script:https://github.com/BlazingWind/OWASP-ASVS-4.0-testing-guide/blob/main/ZAP-scripts/14-3-1-Error-messages.py

Script testing 14.3.1 and 7.4.1 controls from OWASP ASVS 4.0:
'Verify that web or application server and framework error messages are configured to deliver user actionable, customized responses to eliminate any unintended security disclosures.'

'Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support personnel can use to investigate. (C10)'

The script attempts to trigger errors in a web application and checks the response for any software component disclosure - if it finds one, it raises an alert. Most of the attacks are based on OWASP WSTG v4.1
chapter 8.1 Testing for Error Code.
"""
import re

alertTitle = "14.3.1 Verify that web or application server and framework error messages are configured to deliver user actionable, customized responses to eliminate any unintended security disclosures."
alertDescription = "Default error pages has been found which may disclose information about the underlying software and web server in use."
alertRisk = 0
alertReliability = 1
alertSolution = ["Configure the web server to diplay a custom, user-actionable error page instead.", ""]
alertInfo = "Control failure"
cweID = "209 and 210"
wascID = 0

pattern = re.compile(r"[4-5][0-9]{2}")
evidence = re.compile(r"(?i)Bad request|Unauthorized|Payment Required|Forbidden|Not Found|Apache|nginx|IIS|stack|40[1-3]|40[5-9]|5[0-9]{2}")

def scanNode(sas, msg):
  origMsg = msg;
  # Copy requests before reusing them
  msg = origMsg.cloneRequest();
  
  # GET resource that doesn't exist
  alertParam = "/patatata"
  msg.getRequestHeader().getURI().setPath(alertParam)
  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sendMsg(sas, msg, alertParam)
  
  # Use TRACE method that shouldn't be allowed
  msg = origMsg.cloneRequest()
  alertParam = "TRACE method"
  msg.getRequestHeader().setMethod("TRACE")
  sendMsg(sas, msg, alertParam)

  # Use an HTTP method that doesn't exist
  msg = origMsg.cloneRequest()
  alertParam = "Method that doesn't exist"
  msg.getRequestHeader().setMethod("PATATATA")
  sendMsg(sas, msg, alertParam)

  # Use an older version of HTTP
  msg = origMsg.cloneRequest()
  alertParam = "HTTP/0.9"
  msg.getRequestHeader().setVersion(alertParam)
  sendMsg(sas, msg, alertParam)

  # Use a protocol that doesn't exist - does not work bc of regex check which uses HTTP
  #msg = origMsg.cloneRequest()
  #alertParam = "Invalid protocol"
  #msg.setRequestHeader("GET " + msg.getRequestHeader().getURI().toString() + " INVALID/1.1")
  #sendMsg(sas, msg, alertParam)

  # Set Host header to localhost - ZAP enforces the header, can't be changed. See https://github.com/zaproxy/zaproxy/issues/1318
  #msg = origMsg.cloneRequest()
  #alertParam = "Host: localhost header"
  #prime = msg.getRequestHeader().getPrimeHeader()
  #msg.setRequestHeader(prime)
  #msg.getRequestHeader().addHeader("Host", "localhost")
  #sendMsg(sas, msg, alertParam)

  # Send only the first line of the request (ZAP adds Content-Length and Host headers and thus this may not trigger anything)
  msg = origMsg.cloneRequest()
  alertParam = "Prime line of the request"
  prime = str(msg.getRequestHeader().getPrimeHeader())
  msg.setRequestHeader(prime + "\r\n\r\n")
  sendMsg(sas, msg, alertParam)

def scan(sas, msg, param, value):
  pass

def sendMsg(sas, msg, alertParam):
  if (sas.isStop()):
    return
  sas.sendAndReceive(msg, False, False);

  code = str(msg.getResponseHeader().getStatusCode())
  if (re.search(pattern,code)):
    body = msg.getResponseBody().toString()
    if (re.search(evidence,body)):
      sas.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
        msg.getRequestHeader().getURI().toString(), 
        alertParam, "", alertInfo, alertSolution[0], "", cweID, wascID, msg);
  
