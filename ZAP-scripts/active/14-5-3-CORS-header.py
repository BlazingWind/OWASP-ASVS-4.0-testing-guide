"""
Script testing 14.5.3 control from OWASP ASVS 4.0:
'Verify that the cross-domain resource sharing (CORS) Access-Control-Allow-Origin header uses a strict white-list of trusted domains to match against and does not support the "null" origin.'

The script sends a CORS request from an inexisitent domain to determine if the Access-Control-Allow-Origin header is configured with a wildcard, if it reflected the Origin header or if the request was blocked.
"""
import re

alertTitle = '14.5.3 Verify that the cross-domain resource sharing (CORS) Access-Control-Allow-Origin header uses a strict white-list of trusted domains to match against and does not support the "null" origin.'
alertDescription = "This controls checks if CORS policy is properly configured."
alertRisk = 0
alertReliability = 1
alertSolution = ["Use a strict whitelist of sites allowed to request resources of your domain", ""]
alertInfo = "Control failure"
cweID = 346
wascID = 0

origin = "exampletestsite.com"

def scanNode(sas, msg):
  origMsg = msg;
  # Copy requests before reusing them
  msg = origMsg.cloneRequest();
  
  # GET resource that doesn't exist
  msg.getRequestHeader().setHeader("Origin", origin)

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken) 
  if (sas.isStop()):
    return
  sas.sendAndReceive(msg, True, False);

  header = str(msg.getResponseHeader().getHeader("Access-Control-Allow-Origin"))
  header
  if (header == "*"):
    alertParam = "wildcard directive in Access-Control-Allow-Origin"
    sas.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], "", cweID, wascID, msg);
  elif (header == origin):
    alertParam = "Access-Control-Allow-Origin reflects Origin header"
    sas.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], "", cweID, wascID, msg);
  elif (header == "null"):
    alertParam = "Access-Control-Allow-Origin is null"
    sas.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
      msg.getRequestHeader().getURI().toString(), 
      alertParam, "", alertInfo, alertSolution[0], "", cweID, wascID, msg);

def scan(sas, msg, param, value):
  pass

