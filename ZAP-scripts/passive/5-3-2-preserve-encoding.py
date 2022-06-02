"""

Script testing 5.3.2 control from OWASP ASVS 4.0:
'Verify that output encoding preserves the user's chosen character set and locale, 
such that any Unicode character point is valid and safely handled.'

The script will raise an alert if the response header "Content-Type" does not retain 
the charcter set specified in the request header "Accept"

"""
#try to parse the headers to capture charset values and return as dictionary
#if charset is not in header, return 0
def get_char_sets(req, resp):
  try:
    req_index = req.index("charset=") + 8
    resp_index = resp.index("charset=") + 8 
    return {"req" : req[req_index:], "resp": resp[resp_index:]}
  except:
    return 0

def diff_encoding(req, resp):
  sets = get_char_sets(req, resp) #get character sets if listed
  if ("*/*" in req or req == "None"): #if request will accept any encoding or is not specified, return false
    return False
  elif ((resp == "None") or (sets != 0 and (sets["resp"] not in sets["req"]))): #if there is no response header or the character sets dont match, return true
    return True
  return False #all else, return false

def scan(ps, msg, src):

  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "5.3.2 Verify that output encoding preserves the user's chosen character set and locale."
  alertDescription = "Verify that output encoding preserves the user's chosen character set and locale, such that any Unicode character point is valid and safely handled."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = ""
  alertSolution = "Ensure the application preserves the user's chosen character set (located in the 'Accept' Header) by responding with the appropriate 'Content-Type' Header"
  alertEvidence = "" 
  cweID = 176
  wascID = 0
   
  #get request and response headers for 'Accept' and 'Content-Type'
  request_header = str(msg.getResponseHeader().getHeader("Accept"))
  response_header = str(msg.getResponseHeader().getHeader("Content-Type"))

  
  #if the request header and response header dont have matching character sets, raise alert
  if (diff_encoding(request_header, response_header)):
    alertEvidence = "Character set requested: " + request_header + "\n" + "Character set sent: " + response_header
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
    url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
