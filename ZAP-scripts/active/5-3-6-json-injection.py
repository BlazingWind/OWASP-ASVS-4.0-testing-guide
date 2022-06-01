"""

Script testing 5.3.6, 5.5.3 and 13.3.2 controls from OWASP ASVS 4.0:
'Verify that the application protects against JSON injection attacks, 
JSON eval attacks, and JavaScript expression evaluation.'

'Verify that deserialization of untrusted data is avoided or is protected in
 both custom code and third-party libraries (such as JSON, XML and YAML parsers).'

'Verify that JSON schema validation is in place and verified before accepting input.'

The scan function will check if a message returns JSON data by checking for "application/json" in the Content-Type response header.
If it does, it will try injecting various common JSON elements like [, ], {, }, etc... that might be used in a JSON injection attack.
The payload will include a key word along with the element. This way, when we check the response body for the payload, we can reudence 
the number of false positives from properly formatted JSON data.

The script will raise an alert if the payload is echoed in the response body (no sanitization or encoding) or the server returns an error.

"""

def scanNode(sas, msg):
  pass

def scan(sas, msg, param, value):
  #alert parameters
  alertRisk= 3
  alertConfidence = 2
  alertTitle = "5.3.6, 5.5.3, 13.2.2 Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation."
  alertDescription = " 5.3.6 Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation." + "\n" " 5.5.3 Verify that deserialization of untrusted data is avoided or is protected in both custom code and third-party libraries (such as JSON, XML and YAML parsers)." + "\n" + "13.2.2 Verify that JSON schema validation is in place and verified before accepting input."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-project-json-sanitizer/migrated_content" + "\n" + "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
  alertSolution = ""
  alertEvidence = "" 
  cweID = 830
  wascID = 0

  common_json_elements = ["[", "]", "{", "}", ",", ":", '"']


  # Copy requests before reusing them
  msg = msg.cloneRequest();
  sas.sendAndReceive(msg, False, False);

  #check if msg response includes json object
  response_header = msg.getResponseHeader().getHeader("Content-Type")
  if ((response_header != None) and "application/json" in response_header):
    for element in common_json_elements:
      attack = "json attack" + element
      
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
          alertEvidence = attack + " found in Response Body"
          sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
          url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
        elif (code == '500'): #check for server error code (500)
          alertAttack = attack
          alertEvidence = "Status Code: " + code + "\n" + "Attack triggered server error."
          sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
          url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
          
      except:
        pass
