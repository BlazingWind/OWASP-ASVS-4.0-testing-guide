"""

Script testing 4.1.5 control from OWASP ASVS 4.0:

'Verify that access controls fail securely including when an exception occurs.'

The script will raise an alert if an error status code is returned 400-599 and 
sensitive data is leaked in the response body like ssn, email, file_path, zip_code, ip, netid or version information
 
"""
import re

def scan(ps, msg, src):

  #alert parameters
  alertRisk= 2
  alertConfidence = 1
  alertTitle = "4.1.5 Verify that access controls fail securely."
  alertDescription = "Verify that access controls fail securely including when an exception occurs."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/Fail_securely"
  alertSolution = ""
  alertEvidence = "" 
  cweID = 285
  wascID = 0

  
  try:
    code = str(msg.getResponseHeader().getStatusCode()) # get status code
    body = str(msg.getResponseBody()) #get response body

    error_pattern = re.compile(r"[4-5][0-9]{2}") #regular expression for codes 400-599

    #regular expressions for sensitive data
    ssn = re.compile(r"[0-9]{3}-[0-9]{2}-[0-9]{4}")
    email = re.compile(r"^[\w\.=-]+@[\w\.-]+\.[\w]{2,3}$")
    file_path = re.compile(r"\\[^\\]+$")
    zip_code = re.compile(r"^((\d{5}-\d{4})|(\d{5})|([A-Z]\d[A-Z]\s\d[A-Z]\d))$")
    ip = re.compile(r"^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$")
    netid = re.compile(r"^([a-z]{2,3})([2-9]{1,5})$")
    version = re.compile(r"[a-zA-Z]{1}\d{1,2}\.\d{1,2}\.\d{1,3}")

    patterns = [(ssn, "ssn"), (email, "email"), (file_path, "file path"), (zip_code, "zip code"), (ip, "ip address"), (netid, "netid"), (version, "version")]

    error_code = re.search(error_pattern,code)

    #if the response code is 400-599 and loop through the list of patterns
    #and if the response body contains one of the regex, raise an alert
    if (error_code):
      for pat in patterns:
        match = re.search(pat[0],body)
        if (match):  
          alertEvidence = "Error triggered. Status Code: " + code + "\n" + "Possible " + pat[1] + " found in response body: "+ match.group(0)
          ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
          url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
  except:
    pass

