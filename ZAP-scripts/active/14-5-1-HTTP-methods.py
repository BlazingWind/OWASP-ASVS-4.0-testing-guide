"""
Credit to BlazingWind on Github for this script. https://github.com/BlazingWind/OWASP-ASVS-4.0-testing-guide/blob/main/ZAP-scripts/14-5-1-HTTP-methods.py

Script testing 14.5.1 and 13.2.1 controls from OWASP ASVS 4.0:

'Verify that the application server only accepts the HTTP methods in use by the application or API, including pre-flight OPTIONS.'
The script attempts to connect using HTTP methods: HEAD, POST, PUT, DELETE,  OPTIONS, TRACE, PATCH and OPTIONS. A website or an API should only allow the methods that it is using. 

'Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users using DELETE or PUT on protected API or resources.'

A website should only support use of GET, HEAD, POST and OPTIONS. If use of any other methods is allowed, the script will raise an alert.

"""
import re
#import time
alertTitle = "14.5.1 Verify that the application server only accepts the HTTP methods in use by the application or API, including pre-flight OPTIONS."
alertDescription = "Several HTTP methods have known exploits for them and should not be used." + "/n" + "14.5.1 Verify that the application server only accepts the HTTP methods in use by the application or API, including pre-flight OPTIONS."+ "\n" + "13.2.1 Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users using DELETE or PUT on protected API or resources."
alertRisk = 2
alertReliability = 2
alertSolution = ["Ensure that only the required HTTP methods are allowed", ""]
alertInfo = "Control failure"
cweID = 749
wascID = 0

methods = ["HEAD", "POST", "PUT", "DELETE", "TRACE", "PATCH", "OPTIONS", "PATATATA"]
pattern = re.compile(r"2[0-9]{2}")

# If you get an error java.lang.IllegalArgumentException: java.lang.IllegalArgumentException: host parameter is null
#http://deepakmodi2006.blogspot.com/2011/05/javalangillegalargumentexception-host.html - it comes from CONNECT method
#hf=new HostConfiguration();
#hf.setHost("http://localhost", 22);
def scanNode(sas, msg):
  origMsg = msg;
  # Copy requests before reusing them
  if (sas.isStop()):
    return

  for i in methods:
    msg = origMsg.cloneRequest();
    #print(i, methods[i])
    #alertParam = methods[i]
    msg.mutateHttpMethod(i)
    # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    sas.sendAndReceive(msg, False, False);

    code = str(msg.getResponseHeader().getStatusCode())
    if (re.search(pattern,code)):
      #set response and request body to empy JSON so it can be parsed correctly
      msg.setResponseBody("{}") 
      msg.setRequestBody("{}")

      sas.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription, 
        msg.getRequestHeader().getURI().toString(), 
        i, "", alertInfo, alertSolution[0], "", cweID, wascID, msg);
    #time.sleep(1)

def scan(sas, msg, param, value):
  pass