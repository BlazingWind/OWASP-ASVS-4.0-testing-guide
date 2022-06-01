"""

Script testing 3.2.2 control from OWASP ASVS 4.0:
'Verify that session tokens possess at least 64 bits of entropy.'

From OWASP: A session token with 64 bits of entropy must be at least 128 bits in length. The script will raise an alert if a session token is less than 128 bits. The Randomly Selected Passwords formula by Claude Shannon will be used to calculate the bit legth of the token. 

Credit to 4k1 on GitHub for thier implementation of this formula in python. https://gist.github.com/4k1/6fbe670807db1d48407685d6cc46b0af 

"""

import ast, math

#check response body for valid token and return it
#return None if no token is found
def getToken(msg):
  token = None
  try:
    body = str(msg.getResponseBody())
    token = ast.literal_eval(body).get('authentication').get('token')
  except:
    pass
  return token

#calculate entropy of a given token
def calculateEntropy(token):
  n = len(list(set(list(token)))) #n = set of possible characters for token
  l = len(token) #l = length of token
  h = math.log(math.pow(n, l), 2) #h = log2(n^l) = entropy
  return h


def scan(ps, msg, src):

  #alert parameters
  alertRisk= 1
  alertConfidence = 1
  alertTitle = "3.2.2 Verify that session tokens possess at least 64 bits of entropy."
  alertDescription = "Session identifiers should be at least 128 bits long to prevent brute-force session guessing attacks."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length"
  alertSolution = "Ensure any session token is at least 128 bits long." + "\n" + "Note: a single token that does not meet the entropy requirement is not sufficient to show the token generation is insecure."
  alertEvidence = "" 
  cweID = 331
  wascID = 0

  token = getToken(msg)

  if token: #if token is not None
    entropy = calculateEntropy(token)
    if (entropy < 128): #raise alert if entropy is less than 128
      alertEvidence = "Token " + str(token) + "/n" + "Entropy " + entropy
      ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);