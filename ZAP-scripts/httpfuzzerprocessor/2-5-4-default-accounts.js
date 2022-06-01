/*

Script testing 2.5.4 from OWASP ASVS 4.0:

Verify shared or default accounts are not present (e.g. "root", "admin", or "sa").

How to run this script:
	1. Enable the script from the scripts tab
	2. Manually login with a user account in the application
	3. In the history window, right click the login entry, usually it will be a POST message (for juice shop the url is http://localhost:3000/rest/user/login)
	4. Select Attack > Fuzz
	5. If the fuzz location menu, highlight the username value in the JSON object in the request body (ex: highlight test@test.com in {"username":"test@test.com", "password":"test123"})
	6. Select add > add and import a wordlist of valid usernames
	8. Go to the manage processors tab and select add
	9. Ensure the type is Fuzzer HTTP Processor (Script) and from the script drop down select 2-5-4-default-account.js
	10. Start fuzzer

The script will add a custom state in the fuzzer window if the http response contains "invalid password" rather than "invalid username or password". 
This lets us know that an account with the fuzzed username exists.

*/


// Auxiliary variables/constants needed for processing.
var count = 1;

function processMessage(utils, message) {
	message.getRequestHeader().setHeader("X-Unique-Id", count);
	count++;
}

//ran after the fuzzed msg is sent
function processResult(utils, fuzzResult){

	//testing variables
     var response_body = fuzzResult.getHttpMessage().getResponseBody().toString().toLowerCase(); //set to lowercase for conditional
     var payload = utils.getPayloads().toString();

	//alert info
     var risk= 1;
     var confidence = 1;
     var name = "2.5.4 - Verify shared or default accounts are not present (e.g. root, admin, or sa).";
     var description = "2.5.4 - Verify shared or default accounts are not present (e.g. root, admin, or sa)." + "\n" + "Account found: " + payload + "cweID:  " + "16" + "\n" + "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials";
     
     
	if (response_body.indexOf("invalid password") !== -1){//if "invalid pasword" is found in http response body
               fuzzResult.addCustomState("Key Custom State", "2.5.4 - Verify shared or default accounts are not present (e.g. root, admin, or sa)");
			utils.raiseAlert(risk, confidence, name, description);
        }
	return true;
}

function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}

