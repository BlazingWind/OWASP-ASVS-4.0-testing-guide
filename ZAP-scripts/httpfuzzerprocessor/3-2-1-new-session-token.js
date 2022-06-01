/*

Script testing 3.2.1 from OWASP ASVS 4.0:

Verify the application generates a new session token on user authentication.

How to run this script:
	1. Enable the script from the scripts tab
	2. Manually login with a user account in the application
	3. In the history window, right click the login entry, usually it will be a POST message (for juice shop the url is http://localhost:3000/rest/user/login)
	4. Select Attack > Fuzz
	5. If the fuzz location menu, highlight the username value in the JSON object in the request body (ex: highlight test@test.com in {"username":"test@test.com", "password":"test123"})
	6. Select add > add and import a wordlist of valid usernames
	7. Repeat with the password parameter value and a wordlist of corresponding valid passwords
	8. Go to the manage processors tab and select add
	9. Ensure the type is Fuzzer HTTP Processor (Script) and from the script drop down select 3-2-1-new-session-token.js
	10. Start fuzzer

The script will add a custom state in the fuzzer window if 2 or more user accounts share the same session token.

*/


// Auxiliary variables/constants needed for processing.
var count = 1;

//Store all session tokens
var tokens = [];

//function to retrieve session token from response body
//looking for authentication: token: value in the JSON obj in the response
//either returns token or undefined obj
function getToken(body){
	try {
		var obj = JSON.parse(body)
  		var token = obj.authentication.token;
          return token;
	} catch (error) {

	}
}

function processMessage(utils, message) {
	message.getRequestHeader().setHeader("X-Unique-Id", count);
	count++;
}

//ran after the fuzzed msg is sent
function processResult(utils, fuzzResult){

	//testing variables
     var codes = [200, 201, 202, 203, 204, 205, 206, 207, 208, 209];
     var response_code = fuzzResult.getHttpMessage().getResponseHeader().getStatusCode();
     var response_body = fuzzResult.getHttpMessage().getResponseBody();
	var index = codes.indexOf(response_code);
	var current_token = getToken(response_body);
     var payload = utils.getPayloads().toString();
	var index = tokens.indexOf(current_token);

	//alert info
     var risk= 1;
     var confidence = 1;
     var name = "3.2.1 - Verify the application generates a new session token on user authentication.";
     var description = "3.2.1 - Verify the application generates a new session token on user authentication." + "\n" + "Payloads: " + payload + "\n" +"Token repeated: " + current_token + "\n" + "cweID:  " + "384" + "\n" + "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html";
     
     
	if (index != -1){//if current token is in array 
               fuzzResult.addCustomState("Key Custom State", "3.2.1 - Verify the application generates a new session token on user authentication.");
			utils.raiseAlert(risk, confidence, name, description);
        }

	//dont add undefined obj to global token list
	if (current_token !== undefined){
		tokens.push(current_token);
	}
	return true;
}

function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}

