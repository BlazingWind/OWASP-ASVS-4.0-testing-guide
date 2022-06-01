/*

Script testing the following password security controls from OWASP ASVS 4.0:

2.1.1 - Verify that user set passwords are at least 12 characters in length (after multiple spaces are combined).

2.1.2 - Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied.

2.1.4 - Verify that any printable Unicode character, including language neutral characters such as spaces and Emojis are permitted in passwords.

2.1.7 - Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords 
        either locally (such as the top 1,000 or 10,000 most common passwords which match the system's password policy) or using an external API. 
        If using an API a zero knowledge proof or other mechanism should be used to ensure that the plain text password is not sent or used in verifying the breach status of the password. 
        If the password is breached, the application must require the user to set a new non-breached password.

2.1.9 - Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters.


Once the fuzzer is run with the provided wordlist, this script will check the response from each fuzzed request. 

	If the reponse status code is successful (200-209), the script will check the payload and add a custom status code if following criteria apply:
		1. Payload is less than 12 characters (2.1.1)
		2. Payload is greater than 128 characters (2.1.2)
		3. Payload is from top 1,000 most common passwords, taken from rockyou.txt (2.1.7)
		*This condition is true by default if the payload is greater than 12 and less than 128 characters long. This is because the wordlist contains only payloads from rockyou.txt and payloads that are too short or too long.
		*If changes are made to the wordlist or another one is used, false positive may be triggered so please review your results.
	
	If the response status code is NOT successful,  the script will check the payload and add a custom status code if following criteria apply (Note: these conditions are more prone to false positives):
		1. Payload is between 64 and 128 characters (2.1.2)
		2. Payload is valid length and contains special character (2.1.9)
		3. Payload is valid length and contains a space or emoji (2.1.4)

*/


// Auxiliary variables/constants needed for processing.
var count = 1;

//function to determine if string contains a special character using regex
function containsSpecial(str){
	var regex = /[ !@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g;
	return regex.test(str);
}

//function to determine if string contains an emoji or space since the only payloads in the wordlist that contain those characters start with DGGVss
function containsEmoji(str){
	var index = str.indexOf("DGGVss");
     return (index != -1);
	
}

function processMessage(utils, message) {
	message.getRequestHeader().setHeader("X-Unique-Id", count);
	count++;
}

function processResult(utils, fuzzResult){

	//testing variables
     var payload = utils.getPayloads().toString();
     var codes = [200, 201, 202, 203, 204, 205, 206, 207, 208, 209];

     var response_code = fuzzResult.getHttpMessage().getResponseHeader().getStatusCode();
	var index = codes.indexOf(response_code);
	var length = payload.length;
  

	//alert info
     var risk= 0;
     var confidence = 1;
     var name = "Fuzzer: Password Security";
     var description = "Please check the state column in the Fuzzer window to see which ASVS control was triggered for each payload." + "\n" + "Status Code: " + response_code + "\n" + "cweID:  " + "521" + "\n" + "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy";
     
     
	if (index != -1){//if, status code is found in list of successful codes (permitted)
          if (length < 12){//Payload is less than 12 characters (2.1.1)
               fuzzResult.addCustomState("Key Custom State", "2.1.1 - Verify that user set passwords are at least 12 characters in length (after multiple spaces are combined).");
               risk= 1;
			utils.raiseAlert(risk, confidence, name, description);
          }else if (length > 128){ //Payload is greater than 128 characters (2.1.2)
               fuzzResult.addCustomState("Key Custom State", "2.1.2 - Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied.")
               risk= 1;
			utils.raiseAlert(risk, confidence, name, description);
          }else{//Payload is from top 1,000 most common passwords, taken from rockyou.txt (2.1.7)
               fuzzResult.addCustomState("Key Custom State", "2.1.7 - Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords" 
        + "either locally (such as the top 1,000 or 10,000 most common passwords which match the system's password policy) or using an external API. "
        + "If using an API a zero knowledge proof or other mechanism should be used to ensure that the plain text password is not sent or used in verifying the breach status of the password. "
        + "If the password is breached, the application must require the user to set a new non-breached password.")
               risk= 1;
			utils.raiseAlert(risk, confidence, name, description);
}

     }else{//if denied/error (response code is not 200-209)
          if (length > 63 && length < 129){//Payload is between 64 and 128 characters (2.1.2) but was denied
			fuzzResult.addCustomState("Key Custom State", "2.1.2 - Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied.")
			utils.raiseAlert(risk, confidence, name, description);
		}else if ((length > 11 && length < 129) && containsEmoji){//Payload is valid length and contains emoji or space (2.1.4) but was denied
               fuzzResult.addCustomState("Key Custom State", "2.1.4 - Verify that any printable Unicode character, including language neutral characters such as spaces and Emojis are permitted in passwords.")
			utils.raiseAlert(risk, confidence, name, description);
		}else if ((length > 11 && length < 129) && containsSpecial(payload)){//Payload is valid length and contains special character (2.1.9) but was denied
               fuzzResult.addCustomState("Key Custom State", "2.1.9 - Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters.")
			utils.raiseAlert(risk, confidence, name, description);
          }

     }
	return true;
}

function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}

