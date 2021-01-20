#!/user/bin/env bash

#This bash script is used to verify controls 9.1.1-3 from OWASP ASVS

# Use a domain supplied when running the script
input=$1

#array with approved cipher suites
approved_ciphers=("ECDHE-ECDSA-AES128-GCM-SHA256" \
"ECDHE-ECDSA-AES256-GCM-SHA384" \
"ECDHE-ECDSA-AES128-SHA" \
"ECDHE-ECDSA-AES256-SHA" \
"ECDHE-ECDSA-AES128-SHA256" \
"ECDHE-ECDSA-AES256-SHA384" \
"ECDHE-RSA-AES128-GCM-SHA256" \
"ECDHE-RSA-AES256-GCM-SHA384" \
"ECDHE-RSA-AES128-SHA" \
"ECDHE-RSA-AES256-SHA" \
"ECDHE-RSA-AES128-SHA256" \
"ECDHE-RSA-AES256-SHA384" \
"DHE-RSA-AES128-GCM-SHA256" \
"DHE-RSA-AES256-GCM-SHA384" \
"DHE-RSA-AES128-SHA" \
"DHE-RSA-AES256-SHA" \
"DHE-RSA-AES128-SHA256" \
"DHE-RSA-AES256-SHA256")

# Try to connect over HTTP and output only status code
check-http () {
        http_status=$(curl -k --w '%{http_code}' --head --silent --output /dev/null  "http://$input/" )

        # check if  status code is 2xx success
        if [[  "$http_status" =~ 2[0-9]{2}   ]]; then
         echo "Connected to $input over HTTP. Status code: $http_status"
         req911="Failure"
         req912="Failure"
         req913="Failure"
        # Check if status code is redirected and try follow redirection
        elif [[  "$http_status" =~ 3[0-9]{2}   ]]; then
         echo "Trying to redirect..."
         check-tls
        else
         echo "Error"
        fi
}

check-tls () {
        r_status=$(curl -k --w '%{http_code}' --head --location --silent --output /dev/null  "http://$input/" )
        r_url=$(curl -k --w '%{url_effective}'  --head --location --silent --output /dev/null "http://$input/" ) 
        echo "Redirect URL: $r_url"
        echo "Status code: $r_status"
        # if the webserver redirects to https, the 9.1.1 control is successful
        # Cycle through all TLS versions to determine which are supported 
        if [[ "$r_url" == "https://"* ]]; then
         req911="Success"
         for version in "tls1" "tls1_1" "tls1_2" "tls1_3"; do
          if timeout 1s openssl s_client -connect $input:443 -$version < /dev/null > /dev/null 2>&1; then
           Connected+=("$version");
          else
           Error+=("$version");
          fi
         done
        fi
         if [[ " ${Connected[@]} " == *"tls1_1"* ]] || [[ " ${Connected[@]} " == *"tls1,"* ]]; then
          req913="Failure";
         elif [[ " ${Connected[@]} " == *"tls1_3"* ]] || [[ " ${Connected[@]} " == *"tls1_2"* ]]; then
          req913="Success";
         fi
}

check-ciphers () {
        echo "Ciphers connected"
        #cycle through all TLS versions
        for versionn in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
         #cycle through all ciphers in each TLS version and replace : with a space 
         for cipher in $(openssl ciphers 'ALL:eNULL' | tr ':' ' '); do
          if [[ " ${approved_ciphers[@]} " =~ " ${cipher} " ]] && [[ "$versionn" = tls1_2 || "$versionn" = tls1_3 ]]; then
           approved="Yes"
          else
           approved="No"
          fi
          #append the cipher to results if openssl connects
          if timeout 1s openssl s_client -connect $input:443 \
          -cipher $cipher -$versionn < /dev/null > /dev/null 2>&1; then
           echo "$input,$versionn,$cipher,$approved"
           if [ "$approved" = "No" ]; then
            req912="Failure"
           else
            req912="Success"
           fi
          fi
          done
         done


}
show-results () {
        echo "9.1.1"
        echo "Verify that secured TLS is used for  all client connectivity, and does not fall back to insecure or unencrypted protocols."
        echo "Result:  $req911"
        echo "»»————-　★　————-««"
        echo "9.1.2"
        echo "Verify using online or up to date TLS testing tools that only strong algorithms, ciphers, and protocols are enabled, with the strongest algorithms and ciphers set as preferred."
        echo "Result: $req912"
        echo "»»————-　★　————-««"
        echo "9.1.3"
        echo "Verify that old versions of SSL and TLS protocols, algorithms, ciphers, and configuration are disabled, such as SSLv2, SSLv3, or TLS 1.0 and TLS 1.1. The latest version of TLS should be the preferred cipher suite."
        echo "Connected"
        echo ${Connected[@]} | sed 's/,/\\n/g'| column -t ;
        echo "Did not connect"
        echo ${Error[@]} | sed 's/,/\\n/g'| column -t ;
        echo "Result: $req913"
        echo "»»————-　★　————-««"
}
check-http
check-ciphers
show-results
