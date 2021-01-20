# 14.4.2 Content-Disposition: attachment

> Verify that all API responses contain Content-Disposition: attachment; filename="api.json" (or other appropriate filename for the content type).

CWE 116

# Explanation

Content-disposition header in an API response is used to automatically give a name to a file downloaded by a user. Adding the header to API responses helps protect against misunderstanding of the MIME type between client and server. The "filename" option helps protect against Reflected File Download attacks.

# Testing methods

## Manually

Find and try to fetch some resources from the API using DevTools, curl, Postman or other tool. Observe the response for Content Disposition header.

## Proxy

Enable the script "14-4-2 Content-Disposition: attachment.py" found under Scripts > Passive Rules. Using the built-in browser, browse directly to the API and fetch one or more of the resources. If the response does not contain Content-Disposition header, the script will raise an alert.

You may also look in the proxy at the response yourself.

# Control

Observe if the header Content-Disposition with a proper name is in the response. If yes, control is successful.

# Resources

[https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/reflected-file-download-a-new-web-attack-vector/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/reflected-file-download-a-new-web-attack-vector/)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition)