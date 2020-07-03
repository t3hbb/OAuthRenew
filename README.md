# OAuthRenew

Based on my JWT/JWS tool, I was testing a web app that used OAuth 2.0 with some non standard parameters that was obtained from a different URL to the one being tested.

The Bearer token was only valid for a few minutes so I adapted the JWT/JWS tool code to handle the bearer token and maintain validity for tests that would have exceeded the lifetime of the token.

Make any changes that you need in the source code (URL for OAuth, data required to pass to the endpoint, how you identify an expired token etc) and then just load in up in Burp and it should auto renew the token.

Probably worth noting that the initial request will need to contain the (in this case) "Authorization: Bearer" header else the extension has nothing to search/replace on.

Please note that this is rudimentary rather than pretty. Please feel free to improve it if you need to. Enjoy! 
