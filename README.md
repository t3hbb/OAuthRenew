# OAuthRenew

Based on my JWT/JWS tool, I was testing a web app that used OAuth 2.0 with some non standard parameters that was obtained from a different URL to the one being tested.

The Bearer token was only valid for a few minutes so I adapted the JWT/JWS tool code to handle the bearer token and maintain validity for tests that would have exceeded the lifetime of the token.

Make any changes that you neeed in the source code (URL for OAuth, data required to pass to the endpoint, how you identify an expired token etc) and then just load in up in Burp and it should auto renew the token.
