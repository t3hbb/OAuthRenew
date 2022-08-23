
print "Loading OAuth Bearer Token Tool"
print "https://github.com/t3hbb/OAuthRenew"
print "Check for an expired Bearer token and replace if required."
print "Remember to update any neccessary details in the extension!\n"

#A big thank you to @mohammadaskar2 for helping speak parseltongue!
  
from burp import IBurpExtender
from burp import IHttpListener
from burp import ISessionHandlingAction


  
# Regex are used for capturing the token value from the response
import re
import ssl
import urllib2
import httplib
import base64

#I still hate regex. It's witchcraft. :)

#PLEASE UPDATE THESE LINES - 1st SECTION

#Regex to find the token in the response
AccessTokenRegex = re.compile(r"access_token\"\:\"(.*?)\"")
#Regex to identify if bearer token expired
BearerErrorRegex = re.compile(r"Unauthorized")

class BurpExtender(IBurpExtender, IHttpListener, ISessionHandlingAction):
	# Variables to hold the tokens found so that it can be inserted in the next request
	discoveredBearerToken = ''

  
	def registerExtenderCallbacks(self, callbacks):
		 self._callbacks = callbacks
		 self._helpers = callbacks.getHelpers()
		 callbacks.setExtensionName("OAuthRefresher")
		 callbacks.registerHttpListener(self)
		 print "Extension registered successfully."
		 return
  
	def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
		# Operate on all tools other than the proxy. Comment out if you are passing stuff through from Postman or SoapUI
		#if toolFlag != self._callbacks.TOOL_PROXY:
		if messageIsRequest:
			#Check to see if a replacement bearer token exists
			if BurpExtender.discoveredBearerToken != '':
				self.processRequest(currentMessage)
		else:
			self.processResponse(currentMessage)
 
	def processResponse(self, currentMessage):
		print "Response received"
		response = currentMessage.getResponse()
		parsedResponse = self._helpers.analyzeResponse(response)
		respBody = self._helpers.bytesToString(response[parsedResponse.getBodyOffset():])
		#Search the response for the error message indicating the token has expired
		token = BearerErrorRegex.search(respBody)
		#Some debugging strings - remove if you have flow or logger++
		if token is None:
			print "Bearer token is valid"
		else:
			print "Bearer token expired - obtaining new one"
			self.BearerRefresh()
			print "New Bearer Token Acquired : ",BurpExtender.discoveredBearerToken
			

	def processRequest(self, currentMessage):
		request = currentMessage.getRequest()
		requestInfo = self._helpers.analyzeRequest(request)
		headers = requestInfo.getHeaders()
		requestBody = self._helpers.bytesToString(request[requestInfo.getBodyOffset():])
		#headers is an array list
		#Convert to single string to process (sorry!)
		headerStr=""
		for x in range(len(headers)): 
			headerStr = headerStr + headers[x] +"\n"
		reqBody = currentMessage.getRequest()[requestInfo.getBodyOffset():]
		reqBody = self._helpers.bytesToString(request)
		
		updatedheaders = headerStr
		
		# Update Bearer token
		print "Replacing Bearer Token with latest obtained"#,BurpExtender.discoveredBearerToken #Uncomment first hash to see bearer token
		updatedheaders = re.sub(r"Authorization\: .*", "Authorization: Bearer {0}".format(BurpExtender.discoveredBearerToken), headerStr)
		
		#convert headers back into a list
		headerslist = updatedheaders.splitlines()
		updatedRequest = self._helpers.buildHttpMessage(headerslist, requestBody)
		currentMessage.setRequest(updatedRequest)
		
		
	def BearerRefresh(self):
		# PLEASE UPDATE THESE LINES - 2nd SECTION
		print "Authing App - visiting URL"
		# HOST SHOULD BE IN FORMAT https://host.com
		host = "REPLACE_AUTH_URL_HERE"
		req = urllib2.Request(host)
		req.add_header('User-Agent','Mozilla/5.0') # (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0')
		# UNCOMMENT (OR MODIFY) LINE BELOW IF YOU WISH TO SEND JSON
		#req.add_header('Content-Type', 'application/json')
		#REPLACE data BELOW WITH APPROPRIATE VARIABLES
		data = "grant_type=client_credentials&client_id=CLIENTID&client_secret=CLIENTSECRET&scope=SCOPE&audience=AUDIENCE"
		#IF THE DATA YOU NEED TO SEND CONTAINS INVERTED COMMAS i.e JSON, THEN YOU CAN USE BASE64 TO SEND IT
		#data = base64.b64decode('eyJncmFudF90eXB==')
		req.add_data(data)
		resp = urllib2.urlopen(req) #, context=ssl._create_unverified_context())
		content = resp.read()
		#print content
		token = AccessTokenRegex.search(content)
		#print token
		BurpExtender.discoveredBearerToken=token.group(1)
		if BurpExtender.discoveredBearerToken is None:
			print "***Error aquiring token***"
		
		
