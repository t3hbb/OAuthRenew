
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

#I still hate regex. It's witchcraft. :)

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
		 callbacks.setExtensionName("OAuthRenewalTool")
		 callbacks.registerHttpListener(self)
		 print "Extension registered successfully."
		 return
  
	def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
		# Operate on all tools other than the proxy. Comment out if you are passing stuff through from Postman or SoapUI
		#if toolFlag != self._callbacks.TOOL_PROXY:
		if messageIsRequest:
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
		
		if BurpExtender.discoveredBearerToken != '':
		# Update Bearer token
			print "Replacing Bearer Token with latest obtained"#,BurpExtender.discoveredBearerToken #Uncomment first hash to see bearer token
			updatedheaders = re.sub(r"Authorization\: .*", "Authorization: Bearer {0}".format(BurpExtender.discoveredBearerToken), headerStr)
		#else:
			#print "No Bearer token to replace."	
		#Commented out to reduce output in log.

		#convert headers into a list
		headerslist = updatedheaders.splitlines()
		updatedRequest = self._helpers.buildHttpMessage(headerslist, requestBody)
		currentMessage.setRequest(updatedRequest)
		
		
	def BearerRefresh(self):
		#Debug String
		print "Authing App - visiting URL"
		#URL to visit to request a new token
		host = "URL"
		req = urllib2.Request(host)
		#User agent
		req.add_header('User-Agent','Mozilla/5.0') # (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0')
		#Data to POST - feel free to change to how you need it
		data = "grant_type=client_credentials&client_id=CLIENTID&client_secret=CLIENTSECRED&scope=SCOPE&audience=AUDIENCE"
		req.add_data(data)
		resp = urllib2.urlopen(req) #, context=ssl._create_unverified_context())
		content = resp.read()
		token = AccessTokenRegex.search(content)
		BurpExtender.discoveredBearerToken=token.group(1)
		print "New Bearer Token ", BurpExtender.discoveredBearerToken
	

		
		
		
