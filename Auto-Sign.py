#coding:utf-8
import sys  
from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
import hashlib
import re

reload(sys)
sys.setdefaultencoding('utf8')

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auto-Sign")
        callbacks.registerHttpListener(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.issueAlert("Loaded Successfull.")

    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        if messageIsRequest:

            requestInfo = self._helpers.analyzeRequest(currentRequest)

            self.headers = list(requestInfo.getHeaders())
            #print self.headers
            if "sign:" in str(self.headers) :

                bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
                self.body = self._helpers.bytesToString(bodyBytes)
                body=self.body.decode('utf-8')
                new_sign = self.update_sign(body)

                headers = str(self.headers).replace("u'", "")
                pattern = re.compile(r'sign: [A-Za-z0-9]+')
                old_sign = pattern.findall(headers)

                old_sign = str(old_sign).replace("['", "")
                old_sign = str(old_sign).replace("']", "")
                old_sign = old_sign

                index=self.headers.index(old_sign)
                self.headers[index] = self.headers[index].replace(self.headers[index],new_sign)
                print self.headers[index]
                #print ", ".join(self.headers)

                newMessage = self._helpers.buildHttpMessage(self.headers, self.body)
                currentRequest.setRequest(newMessage)

            else:
                print "no sign in headers"

        # Process responses
        else:
            pass

    def update_sign(slef,body):
        try:
            appKey = "TEST_KEY"
            hash_param='secret= '+appKey+'&'+body

            print "-----------------------------"
            print hash_param
            print "-----------------------------"

            sign = hashlib.sha1(hash_param).hexdigest()
            sign = 'sign:'+sign.upper()
            return sign

        except Exception, e:
            print e
            return "",""
