#!/usr/bin/python3
import requests
import argparse
import sys
from fake_useragent import UserAgent  ### you can use rou useragent
import time
import socket, ssl
from urllib.parse import urlparse

class checkServer:
    agent = ''
    timeout = 5
    loop = 1
    tmp = 0


    def __init__(self, args):
        self.agent = args.agent
    
##########################################################################################################################################
#   check CLTE {content length/ transfer encoding vulnerability}
##########################################################################################################################################

    def start(self, url, req):
        if self.checkCLTE(url, req) == 0:
        
            if self.checkTECL(url, req) == 0:
                
                if self.checkTETE(url, req) == 0:
                    print(f"Not found vulnerability")
                    
    
    def clear(self, url):
        requests.get(url, headers={"User-Agent" : self.agent})


###########################################################################################################################################
#           check Content length / COnetent length in server 
############################################################################################################################################
    
    def checkCLCL(self):
        header_payload = {
            "Content-Length": ""
        }

###########################################################################################################################################
#      cehck conetent length / Transfer encoding in serer
###########################################################################################################################################
    def checkCLTE(self, url, req):
        print("[*] Testing CL.TE...")
        
        urlInfo = urlparse(url)
        path = urlInfo.path if len(urlInfo.path) > 0 else "/"
        header = 'POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n'.format(path, urlInfo.netloc)
        data = '0\r\n\r\n\r\n'
        
        start = time.time()
        sendPayload(url, header, data)
        
        if time.time() - start >= self.timeout:
            self.printResult(header, data)
            return 1
        return 0
        



############################################################################################################################################
#        check transfert encoding / content length in server 
############################################################################################################################################
    
    def checkTECL(self, url, req):
        print("[*] Testing TE.CL...")
        
        urlInfo = urlparse(url)
        path = urlInfo.path if len(urlInfo.path) > 0 else "/"
        header = 'POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n'.format(path, urlInfo.netloc)
        data = '0\r\n\r\n\r\n'
        
        start = time.time()
        sendPayload(url, header, data)
        
        if time.time() - start >= self.timeout:
            self.printResult(header, data)
            return 1
        return 0
        
        for p in payload:
            for i in range(self.loop):
                sendPayload(url, p["header"], p["data"])
                
                res = requests.post(url, headers={"User-agent" : self.agent})
                ##########################################################
                # Check if request is smuggled.
                ##########################################################
                if res.text.find("GPOST") != -1:
                    self.printResult(p["header"], p["data"], p["vulName"])
                    self.tmp = 1
                    # break
                    return 1
        return 0
    
       
    def printResult(self, header, data, name = ''):
        if sys._getframe(1).f_code.co_name.find("CLTE") == -1 and self.tmp == 0:
            print(f'[*] Server using {sys._getframe(1).f_code.co_name.replace("check", "")[:4]}')
        print(f">> {name}")
        print(f"====== payload ======")
        print(header + data, end="")
        print(f"=====================\n\n")

def sendPayload(url, header, data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    parse = urlparse(url)
    
    if parse.scheme == "https":
        port = 443
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_NONE
        s = context.wrap_socket(s, server_hostname=parse.netloc)
    else:
        port = 80
    
    s.connect((parse.netloc, port))
    s.sendall(header.encode('iso-8859-1') + data.encode('ascii'))

    response = s.recv(1000).decode('utf-8')
    status_code = response[:response.index("\r\n")]
    print(" CODE HTTP  "+status_code)
    
######################################################################################
# Generate fake user-agent
#####################################################################################

def generateUserAgent():
    print("[*] Generating fake user-agent...")
    useragent = UserAgent().chrome
    print("[*] Done.")
    return useragent


def banner():
        print("")
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "HTTP request Smuggler Detection")
    
    parser.add_argument("--url", required=False, help="Input url. --url https://www.exemple.com")
    parser.add_argument("--agent", required=False, action="store_true", help="Generating random User-Agent. --agent")
    args = parser.parse_args()
    
    banner()
    
    # Setting
    if args.url == "" or args.url == None:
        if args.file == "" or args.file == None:
            print("[!] Input URL.")
            exit()
    if args.agent == True:
        args.agent = generateUserAgent()
    else:
        args.agent = "Smuggler test"
    
    url = []
    
    for u in url:
        try:
            r = requests.get(u, headers={"User-agent" : args.agent})
        except requests.exceptions.MissingSchema as e:
            print(f"[!] No schema. Input url including http:// or https://.")
            exit()
        tester = checkServer(args)
        
        print(f"\n\n[*] Sending to {u}")
        
        tester.start(u, r)
