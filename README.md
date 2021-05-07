# http-request-smuggling-detection-script
  What is HTTP request smuggling? HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users  This script is that send request to target server using simple payload for detecting http request smuggling.
  payload: 
  CL:CL ===============> Content length / Content length 
  CL:TE ===============> Content length / Transfer encoding 
  TE:CL ===============> Transfert encding / Content length
  
  
  
  
  
  scan a url:
  python3 http_smuggling_script.py --url https://www.exemple.com --agent
  
