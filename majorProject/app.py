import urllib
import http.client as httplib
from xml.etree import ElementTree as ET
import base64
import csv

log_path = "burp.log"

def parse_log(log_path):
    """
    This function accepts a Burp log file path
    and returns a dictionary of request and response
    result = {'GET /page.php...': '200 OK HTTP / 1.1....', '': '', ...}
    """
    result = {}
    try:
        with open(log_path) as f:
            pass
    except FileNotFoundError:
        print("[+] Error!!! ", log_path, " doesn't exist..")
        exit()
    try:
        tree = ET.parse(log_path)
    except ET.ParseError as e:
        print(
            "[+] Oops..! Please make sure binary data is not present in the log, like raw image dump, flash (.swf files) dump, etc.")
        exit()
    root = tree.getroot()
    for reqs in root.findall("item"):
        raw_req = reqs.find("request").text
        raw_req = urllib.parse.unquote(raw_req)
        raw_resp = reqs.find("response").text
        result[raw_req] = raw_resp
    return result

def parseRawHTTPReq(rawreq):
    try:
        if isinstance(rawreq, bytes):
            raw = rawreq.decode("utf8")
        else:
            raw = rawreq
    except Exception as e:
        raw = rawreq
    headers = {}
    method = ""
    body = ""
    path = ""
    sp = raw.split('\r\n\r\n', 1)
    if sp[1] != "":
        head = sp[0]
        body = sp[1]  
    else:
        head = sp[0]
        body = ""

    c1 = head.split('\n', head.count('\n'))
    method = c1[0].split(' ', 2)[0]
    path = c1[0].split(' ', 2)[1]
    for i in range(1, head.count('\n') + 1):
        slice1 = c1[i].split(': ', 1)
        if slice1[0] != "":
            try:
                headers[slice1[0]] = slice1[1]
            except:
                pass
    return headers, method, body, path


f = open('httplog.csv', "w")
c = csv.writer(f)
c.writerow(["method","body","path","headers"])
f.close()            

result = parse_log(log_path)

# Example usage:

for items in result:
    data = []
    raaw = base64.b64decode(items)
    headers,method,body,path = parseRawHTTPReq(raaw)
    data.append(method)
    data.append(body)
    data.append(path)
    data.append(headers)
    f = open('httplog.csv', "a")
    c = csv.writer(f)
    c.writerow(data)
    f.close()