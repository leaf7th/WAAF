from urllib.parse import urlparse
from socket import gethostbyname
import re
import json

def check_ip(ipAddr):
    compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ipAddr):
        return True
    else:
        return False

def get_ip(url):
    host = urlparse(url).hostname
    if check_ip(host):
        return host
    else:
        ip_list = gethostbyname(host)
        return ip_list

def get_path(url):
    path = urlparse(url).path
    return path

def ansi_escape(string):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    result = ansi_escape.sub('', string)
    return result

def generate_report(i, report_file, report_issue):
    with open(f"./Report/{report_file}", "r") as r:
        data = json.load(r)
    data[f"Pentest path {i}"] = report_issue
    j = json.dumps(data, indent=4)
    with open(f"./Report/{report_file}", "w+") as w:
        w.write(j)

def escapeurl(str):
    rstr = r"[\/\\\:\*\?\"\<\>\|]"  # '/ \ : * ? " < > |'
    new_str = re.sub(rstr, "_", str)
    return new_str
