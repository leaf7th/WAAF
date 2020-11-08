import os
import subprocess
import signal
import time
import util
import re

class scanner:
    def __init__(self, args):
        self.url = args["url"]
        self.cookie = args["cookie"]
        self.include = args["include"]
        self.exclude = args["exclude"]
        self.save = args["save"]

    def scan(self):
        target = self.url
        cookies_use = False
        cookie = self.cookie
        # exclude_pattern = "\"logout|security|login|setup\""
        exclude_pattern = self.exclude
        include_pattern = self.include

        path = os.getcwd()
        os.environ["OPENSSL_CONF"] = "/etc/ssl"

        cmd = ["./arachni/bin/arachni", target]
        if cookie:
            cmd.append(f"--http-cookie-string={cookie}")

        if exclude_pattern:
            cmd.append(f"--scope-exclude-pattern={exclude_pattern}")

        if include_pattern:
            cmd.append(f"--scope-exclude-pattern={include_pattern}")

        cmd.append("--audit-links")
        cmd.append("--audit-forms")

        cmd.append(f"--report-save-path={path}/Data")
        # cmdstring = ""
        # for i in cmd:
        #     cmdstring += f" {i}"
        # print(cmdstring)
        # return

        scan_process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        print("[*] =================== Start scanning: ===================")
        report_path = ""
        while True:
            line = scan_process.stdout.readline().decode("UTF-8")
            if "Report saved at: " in line:
                report_path = re.search("\/.*afr", line).group(0)
            if not line:
                break
            print(line.replace('\n', ''))

        savename = self.save
        outfile = f"./Data/{savename}_raw.json"
        report = ["./arachni/bin/arachni_reporter", report_path, f"--reporter=json:outfile={outfile}"]
        report_process = subprocess.Popen(report, stdout=subprocess.PIPE)
        while True:
            line = report_process.stdout.readline().decode("UTF-8")
            if not line:
                print("[*] =================== Scan finish ===================")
                break
            print(line.replace('\n', ''))

        return outfile
