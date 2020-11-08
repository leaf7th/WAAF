from transitions import Machine, State
import Execution
import json
import time
import util

class Attacker(object):
    # Define some states in attack process.
    states = ['initialization',
              State(name='exploit', on_enter=['initial_exploit']),
              State(name='basic', on_enter=['pe']),
              State(name='root', on_enter=['root']),
              State(name='sql', on_enter=['sql']), ]

    transitions = [
        ['start', 'initialization', 'exploit'],
        ['get_shell_success', 'exploit', 'basic'],
        ['sql_success', 'exploit', 'sql'],
        ['pe_success', 'basic', 'root'],
        ['back', ['basic', 'root', 'sql'], 'exploit'],
        ['exploit_back', 'exploit', 'initialization']
    ]

    def __init__(self, argdict):
        self.machine = Machine(model=self, states=self.states, initial='initialization', transitions=self.transitions)
        self.target = argdict["save"]
        self.lhost = argdict["lhost"]
        with open(f'./Data/{self.target}.json', 'r') as f:
            self.data = json.load(f)
        self.start_time = int(time.time())
        report = {}
        j = json.dumps(report, indent=4)
        with open(f"./Report/{self.target}_report.json", "w+") as w:
            w.write(j)
        self.report = f"{self.target}_report.json"
        self.path_count=0

    def initial_exploit(self, debug=None):
        print(f"=== Current state is {self.state} ===")
        print("Are there untested high-risk issues?")
        vuldata = None
        for index, value in enumerate(self.data["issues"]):
            if value["used"] == 0 and value["severity"] == "high" and ((debug == None) or (value["cwe"] == debug)):
                vuldata = value
                vuldata["cookie_string"] = self.data["cookie_string"]
                self.data["issues"][index]["used"] = 1
                j = json.dumps(self.data, indent=4)
                with open(f'./Data/{self.target}.json', 'w') as w:
                    w.write(j)
                break

        if vuldata:
            report_issue = None
            self.path_count+=1
            print("-> Yes!")
            print(f"Start to attack {self.target} through issue {vuldata['name']}...")
            if vuldata["cwe"] == 78:
                report_issue = Execution.cmd_injection(vuldata)
            elif vuldata["cwe"] == 79:
                report_issue = Execution.xss(vuldata)
            elif vuldata["cwe"] == 89:
                report_issue = Execution.sql_injection(vuldata)
            elif vuldata["cwe"] == 22 or vuldata["cwe"] == 98:
                report_issue = Execution.LFI_Path(vuldata)
            elif vuldata["cwe"] == 94:
                report_issue = Execution.RFI(vuldata)
            elif vuldata["cwe"] == 352:
                report_issue = Execution.CSRF(vuldata, self.report)
            if report_issue:
                if report_issue["next_state"] == "initialization":
                    util.generate_report(self.path_count, self.report, report_issue)
                    self.exploit_back()
                    self.start()
                elif report_issue["next_state"] == "basic":
                    self.get_shell_success()
                    if report_issue["cwe"] == 78:
                        path = Execution.pe_cmd(report_issue, lhost=self.lhost)
                    elif report_issue["cwe"] == 94:
                        path = Execution.pe_rfi(report_issue, lhost=self.lhost)
                    util.generate_report(self.path_count, self.report, path)
                    if path["Privilege escalation"]["next_state"] == "root":
                        self.pe_success()
                    self.back()
                elif report_issue["next_state"] == "sql":
                    self.sql_success()
                    util.generate_report(self.path_count, self.report, report_issue)
                    self.back()
                elif report_issue["next_state"] == "root":
                    self.pe_success()
                    util.generate_report(self.path_count, self.report, report_issue)
                    self.back()
            else:
                print("[!] This framework does not include the exploitation of this vulnerability.")
                self.exploit_back()
                self.start()
        else:
            print(f"-> No!")
            print(f"[*] ============ Pentest Finished ============")
            totaltime = int(time.time())-self.start_time
            print(f"[*] Total time : {time.strftime('%H:%M:%S', time.gmtime(totaltime))}")
            print(f"[*] Pentest report : ./Report/{self.report}")

    def pe(self):
        print(f"=== Current state is {self.state} ===")
        print("Basic shell has been obtained.")
        print("Start privilege escalation...")

    def root(self):
        print(f"=== Current state is {self.state} ===")
        print("Root shell has been obtained. \n     Attack path saved.")

    def sql(self):
        print(f"=== Current state is {self.state} ===")
        print("Sql injection finished. \n      Attack path saved.")
