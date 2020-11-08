# Web Attack Automation Framework
## Dependency
[Arachni](https://github.com/Arachni/arachni) --- Download to main directory

[commix](https://github.com/commixproject/commix) --- Download and add to PATH

[sqlmap](https://github.com/sqlmapproject/sqlmap) --- Download and add to PATH

[metasploit](https://www.metasploit.com/download) --- Download and add to PATH

[transitions](https://github.com/pytransitions/transitions) --- pip install

## Structure
```
WAAF
├── Data
│   ├── http___192.168.1.112_dvwa_vulnerabilities_.json         # example security model
│   ├── http___192.168.1.112_dvwa_vulnerabilities__raw.json     # example scan results
│   └── scanlist.json
├── msfScript
│   ├── 5675.rc
│   ├── 7281.rc
│   └── 9906.rc
├── Report
│   └── http___192.168.1.112_dvwa_vulnerabilities__report.json  # example report
├── Data_processing.py
├── Execution.py
├── Main.py
├── Plan.py
├── Scan.py
├── util.py
├── Vulnerability.py
└── webserver.py
```

## Usage
`$ python3 Main.py -h`

```
usage: Main.py [-h] --url URL [--cookie COOKIE] [--include INCLUDE] [--exclude EXCLUDE] [--file FILE] --lhost LHOST

WAAF is a quickly deployable and easy to use web attack automation framework.

optional arguments:
  -h, --help                        show this help message and exit
  --url URL, -u URL                 Set the target
  --cookie COOKIE, -C COOKIE        Set the cookies for scanning.
  --include INCLUDE, -I INCLUDE     Restricts the scope of the scan to resources whose URL matches the pattern.
  --exclude EXCLUDE, -E EXCLUDE     Excludes resources whose URL matches the pattern.
  --file FILE, -F FILE              Start to exploit with existing scan results
  --lhost LHOST, -L LHOST           Set the local host for exploit
```

`$ python3 webserver.py -h`

```
usage: webserver.py [-h] --port PORT

WAAF is a quickly deployable and easy to use web attack automation framework.

optional arguments:
  -h, --help                        show this help message and exit
  --port PORT, -P PORT              Listen the port
```

## Example
```bash
# Scan and attack
python3 Main.py -u http://192.168.1.112/dvwa/vulnerabilities/ -C "security=low; path=/, PHPSESSID=608238f8a2df906199a85596a101a7e0; path=/" -E "logout|security|login|setup" -L 192.168.1.111
# Attack with existing scan results
python3 Main.py -u http://192.168.1.112/dvwa/vulnerabilities/ -F "./Data/http___192.168.1.112_dvwa_vulnerabilities__raw.json" -L 192.168.1.111
# Webserver
python3 webserver.py -P 9000
curl localhost:9000/scan -d "url=http://192.168.1.112/dvwa/vulnerabilities/&lhost=192.168.1.111"
```