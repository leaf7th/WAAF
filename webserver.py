import flask
from flask import request, jsonify
import json
import argparse
import Data_processing
import Scan
import Plan
import util
from multiprocessing import Process


parser = argparse.ArgumentParser(description="WAAF is a quickly deployable and easy to use web attack automation framework.")
parser.add_argument('--port', '-P', required=True,
                    help='Listen the port')
args = parser.parse_args()

port = args.port

def pentest():
    # while True:
    #     print("test")
    #     time.sleep(1)
    while True:
        with open(f"./Data/scanlist.json", "r") as r:
            data = json.load(r)
        for k,v in data.items():
            if v["report"]:
                save_name = util.escapeurl(args.url)
                argsdict = {
                    "url": v["url"],
                    "save": save_name,
                    "file": False,
                    "lhost": args.lhost
                }
                if not argsdict["file"]:
                    scan = Scan.scanner(dict)
                    argsdict["file"] = scan.scan()
                data = Data_processing.data_processing(argsdict["file"])
                exploit = Plan.Attacker(dict)
                exploit.start()

app = flask.Flask(__name__)
app.config["DEBUG"] = True

@app.route('/scan', methods=['POST'])
def gettarget():
    url = ""
    status = "success"
    if 'url' in request.form:
        url = request.form['url']
    else:
        status = "failed"
        return jsonify({"status": status,
                "error": "IP is needed!"})
    if 'lhost' in request.form:
        lhost = request.form['lhost']
    else:
        status = "failed"
        return jsonify({"status": status,
                "error": "lhost is needed!"})
    target = {"url" : url,
              "lhost" : lhost}
    res = add2list(target)
    return jsonify(res)

def add2list(target):
    url = target["url"]
    lhost = target["lhost"]
    with open(f"./Data/scanlist.json", "r") as r:
        data = json.load(r)
    key = f"{url}"
    if key in data.keys():
        return data[key]
    else:
        data[key] = { "url" : url,
                      "lhost" : lhost,
                      "status" : "waiting",
                      "report" : False}
        j = json.dumps(data, indent=4)
        with open(f"./Data/scanlist.json", "w+") as w:
            w.write(j)
        return data[key]

pentestprocess = Process(
    target=pentest,
    daemon=True
)
pentestprocess.start()

app.run(host="127.0.0.1", port=f"{port}")
