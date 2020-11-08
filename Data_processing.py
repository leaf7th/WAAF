import json
from Vulnerability import Vul

def data_processing(file):
    print("\n[*] =================== Start data processing ===================")
    path = file
    fo = open(path)
    data = json.load(fo)
    fo.close()
    print("[*] Remove redundant information")
    new_data = {}
    new_data["sitemap"] = data["sitemap"]
    new_data["issues"] = []
    if data["options"]["http"]["cookie_string"]:
        new_data["cookie_string"] = data["options"]["http"]["cookie_string"].replace("path=/","").replace(",","").replace(" ","")[:-1]
    else:
        new_data["cookie_string"] = ""
    i = 0
    for dic in data["issues"]:
        new_dic = {}
        new_dic["name"] = dic["name"]
        new_dic["url"] = dic["vector"]["url"]
        if "cwe" in dic.keys():
            new_dic["cwe"] = dic["cwe"]
        if "cwe_url" in dic.keys():
            new_dic["cwe_url"] = dic["cwe_url"]
        new_dic["severity"] = dic["severity"]
        new_dic["vector"] = dic["vector"]
        if "proof" in dic.keys():
            new_dic["proof"] = dic["proof"]
        new_dic["affected_page"] = dic["page"]["dom"]["url"]
        new_dic["used"] = 0
        new_data["issues"].append(new_dic)
    print("[*] Add metrics information")
    for issue in new_data["issues"]:
        if "cwe" in issue.keys():
            if issue["cwe"] == 79:
                issue["score"] = Vul.XSS.score()
            elif issue["cwe"] == 89:
                issue["score"] = Vul.SQLi.score()
            elif issue["cwe"] == 78:
                issue["score"] = Vul.CMDi.score()
            elif issue["cwe"] == 94:
                issue["score"] = Vul.RFI.score()
            elif issue["cwe"] == 352:
                issue["score"] = Vul.CSRF.score()
            elif issue["cwe"] == 22:
                issue["score"] = Vul.PATH.score()
            elif issue["cwe"] == 98:
                issue["score"] = Vul.LFI.score()
    new_data["issues"].sort(key=lambda k: (k.get("score", 0)), reverse=True)

    # Test
    # for i in new_data["issues"]:
    #     print(i["name"], i["score"])

    fo = open(file.replace('_raw',''), "w+")
    j = json.dumps(new_data, indent=4)
    fo.write(j)
    fo.close()
    print("[*] =================== Data processing done! ===================\n")
    return

# Test
# data_processing("latest_raw")