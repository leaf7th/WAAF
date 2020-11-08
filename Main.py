import Plan
import Data_processing
import Scan
import util
import argparse

framworkascii = r"""
 ___       __   ________  ________  ________ 
|\  \     |\  \|\   __  \|\   __  \|\  _____\
\ \  \    \ \  \ \  \|\  \ \  \|\  \ \  \__/ 
 \ \  \  __\ \  \ \   __  \ \   __  \ \   __\
  \ \  \|\__\_\  \ \  \ \  \ \  \ \  \ \  \_|
   \ \____________\ \__\ \__\ \__\ \__\ \__\
    \|____________|\|__|\|__|\|__|\|__|\|__|
"""

parser = argparse.ArgumentParser(description="WAAF is a quickly deployable and easy to use web attack automation framework.")

parser.add_argument('--url', '-u', required=True,
                    help='Set the target')
parser.add_argument('--cookie', '-C',
                    help='Set the cookies for scanning.',
                    default=False)
parser.add_argument('--include', '-I',
                    help='Restricts the scope of the scan to resources whose URL matches the pattern.',
                    default=False)
parser.add_argument('--exclude', '-E',
                    help='Excludes resources whose URL matches the pattern.',
                    default=False)
parser.add_argument('--file', '-F',
                    help='Start to exploit with existing scan results',
                    default=False)
parser.add_argument('--lhost', '-L', required=True,
                    help='Set the local host for exploit')
args = parser.parse_args()
save_name = util.escapeurl(args.url)

argsdict = {
    "url" : args.url,
    "save" : save_name,
    "cookie" : args.cookie,
    "include" : args.include,
    "exclude" : args.exclude,
    "file" : args.file,
    "lhost" : args.lhost
}

print(framworkascii)
# print(argsdict)

if not argsdict["file"]:
    scan = Scan.scanner(argsdict)
    argsdict["file"] = scan.scan()
data = Data_processing.data_processing(argsdict["file"])
exploit = Plan.Attacker(argsdict)
exploit.start()

