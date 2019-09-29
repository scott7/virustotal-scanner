from vt import *
import argparse

def get_options():
  parser = argparse.ArgumentParser()
  parser.add_argument("-a", "--api-key", dest="api_key",
                          help="VirusTotal API key")
  parser.add_argument("-f", "--file", dest="file",
                          help="file path to query and upload")
  parser.add_argument("-r", "--resource", dest="resource",
                          help="hash/scan id to search for")
  
  
  return parser.parse_args()

def init_scan():
  arg = get_options()
  
  if not arg.api_key:
    print("Please provide api key with '-a' argument")
  api = arg.api_key
  
  if arg.file:
    scanner = Scan(api,arg.file)
    scanner.scan_file(verbose_flag=1)
  elif arg.resource:
    scanner = Scan(api)
    scanner.scan_report(arg.resource,verbose_flag=1)
  else:
    print("No option specified.")
  
  
if __name__ == "__main__":
  init_scan()
