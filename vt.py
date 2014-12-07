import json
import urllib
import urllib2
import hashlib
import postfile
import time
import sys

########################################################################## 

#global var error codes used in three classes below
IS_BATCH_ERROR = 2
INVALID_TYPE_ERROR = 3
BAD_RESPONSE_ERROR = 4
STAT_FAILED = 5
INVALID_RESULTS_ERROR = 6

########################
#   fileinfo class     #
#                      #
########################
class fileinfo():
  """
  fileinfo class contains static methods to return hash values to 
  Scan and VirusTotal classes below
  """
  #md5hash - reurn md5 hash of file 
  @staticmethod
  def md5hash(path):
    block_size = 128
    f = open(path, "rb")
    md5 = hashlib.md5()
    while True:
      data = f.read(block_size)
      if not data:
        break
      md5.update(data)
    f.close()
    return md5.hexdigest()
        

########################
#   Virus Total Class  #
#                      #
########################
class VirusTotal(object):

  def __init__(self, api_key, resource="NA", path="NA"):
    """ 
    VirusTotal object which interacts directly with the VirusTotal public
    API
    Should not be used directly:
    Use Scan object below to work with files/urls/reports
    
    attributes: 
      resource: can be scan_id/hash (optional)
      path: full path to single file (optional)
      api_key (required)
    """
    self.resource = resource
    self.path = path
    self.api_key = api_key
   
  #######################################################################
  #  _submit_resource                                                   #
  #  internal method to submit values to VT to query info               #
  #  takes method argument which can be either 'report' or 'rescan'     #
  #######################################################################
  def _submit_resource(self, method):
    url = "https://www.virustotal.com/vtapi/v2/file/" + method
    parameters = {"resource": self.resource,
                  "apikey": self.api_key}
    
    #send request
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    if(response.getcode() != 200):
      return BAD_RESPONSE_ERROR
    json_out = response.read()
    
    return json.loads(json_out)
  
  #######################################################################
  #  _is_batch                                                          #
  #  internal method to determine if json output from VT                #
  #    was a batch scan or single                                       #
  #  requires json output from vt as argument                           #
  #######################################################################
  @staticmethod
  def _isbatch(json_output):
    if(type(json_output) == list):
      return True
    else:
      return False
  
  #######################################################################
  #  _is_notbatch                                                       #
  #  internal method to determine if json output from VT                #
  #    was a batch scan or single                                       #
  #  requires json output from vt as argument                           #
  #######################################################################
  @staticmethod
  def _isnotbatch(json_output):
    if(type(json_output) == dict):
      return True
    else:
      return False
  
  #######################################################################
  #  has_file                                                           #
  #  method to determine if VirusTotal has file in it's DB              #
  #                                                                     #
  #  Note: this will send a web request to virustotal everytime         # 
  #    function is called                                               #
  #######################################################################
  def has_file(self):
    method = "report"
    json_out = self._submit_resource(method)
    #batch - list
    #reg - dict
    if(self._isbatch(json_out)):
      return IS_BATCH_ERROR
    if(self._isnotbatch(json_out)):
      if(json_out["response_code"]) == 1:
        return True
      else:
        return False
    else:
       return INVALID_TYPE_ERROR
      
  #######################################################################
  #  submit_file                                                        #
  #  method to submit file to VT for analysis.                          #
  #   This will return scan_id immediatley but will take several minutes#
  #   to analyze fully - see query_status()                             #
  #                                                                     #
  #  Returns dictionary with status code, message, and scan_id          #   
  #                                                                     #
  #  Note: this will send a web request to virustotal everytime         # 
  #    function is called                                               #
  #######################################################################
  def submit_file(self):
    host = "www.virustotal.com"
    selector = "http://www.virustotal.com/vtapi/v2/file/scan"
    fields = [("apikey", self.api_key)]
    file_to_send = open(self.path, "rb").read()
    files = [("file", self.path, file_to_send)]
    json_out = postfile.post_multipart(host, selector, fields, files)
    json_out = json.loads(json_out)
    
    response = json_out["response_code"]
    msg = json_out["verbose_msg"]
    if(response != 1):
      return_json = {"code":0,"val":msg}
      return return_json

    elif(response == 1):
      return_json = {"code":1,"val":msg,"scan_id":json_out["scan_id"]}
      return return_json

  #######################################################################
  #  rescan_file                                                        #
  #  method to rescan file already in DB using scan_id or hash          #
  #   This will return scan_id immediatley but will take several minutes#
  #   to analyze fully - see query_status()                             #
  #                                                                     #
  #  Returns scan_id                                                    #   
  #                                                                     #
  #  Note: this will send a web request to virustotal everytime         # 
  #    function is called                                               #
  #######################################################################
  def rescan_file(self):
    method = "rescan"
    json_output = self._submit_resource(method)
    if(json_output["response_code"]==1):
      return json_output["scan_id"]
    else:
      return BAD_RESPONSE_ERROR
  
  #######################################################################
  #  query_status                                                       #
  #  check status of scan already submiited using scan_id/hash          #
  #                                                                     #
  #  Returns 1 if successful                                            #   
  #                                                                     #
  #  Note: this will send a web request to virustotal everytime         # 
  #    function is called and can take several minutes to complete      #
  #######################################################################
  def query_status(self):
    found = 0
    count = 0
    method = "report"
    while (found == 0):
      count += 1
      time.sleep(60)
      json_out = self._submit_resource(method)
      if(count > 6):
        return STAT_FAILED
      if((json_out["response_code"] == 1 and 
        json_out["verbose_msg"] != "Scan request successfully queued, come back later for the report")):
          found = 1
    return 1
    
  #######################################################################
  #  get_report                                                         #
  #  method to get report from hash/scan_id                             #
  #                                                                     #
  #  Returns raw json report                                            #   
  #                                                                     #
  #  Note: this will send a web request to virustotal everytime         # 
  #    function is called                                               #
  #######################################################################
  def get_report(self):
    method = "report"
    report_json = self._submit_resource(method)
    if(report_json == BAD_RESPONSE_ERROR):
      print("failed at get_report() - bad response from VT")
    elif not report_json:
      return INVALID_RESULTS_ERROR
    else:
      return report_json
  
  #######################################################################
  #  gather_report_details                                              #
  #  internal method to get positive vt result details                  #
  #   such as vendor names,malware names, and dates                     #
  #                                                                     #
  #  Returns dictonary of values if successful                          #   
  #  Returns 1 if no vendors flagged the resource                       #
  #                                                                     # 
  #######################################################################
  @staticmethod 
  def _gather_report_details(json):
    if(json['response_code'] == 1):
      scans = json['scans']
      
      failed_flag = 0
      detect_flag = 0
      vendors = []
      detect_list = []
      not_detect_list = []
      output = {}
      
      for key in scans:
        vendors.append(key)
      for val in vendors:
        detect = scans[val]["detected"]
        if(detect):
          detect_flag = 1
          detect_list.append(val)
        else:
          failed_flag = 1
          not_detect_list.append(val)
          
      if(detect_flag == 0):
        return 1
      elif(failed_flag):
        for val in detect_list:
          output[val] = {"version":scans[val]['version'], "result":scans[val]['result'], "update":scans[val]['update']}
        output['detect_list'] = detect_list
        output['failed'] = 1
        output['failedlist_key'] = {"failed_list":not_detect_list}
      else:
        for val in detect_list:
          output[val] = {"version":scans[val]['version'], "result":scans[val]['result'], "update":scans[val]['update']}
        output['failed'] = 0
      return output
    
    else:
      return 0
  
  #######################################################################
  #  make_awesome_report                                                #
  #  Print full scan report (uses _gather_report_details)               #
  #                                                                     #
  #######################################################################
  def make_awesome_report(self):
    raw_json = self.get_report()
    
    if(raw_json == INVALID_RESULTS_ERROR): #this will happen if invalid hash is submitted
      print "Resouce not found - invalid hash probably"
    elif(raw_json['response_code'] == 1):
      #display status information
      print("Scan Date " + str(raw_json['scan_date']))
      print("sha1: " + str(raw_json['sha1']) + " \n" + "md5: " + str(raw_json['md5']))
      ratio = float(raw_json['positives'])/float(raw_json['total']) * float(100)
      print("Positive results: " + repr(raw_json['positives']) + '\n' + "Total Results: " + repr(raw_json['total'])) 
      print("Detection rate: {0:.0f}%".format(ratio))
      
      #print detailed report
      output = self._gather_report_details(raw_json)
      if(output == 1):
        print "No vendors flagged this resource as malicious"
      elif(output != 0):
        vendor = output['detect_list']
        for val in vendor:
          print "\nVendor: %s \n Result: %s        Version: %s    Update: %s \n" % (val, str(output[val]['result']), str(output[val]['version']),str(output[val]['update']))
        if(output['failed']):    
          print "The following vendors did not flag this as malicious: \n %s" % (str(" -- ".join(output['failedlist_key']['failed_list'])))
      else:
        print "ERROR: Not found." 
      
    #Resource not found in DB 
    elif(raw_json['response_code'] == 0):
      print " Resource not found in Virus Total database "
      print " resource: " + raw_json['resource']
      
      
########################
#   Scan Class         #
#                      #
########################    
class Scan(object):
  
  def __init__(self,api_key,path="NA"):
      """ 
      This object is a wrapper for the 'VirusTotal' object which
      defines most of the logic regarding VT scanning
      
      This object can be called directly to invoke scanning functions.
      available methods:
        object.scan_file(api_key,path)
        object.get_report(api_key,hash)
      
      attributes:
        path to single file (optional)
        api key (required)
      """
      self.path = path
      self.api_key = api_key
      
      
  #######################################################################
  #  _get_filehash                                                      #
  #  method to get file hash                                            #
  #                                                                     #
  #  Returns md5hash                                                    #   
  #                                                                     #
  #######################################################################
  def _get_filehash(self):
    md5hash = fileinfo.md5hash(self.path)
    return md5hash
  
  #######################################################################
  #  scan_file  - call this directly                                    #
  #  method to submit file for analysis - set_verbose flag to 1         #
  #  for more info printed, default is 0                                #
  #                                                                     #
  #  If file exists in DB - file will not be submitted or rescanned     #
  #                                                                     #
  #  Prints report                                                      #   
  #                                                                     #
  #######################################################################
  def scan_file(self,verbose_flag=0):
    md5hash = self._get_filehash()
    if(verbose_flag): print("md5 hash of file: " +  md5hash)
    vt = VirusTotal(self.api_key,md5hash,self.path)
    has_file = vt.has_file()
    if(has_file == IS_BATCH_ERROR or has_file == INVALID_TYPE_ERROR):
      print("scan_file() failed at has_file()")
    elif(has_file == True):
      if(verbose_flag): print("VT already has file -- querying report:")
      
      vt.make_awesome_report()
    else:
      if(verbose_flag): print("submitting file - this could take several minutes")
      return_dict = vt.submit_file()
      if(return_dict['code']== 1):
        scan_id = return_dict['scan_id']
        if(verbose_flag): print("scan_id: " + scan_id)
        if(vt.query_status() != STAT_FAILED):
          
          vt.make_awesome_report()
        else:
          print("scan_file() failed because we were unable to query the status of the file sent (note that file was sent)")
      else:
        print("scan_file() failed because we were unable to send file -- " + return_dict['msg'])
          
  #######################################################################
  #  scan_report  - call this directly                                  #
  #  method to submit hash to get report- set_verbose flag to 1         #
  #  for more info printed, default is 0                                #
  #                                                                     #
  #  If hash does not exist in DB - exit with error                     #
  #                                                                     #
  #  Prints report                                                      #   
  #                                                                     #
  #######################################################################
  def scan_report(self,hash,verbose_flag=0):
    if(verbose_flag): print("resource to search: " +  hash + '\n')
    vt = VirusTotal(self.api_key,hash)
    vt.make_awesome_report()
    
##########################################################################      
   

def example():
  api = "<API kEY>"
  
  resource = "d74b1df3ab16b36d48850f5d57b346b0" #dexter malware hash
  path = "testfile.txt"
  
  #upload/scan file
  scanner = Scan(api,path)
  scanner.scan_file(verbose_flag=1)
  
  #check report based on file hash or scanid
  scanner2 = Scan(api)
  scanner2.scan_report(resource,verbose_flag=1)
  
  
def main():
  print "This script contains the class implementations to interact with VirusTotal - do not call directly"
if __name__ == "__main__":
  main()
