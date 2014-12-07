virustotal-scanner
==================

Python module to interact with the VirusTotal Public API
Perform functions such as scan a file, query a report, and display a report.
More information on the VirusTotal API can be found here: https://www.virustotal.com/

`vt_scanner.py` is a CLI script using the `vt.py` module that can be called directly.
`vt.py` can be used as a library in another python script.

pre-requisites
=====

VirusTotal API key (create an account/sign on to virustotal to get a free API key)

json module

hashlib module

urllib/urllib2 modules

usage - vt_scanner.py
=====

`vt_scanner.py` is wrapper for the vt python module.

Scan a file and display results (if file exists in VT database it will not be resubmitted):

<pre>vt_scanner.py -a API KEY -f /path/to/file</pre> 

Query report and display results (provide file hash or scan id):

<pre>vt_scanner.py -a API KEY -r d74b1df3ab16b36d48850f5d57b346b0</pre> 

SAMPLE OUTPUT:

<pre>
resource to search: dcf28020aa39f5dfec9dffad3208207be4bf15fff20a400b7e7eac0c445e8133

Scan Date 2014-12-03 21:01:19
sha1: 32b5c17c747d96a23004c44684f15fcd43b3c4e8 
md5: e3dd6f7a59a88fac1ede022b44119f56
Positive results: 2
Total Results: 55
Detection rate: 4%

Vendor: CMC 
 Result: Packed.Win32.Zcrypt.3!O        Version: 1.1.0.977    Update: 20141203 


Vendor: TotalDefense 
 Result: Win32/Inject.C!generic        Version: 37.0.11312    Update: 20141203 

The following vendors did not flag this as malicious: 
 Bkav -- MicroWorld-eScan -- nProtect -- CAT-QuickHeal -- ALYac -- Malwarebytes -- VIPRE -- SUPERAntiSpyware -- K7AntiVirus -- K7GW -- TheHacker -- Agnitum -- Cyren -- Symantec -- Norman -- TrendMicro-HouseCall -- Avast -- ClamAV -- Kaspersky -- BitDefender -- NANO-Antivirus -- AegisLab -- Tencent -- Ad-Aware -- Comodo -- F-Secure -- DrWeb -- Zillya -- TrendMicro -- McAfee-GW-Edition -- Sophos -- F-Prot -- Jiangmin -- Avira -- Antiy-AVL -- Kingsoft -- Microsoft -- ViRobot -- AhnLab-V3 -- GData -- ByteHero -- McAfee -- AVware -- VBA32 -- Baidu-International -- Zoner -- ESET-NOD32 -- Rising -- Ikarus -- Fortinet -- AVG -- Panda -- Qihoo-360
</pre>

usage - vt.py module
=====

VirusTotal class - does most of the work to interact with VirusTotal API.

Scan class - is a wrapper for the VirusTotal class to perform scanning and file searching functions.

clone repo and `from vt import *` to use in another script.

<pre>
#upload/scan file
  scanner = Scan(api,path)
  scanner.scan_file(verbose_flag=1)

#check report based on file hash or scanid
  scanner2 = Scan(api)
  scanner2.scan_report(resource,verbose_flag=1)
</pre>

Note VirusTotal class uses postfile.py snippet from http://code.activestate.com/recipes/146306/


improvements planned
=====

Add support batch processing

Add support for url scanning
