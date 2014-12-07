virustotal-scanner
==================

Python module to interact with the VirusTotal Public API
Perform functions such as scan a file, query a report, and display a report.
More information on the VirusTotal API can be found here: https://www.virustotal.com/

`vt_scanner.py` is a CLI script using the vt.py module that can be called directly.
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

<pre>vt_scanner.py -a <API KEY> -f /path/to/file</pre> 

Query report and display results (provide file hash or scan id):

<pre>vt_scanner.py -a <API KEY> -r d74b1df3ab16b36d48850f5d57b346b0</pre> 

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

improvements planned
=====

Add support batch processing
Add support for url scanning
