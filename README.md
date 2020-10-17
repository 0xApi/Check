# VirusTotal
# Name
check.py
# Description
check.py is a python script that takes IP OR Domain OR URL OR Hash, submit it to virustotal.com for analysis using their API and returns the result as either Malicious or Clean. A single detection qualifies for being marked as malicious.
# USAGE
It takes three command-line arguments after script name as follows:<br/>
  1- The script name 'check.py'<br/>
  2- Your API**key**<br/>
  3- The type of the item you want to search for, which will be either: **url** or **hash** or **domain** or **ip-address**<br/>
  4- The url / hash / domain / ip you want to check<br/>
So for exampl, a correct usage will look like:<br/>
  ```python
  check.py oerth0KEY_Exapmle43roi url wwwdotexampledotcom
  or
  check.py oerth0KEY_Exapmle43roi ip-address 255:255:255:255
  or
  check.py oerth0KEY_Exapmle43roi hash dlgh034tj00000HASH_VALUE000dljgkhjdfgkj34
  or
  check.py oerth0KEY_Exapmle43roi domain domain_name
  ```
# OUTPUT
The ouput will be either:<br/>
  1- Clean: for clean items<br/>
  2- Malicious: for malicious items<br/>
  3- The item you searched for was not present in VirusTotal's dataset.<br/>
  4- Connection error.<br/>
  5- Usage message for input error.<br/>
  6- Forbidden. You don't have enough privileges to make the request. If key is wrong.<br/>
  7- Bad request. This can be caused by missing arguments or arguments with wrong values.<br/>
  8- Request rate limit exceeded, Please wait!<br/>
  9- Responce code error!
