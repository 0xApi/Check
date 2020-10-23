# What's Check? ![Python 3](https://img.shields.io/badge/Python-3-brightgreen.svg)
check.py is a python script that takes IP OR Domain OR URL OR Hash, submit it to virustotal.com for analysis using their API and returns the result as either Malicious or Clean. A single detection qualifies for being marked as malicious.
# Requirements
  1- Get your 'API key' by registering at https://www.virustotal.com/ <br/>
  2- Install requests<br/>
  ```bash
  pip install requests
  ```
  3- Download check.py script using the following command:
  ```bash
  git clone github.com/m074mm4d/Check
  ```
# USAGE
It takes three command-line arguments after script name as follows:<br/>
  **1**- Your **API key**<br/>
  **2**- Type the word **'url'** if you are going to check a **url**,<br/>
    or type the word **'hash'** if you are going to check a **hash**,<br/>
    or type the word **'domain'** if you are going to check a **domain**,<br/>
    or type the word **'ip-address'** if you are going to check an **ip-address**<br/>
  **3**- The url / hash / domain / ip you want to check<br/>
So for exampl, a correct usage will look like:<br/>
  ```bash
  python3 check.py [your_api_key] url google.com
  or
  python3 check.py [your_api_key] ip-address 255:255:255:255
  or
  python3 check.py [your_api_key] hash 61D071CE81241301DB7F7231AEDE729EEBA335D438494CE80D7D28E67A49B005
  or
  python3 check.py [your_api_key] domain googler.cloud
  ```
# OUTPUT
The ouput will be either:<br/>
  1- Clean<br/>
  2- Malicious<br/>
  3- The item you searched for was not present in VirusTotal's dataset.<br/>
  4- Connection error.<br/>
  5- Usage message for input errors.<br/>
  6- Forbidden. You don't have enough privileges to make the request.<br/>
      If the key is wrong.<br/>
  7- Bad request. This can be caused by missing arguments or arguments with wrong values.<br/>
  8- Request rate limit exceeded, Please wait!<br/>
      The Public API is limited to 4 requests per minute.<br/>
  9- Responce code error!
  10- The requested item is still queued for analysis.
