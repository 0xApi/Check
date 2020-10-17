from sys import argv, exit
import requests


def main():
    # check command line arguments
    if len(argv) != 4:
        print('Usage: check.py followed by APIkey then item type then its value')
        exit(1)
    if (argv[2] != 'url') and (argv[2] != 'domain') and (argv[2] != 'hash') and (argv[2] != 'ip-address'):
        print('Usage: Third argument must be either: url/domain/hash/ip-address')
        exit(1)
    # define url and params for url
    if argv[2] == 'url':
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': argv[1], 'resource': argv[3]}
        analyzeurh(url, params)
    # define url and params for domain
    if argv[2] == 'domain':
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey': argv[1], 'domain': argv[3]}
        analyzeipd(url, params)
    # define url and params for ip address
    if argv[2] == 'ip-address':
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': argv[1], 'ip': argv[3]}
        analyzeipd(url, params)
    # define url and params for hash
    if argv[2] == 'hash':
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': argv[1], 'resource': argv[3]}
        analyzeurh(url, params)


# define function to analyze url or hash
def analyzeurh(url, params):
    # requesting response
    response = requests.get(url, params=params)
    status_code = response.status_code
    # analyzing response
    if status_code == 200:
        result = response.json()
        response_code = int(result.get('response_code'))
        if response_code == 1:
            if result.get('positives') == None:
                print('Clean')
                exit(0)
            else:
                positives = int(result.get('positives'))
                if positives == 0:
                    print('Clean')
                    exit(0)
                else:
                    print('Malicious')
                    exit(0)
        elif response_code == 0:
            print("The item you searched for was not present in VirusTotal's dataset")
            exit(0)
        elif response_code == -2:
            print('The requested item is still queued for analysis.')
            exit(0)
        else:
            print('Responce code error!')
            exit(1)
    elif status_code == 204:
        print('Request rate limit exceeded, Please wait!.')
        exit(1)
    elif status_code == 400:
        print('Bad request. This can be caused by missing arguments or arguments with wrong values.')
        exit(1)
    elif status_code == 403:
        print("Forbidden. You don't have enough privileges to make the request.")
        exit(1)
    else:
        print('Connection error!')
        exit(1)


# define function to analyze ip or domain
def analyzeipd(url, params):
    # requesting response
    response = requests.get(url, params=params)
    status_code = response.status_code
    # analyzing response
    if status_code == 200:
        result = response.json()
        response_code = int(result.get('response_code'))
        if response_code == 1:
            positive = []
            for item in result['detected_urls']:
                positive.append(item.get('positives'))
            positives = max(positive) if positive else 0
            if positives == 0:
                print('Clean')
                exit(0)
            else:
                print('Malicious')
                exit(0)
        elif response_code == 0:
            print("The item you searched for was not present in VirusTotal's dataset")
            exit(0)
        elif response_code == -2:
            print('The requested item is still queued for analysis.')
            exit(0)
        else:
            print('Response code error!')
            exit(1)
    elif status_code == 204:
        print('Request rate limit exceeded, Please wait!.')
        exit(1)
    elif status_code == 400:
        print('Bad request. This can be caused by missing arguments or arguments with wrong values.')
        exit(1)
    elif status_code == 403:
        print("Forbidden. You don't have enough privileges to make the request.")
        exit(1)
    else:
        print('Connection error!')
        exit(1)


main()
