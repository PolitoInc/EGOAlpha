import fuzzywuzzy
from itertools import repeat
import multiprocessing as mp
from multiprocessing import Pool
from multiprocessing import Process, Value, Array
import pathlib
import dask
import ipaddress
import os 
import json
import requests 
import urllib.parse
import random
import concurrent.futures as thread
import urllib3
import getopt
import sys
import re
import tldextract
import subprocess
import json
import jc
import dask
import ast
import traceback
import dask.array as dd
from nested_lookup import nested_delete
import datetime
import uuid
# custom imports

import EgoSettings

#from dask.distributed import Client, progress
import numpy as np
import time
import hashlib
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

print(os.name)

r ='\033[1;31m'
g ='\033[1;32m'
y ='\033[1;33m'
b ='\033[1;34m'
r_='\033[0;31m'
g_='\033[0;32m'
y_='\033[0;33m'
b_='\033[0;34m'
e ='\033[0m'

global services
services = {
        'AWS/S3'          : {'error':r'The specified bucket does not exist'},
        'BitBucket'       : {'error':r'Repository not found'},
        'Github'          : {'error':r'There isn\'t a Github Pages site here\.'},
        'Shopify'         : {'error':r'Sorry\, this shop is currently unavailable\.'},
        'Fastly'          : {'error':r'Fastly error\: unknown domain\:'},

        'FeedPress'       : {'error':r'The feed has not been found\.'},
        'Ghost'           : {'error':r'The thing you were looking for is no longer here\, or never was'},
        'Heroku'          : {'error':r'no-such-app.html|<title>no such app</title>|herokucdn.com/error-pages/no-such-app.html'},
        'Pantheon'        : {'error':r'The gods are wise, but do not know of the site which you seek.'},
        'Tumbler'         : {'error':r'Whatever you were looking for doesn\'t currently exist at this address.'},
        'Wordpress'       : {'error':r'Do you want to register'},

        'TeamWork'        : {'error':r'Oops - We didn\'t find your site.'},
        'Helpjuice'       : {'error':r'We could not find what you\'re looking for.'},
        'Helpscout'       : {'error':r'No settings were found for this company:'},
        'Cargo'           : {'error':r'<title>404 &mdash; File not found</title>'},
        'StatusPage'      : {'error':r'You are being <a href=\"https://www.statuspage.io\">redirected'},
        'Uservoice'       : {'error':r'This UserVoice subdomain is currently available!'},
        'Surge'           : {'error':r'project not found'},
        'Intercom'        : {'error':r'This page is reserved for artistic dogs\.|Uh oh\. That page doesn\'t exist</h1>'},

        'Webflow'         : {'error':r'<p class=\"description\">The page you are looking for doesn\'t exist or has been moved.</p>'},
        'Kajabi'          : {'error':r'<h1>The page you were looking for doesn\'t exist.</h1>'},
        'Thinkific'       : {'error':r'You may have mistyped the address or the page may have moved.'},
        'Tave'            : {'error':r'<h1>Error 404: Page Not Found</h1>'},

        'Wishpond'        : {'error':r'<h1>https://www.wishpond.com/404?campaign=true'},
        'Aftership'       : {'error':r'Oops.</h2><p class=\"text-muted text-tight\">The page you\'re looking for doesn\'t exist.'},
        'Aha'             : {'error':r'There is no portal here \.\.\. sending you back to Aha!'},
        'Tictail'         : {'error':r'to target URL: <a href=\"https://tictail.com|Start selling on Tictail.'},
        'Brightcove'      : {'error':r'<p class=\"bc-gallery-error-code\">Error Code: 404</p>'},
        'Bigcartel'       : {'error':r'<h1>Oops! We couldn&#8217;t find that page.</h1>'},
        'ActiveCampaign'  : {'error':r'alt=\"LIGHTTPD - fly light.\"'},

        'Campaignmonitor' : {'error':r'Double check the URL or <a href=\"mailto:help@createsend.com'},
        'Acquia'          : {'error':r'The site you are looking for could not be found.|If you are an Acquia Cloud customer and expect to see your site at this address'},
        'Proposify'       : {'error':r'If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz'},
        'Simplebooklet'   : {'error':r'We can\'t find this <a href=\"https://simplebooklet.com'},
        'GetResponse'     : {'error':r'With GetResponse Landing Pages, lead generation has never been easier'},
        'Vend'            : {'error':r'Looks like you\'ve traveled too far into cyberspace.'},
        'Jetbrains'       : {'error':r'is not a registered InCloud YouTrack.'},

        'Smartling'       : {'error':r'Domain is not configured'},
        'Pingdom'         : {'error':r'pingdom'},
        'Tilda'           : {'error':r'Domain has been assigned'},
        'Surveygizmo'     : {'error':r'data-html-name'},
        'Mashery'         : {'error':r'Unrecognized domain <strong>'},
}

headers = {"Content-type": "application/json", "Accept": "application/json"}

def validIPAddress(IP: str) -> str:
    try:
        if type(ipaddress.ip_address(IP)) is ipaddress.IPv4Address:
            return True
        else:
            return False
    except ValueError:
        return False

def validIPNetWorks(IP: str) -> str:
    try:
        if type(ipaddress.ip_network(IP)) is ipaddress.IPv4Network:
            return True
        else:
            return False
    except ValueError:
        return False

def DomainName_CREATOR(domain):
    D_bool= bool(domain)
    if validIPNetWorks(domain) == True:
        if domain is None:
            set = {"Ipv": ["None"]}
        else:
            print([str(ip) for ip in ipaddress.IPv4Network(domain)])
            set = {"Ipv": [str(ip) for ip in ipaddress.IPv4Network(domain)]}
            return set
    elif validIPAddress(domain) == True:
        if domain is None:
            set = {"Ipv": ["None"]}
        else:
            set = {"Ipv": [domain]}
            return set
        
    elif validIPAddress(domain) == False:
        if domain is None:
            pass
        else:
            tldExtracted= tldextract.extract(domain)
            SUFFIX= tldExtracted.suffix
            DOMAIN= tldExtracted.domain
            SUBDOMAIN= tldExtracted.subdomain
            if bool(SUBDOMAIN) == False:
                domainname= f'{DOMAIN}.{SUFFIX}'
                set= {"domainname": domainname, "fulldomain": domainname, "search_domain": f".{DOMAIN}.", "SUBDOMAIN": None, "DOMAIN": DOMAIN, "SUFFIX": SUFFIX}
                return set
            elif SUBDOMAIN == '*':
                domainname= f'{DOMAIN}.{SUFFIX}'
                set= {"domainname": domainname, "fulldomain": domainname, "search_domain": f".{DOMAIN}.", "SUBDOMAIN": None, "DOMAIN": DOMAIN, "SUFFIX": SUFFIX}
                return set
            else:
                domainname= f'{DOMAIN}.{SUFFIX}'
                FullDomainName= f'{SUBDOMAIN}.{DOMAIN}.{SUFFIX}'
                set= {"domainname": domainname, "fulldomain": FullDomainName, "search_domain": f".{DOMAIN}.", "SUBDOMAIN": SUBDOMAIN, "DOMAIN": DOMAIN, "SUFFIX": SUFFIX}
                return set
    else:
        return False

def split(list_a, chunk_size):
    if None in list_a:
        pass
    else:
        results= []
        for i in range(0, len(list_a), chunk_size):
            chunk= list_a[i:i + chunk_size]

            random.shuffle(chunk)
            results.append(chunk)
        return results 

def divide_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]

def checkurl(url):
    o = urllib.parse.urlsplit(url)
    if o.scheme  not  in ['http','https','']:
        warn('Scheme "%s" not supported!'%o.scheme,1)
    if o.netloc == '':
        return 'http://' + o.path
    elif o.netloc:
        return o.scheme + '://' + o.netloc 
    else:
        return 'http://' + o.netloc 

def warn(string):
	print('{0}[ ! ]{1} {2}'.format(r,e,string))

def find(content,status):
    store_out = []
    for service in services:
        for values in services[service].items():
            if re.findall(str(values[1]),str(content),re.I) and int(status) in range(201,200,599):
                service= dict.fromkeys(['service'],service)
                values= dict.fromkeys(['values'],values[1])
                service.update(values)
                store_out.append(service)
            else:
                pass
    return store_out

def Subdomain_attack(domain):
    meow= False
    if meow is False:
        pass
    else:
        print('Subdomain_attack')
        url= checkurl(domain)
        headers= {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'}
        try:
            s = requests.Session()
            request = s.get(
                url,
                headers= headers,
                allow_redirects= True,
                timeout= 5,
                verify= False
                )
            status= request.status_code
            response= request.content
            subdomain_find= find(response,status)
            if bool(subdomain_find) == True:
                timestamp= datetime.datetime.now()
                split_time= timestamp.split('.', 1)[0]
                results= dict({"date": f"{split_time}", "name": f"{subdomain_find}", "method": "http", "severity": "high", "vulnerable": f"{domain}"})
                return results
            else:
                print(f'bool failure {bool(subdomain_find)} {subdomain_find}')
                pass
        except Exception as err:
            print(err)
            pass

def replace_strings(string):
    string1= string.replace("[", "")
    string2= string1.replace("]", "")
    return string2

def list_to_dict(rlist):
    try:
        reresults = dict(map(lambda s : s.split(":"), rlist))
        return
    except Exception as E:
        print(E)
        pass
     

def brain_word_comprehension(data, record_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=None):
    #print(f'brain_word_comprehension {data} type of data {type(data)}')
    # reads None value from memory
    print('brain_word_comprehension')
    if data == 'None':
        pass
    else:
        STORED= set()
        DIC= {}
        datatype= type(data)
        print('loads2')
        itype= type(data)
        print(f'z newlinesplit', data, f'type {itype} bool value {bool(data)}')
        i = data
        if itype == None:
            pass
        elif "template" in i:
            print('hereerererereererererereer')
            
            del i['timestamp']
            print('hereerererereererererereer')
            if 'curl-command' in i:
                curl_command = i.get('curl-command', '')
                i = (nested_delete(i, 'curl-command'))
                
                print('i9iiiiiiiiiii', i)
                md5_hash = hashlib.md5(json.dumps(i, sort_keys=True).encode('utf-8')).hexdigest()
                curl_command = dict.fromkeys(['curl_command'], curl_command)
                i.update(curl_command)
                md5 = dict.fromkeys(['md5'], md5_hash)
                print(f'failed here2     {DIC}      {md5}')
                DIC.update(md5)
                template_id = dict.fromkeys(['record_id'], record_id)
                print(f'failed here3        {DIC}')
                DIC.update(template_id)
                print(f'failed here14       {DIC}')
                DIC.update(i)
                print(f'failed here15       {DIC}')
                DIC_OUT = []
                for k in list(DIC):
                    if '-' in k:
                        #print(F' - {k}')
                        Removed_underscore = k.replace('-',"_")
                        DIC[Removed_underscore] = DIC.pop(k)
                        #print(DIC)
                        
                        if k == 'classification':
                            port_i= i.get('classification',{})
                            for k in port_i:
                                Removed_underscore = k.replace('-',"_")
                                DIC[Removed_underscore] = DIC.pop(k)
                                #print(DIC)
                                DIC_OUT.append(DIC)
                        else:
                            DIC_OUT.append(DIC)
                print(DIC)
                DIC = DIC_OUT[0]
                print(f' failed here {DIC}')
                certificateurlPost= f"{HostAddress}:{Port}/api/Templates/create/"
                recs= json.dumps(DIC)
                print('recs  ', recs)
                if auth_token_json:
                    headers.update(auth_token_json)
                headers.update(auth_token_json)
                postRecords = requests.post(certificateurlPost, data=(recs), headers=headers, verify=False)
                print(json.loads(postRecords.content))
            else:
                md5_hash = hashlib.md5(json.dumps(i, sort_keys=True).encode('utf-8')).hexdigest()
                md5 = dict.fromkeys(['md5'], md5_hash)
                print(f'failed here2     {DIC}      {md5}')
                DIC.update(md5)
                template_id = dict.fromkeys(['record_id'], record_id)
                print(f'failed here3        {DIC}')
                DIC.update(template_id)
                print(f'failed here14       {DIC}')
                DIC.update(i)
                print(f'failed here15       {DIC}')
                DIC_OUT = []
                for k in list(DIC):
                    if '-' in k:
                        #print(F' - {k}')
                        Removed_underscore = k.replace('-',"_")
                        DIC[Removed_underscore] = DIC.pop(k)
                        #print(DIC)
                        
                        if k == 'classification':
                            port_i= i.get('classification',{})
                            for k in port_i:
                                Removed_underscore = k.replace('-',"_")
                                DIC[Removed_underscore] = DIC.pop(k)
                                #print(DIC)
                                DIC_OUT.append(DIC)
                        else:
                            DIC_OUT.append(DIC)
                            
                DIC = DIC_OUT[0]
                print(f' failed here {DIC}')
                certificateurlPost= f"{HostAddress}:{Port}/api/Templates/create/"
                recs= json.dumps(DIC)
                print('recs  ',certificateurlPost,  recs)
                if auth_token_json:
                    headers.update(auth_token_json)
                headers.update(auth_token_json)
                postRecords = requests.post(certificateurlPost, data=(recs), headers=headers, verify=False)
                print(json.loads(postRecords.content))
        else:
            itype= type(i)
            print('i not template', i, f'type {itype}')
            #words = replace_strings(i)
            wordsList = re.split(' ', i)
            itype= type(wordsList)
            print('i not template wordsList', wordsList, f'type {itype}')
            if len(wordsList) == 6:
                print('hereerererereererererereer')
                print(f'length is 6')
                DIC= {}
                date_nuclei= f'{wordsList[0]} {wordsList[1]}'
                date= dict.fromkeys(['date'], date_nuclei)
                name_nuclei= wordsList[2]
                name= dict.fromkeys(['name'], name_nuclei)
                method_nuclei= wordsList[3]
                method= dict.fromkeys(['method'], method_nuclei)
                severity_nuclei= wordsList[4]
                severity= dict.fromkeys(['severity'], severity_nuclei)
                vulnerable_nuclei= wordsList[5]
                vulnerable= dict.fromkeys(['vulnerable'], vulnerable_nuclei)
                DIC.update(date)
                print(f'DIC date  {DIC}')
                DIC.update(name)
                print(f'DIC name  {DIC}')
                DIC.update(method)
                print(f'DIC method  {DIC}')
                DIC.update(severity)
                print(f'DIC severity  {DIC}')
                DIC.update(vulnerable)
                print(f'dic {DIC}')
                Nuclei_id = dict.fromkeys(['nuclei'], record_id)
                Nuclei_id.update(DIC) 
                certificateurlPost= f"{HostAddress}:{Port}/api/Nuclei/"
                recs= json.dumps(Nuclei_id)
                print('recs  ',certificateurlPost,  recs)
                if auth_token_json:
                    headers.update(auth_token_json)
                postRecords = requests.post(certificateurlPost, data=(recs), headers=headers, verify=False)
            elif len(wordsList) == 7:
                print('hereerererereererererereer')
                print(f'length is 7 == {len(wordsList)} {wordsList}')
                DIC= {}
                date_nuclei= f'{wordsList[0]} {wordsList[1]}'
                date= dict.fromkeys(['date'], date_nuclei)
                name_nuclei= f'{wordsList[2]} {wordsList[6]}'
                name= dict.fromkeys(['name'], name_nuclei)
                method_nuclei= wordsList[3]
                method= dict.fromkeys(['method'], method_nuclei)
                severity_nuclei= wordsList[4]
                severity= dict.fromkeys(['severity'], severity_nuclei)
                vulnerable_nuclei= wordsList[5]
                vulnerable= dict.fromkeys(['vulnerable'], vulnerable_nuclei)
                DIC.update(date)
                print(f'DIC date  {DIC}')
                DIC.update(name)
                print(f'DIC name  {DIC}')
                DIC.update(method)
                print(f'DIC method  {DIC}')
                DIC.update(severity)
                print(f'DIC severity  {DIC}')
                DIC.update(vulnerable)
                print(f'dic {DIC}')
                Nuclei_id = dict.fromkeys(['nuclei'], record_id)
                Nuclei_id.update(DIC) 
                certificateurlPost= f"{HostAddress}:{Port}/api/Nuclei/"

                recs= json.dumps(Nuclei_id)
                print('recs  ', certificateurlPost, recs)
                if auth_token_json:
                    headers.update(auth_token_json)
                postRecords = requests.post(certificateurlPost, data=(recs), headers=headers, verify=False)
            else:
                print(f'compllete fialure not 7 or 6 vlaue {len(wordsList)}   {wordsList}   {i}')
                pass
                

        return STORED  

def get_path(readyson):
    if os.name == 'posix':
        if not os.path.exists('./dump'):
            os.makedirs('./dump')
            return f"{EgoSettings.dump}/dump/{readyson}.json"
        else:
            return f"{EgoSettings.dump}/dump/{readyson}.json"
    else:
        if not os.path.exists('./dump'):
            os.makedirs('dump')
            return f"{EgoSettings.dump}/dump/{readyson}.json"
        else:
            return f"{EgoSettings.dump}/dump/{readyson}.json"

def get_url(domain_set, port):
    if any(x == '443' for x in port):
        fulldomain = domain_set['fulldomain']
        url = f"https://{fulldomain}"
    else:
        fulldomain = domain_set['fulldomain']
        url = f"http://{fulldomain}"
    return url, fulldomain

def get_nuclei_rate_limit(Global_Nuclei_CoolDown, Global_Nuclei_RateLimit):
    if Global_Nuclei_CoolDown > 0:  
        return ['-rlm', str(Global_Nuclei_CoolDown)]
    else:
        return ['-rate-limit', str(Global_Nuclei_RateLimit)]

def run_nuclei(url, severity, path, Nuclei_rate_limit):
    try:
        nuclei = subprocess.check_output([f'{EgoSettings.nuclei}', '-no-color','-vv', '-jsonl', '-silent', 
                                        '-interactions-cooldown-period', '30', 
                                        '-interactions-poll-duration', '10', 
                                        '-interactions-eviction', '30'] + Nuclei_rate_limit + ['-u', url,  
                                        '-severity', severity, '-output', path], text=True)
        return nuclei.split('\n')
    except Exception as E:
        print(E)
        return None

def process_nuclei_results(nuclei_results, record_id, HostAddress, Port, auth_token_json):
    for i in nuclei_results:
        if i:  # Check that i is not an empty string
            nuclei_result = json.loads(i)
            nuclei_brain = brain_word_comprehension(nuclei_result, record_id, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
    return True

def nuclei_func(domain, NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, ego_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, Ipv_Scan=False, auth_token_json=None):
    try:
        update_gnaw_control(domain['subDomain'], ego_id, auth_token_json)
        record_id = domain['id']
        alive = domain["alive"]
        p = domain['subDomain']
        port = domain['OpenPorts']
        domain_set = DomainName_CREATOR(p)
        url, fulldomain = get_url(domain_set, port)
        Record_NucleiScan = domain['nucleiBool']
        if Record_NucleiScan == NucleiScan:
            if Ipv_Scan == True:
                severity_scored = 'info,low,medium,high,critical,unknown'
                severity_scored_list = re.split(';|,|\*|\n', severity_scored)
                severity_list = severity.split(",")
                if any(list == severity_list for list in severity_scored_list):
                    return False
                else:
                    readyson = fulldomain.replace('.', '_')
                    path = get_path(readyson)
                    Nuclei_rate_limit = get_nuclei_rate_limit(Global_Nuclei_CoolDown, Global_Nuclei_RateLimit)
                    nuclei_results = run_nuclei(url, severity, path, Nuclei_rate_limit)
                    if nuclei_results:
                        return process_nuclei_results(nuclei_results, record_id, HostAddress, Port, auth_token_json)
                    else:
                        return False
        else:
            severity_scored = 'info,low,medium,high,critical,unknown'
            severity_scored_list = re.split(';|,|\*|\n', severity_scored)
            severity_list = severity.split(",")
            if any(list == severity_list for list in severity_scored_list):
                return False
            else:
                readyson = fulldomain.replace('.', '_')
                path = get_path(readyson)
                Nuclei_rate_limit = get_nuclei_rate_limit(Global_Nuclei_CoolDown, Global_Nuclei_RateLimit)
                nuclei_results = run_nuclei(url, severity, path, Nuclei_rate_limit)
                if nuclei_results:
                    return process_nuclei_results(nuclei_results, record_id, HostAddress, Port, auth_token_json)
                else:
                    return False
    except Exception as E:
        print('Exception')
        print(E)
        return E

def DATEREADER(created_date, LastScanned):
    current_date = datetime.datetime.now()
    when_to_scanCreate = (str(created_date) + str(datetime.timedelta(days=30)))
    when_to_scanCreateMargin = str(created_date) + str(datetime.timedelta(days=2))
    current_date = str(current_date).split(" ")
    when_to_scan = str(when_to_scanCreate).split(" ")
    LastScanned_date = (when_to_scanCreate.replace("T", " ").replace(".000Z", ""))
    created_date = (when_to_scanCreateMargin.replace("T", " ").replace(".000Z", ""))
    if LastScanned_date == created_date:
        result = True
    elif str(current_date[0]) <= str(when_to_scan[0]):
        result = True
    elif created_date >= str(when_to_scanCreateMargin[0]):
        result = True
    else:   
        result = False
    return result

def Chunky(lst, num_chunks):
    avg = len(lst) // num_chunks
    remainder = len(lst) % num_chunks
    return [lst[i * avg + min(i, remainder):(i + 1) * avg + min(i + 1, remainder)] for i in range(num_chunks)]

def get_auth_token():
    urlLogin = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/login"
    headers = {"Content-type": "application/json", "Accept": "application/json"}
    creds = {"username": EgoSettings.EgoAgentUser, "password": EgoSettings.EgoAgentPassWord}
    req = requests.post(urlLogin, data=json.dumps(creds), headers=headers, verify=False)
    rjson_auth = req.json()
    if rjson_auth:
        return {"Authorization": f"Token {rjson_auth['token']}"}
    return None

def get_request(url, auth_token_json=None):
    if auth_token_json:
        return requests.get(url, headers=auth_token_json, verify=False)
    return requests.get(url, verify=False)

def create_EGOAgent(data, auth_token_json):
    url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/EGOAgent/"
    headers = {"Content-type": "application/json", "Accept": "application/json"}
    dt = datetime.datetime.now()
    data.update({"lastConnect": dt.strftime('%Y-%m-%d')})
    egoB = dict.fromkeys(['alive'], True)    
    data.update(egoB)
    if auth_token_json:
        headers.update(auth_token_json)
    response = requests.post(url, data=json.dumps(data), headers=headers, verify=False)
    return response.json()

def update_agent_checkin(agent_id, auth_token_json):
    # Prepare the URL and headers
    url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/EGOAgent/{agent_id}/"
    headers = {"Content-type": "application/json", "Accept": "application/json"}
    if auth_token_json:
        headers.update(auth_token_json)
    # Prepare the data with the current date and time
    dt = datetime.datetime.now()
    data = {"checkin": dt.strftime('%Y-%m-%d %H:%M:%S')}
    # Send the PATCH request
    response = requests.patch(url, data=json.dumps(data), headers=headers, verify=False)
    return response.json()

def update_AgentControl(ego_id, agent_id, auth_token_json):
    # Get the current list of UUIDs in the 'egoAgent' field
    headers = {"Content-type": "application/json", "Accept": "application/json"}
    headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleeWbKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"})
    if auth_token_json:
        headers.update(auth_token_json)
    # Update the 'egoAgent' field with the new list
    url_patch = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/{ego_id}"
    data = {
        'egoAgentID': agent_id,
    }
    rjson = json.dumps(data)
    response_patch = requests.patch(url_patch, data=rjson, headers=headers, verify=False)
    return response_patch

def worker_func(records, NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, ego_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, Ipv_Scan=False, auth_token_json=None): 
    # Update GnawControl with the subDomain
    outStore = []
    for record in records:
        out = nuclei_func(record, NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, ego_id, HostAddress=HostAddress, Port=Port, Ipv_Scan=Ipv_Scan, auth_token_json=auth_token_json) 
        outStore.append(out)
    return outStore

def register_and_update_agent(auth_token_json=None):
    Url_EgoControls = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/"
    request = get_request(Url_EgoControls, auth_token_json)
    responses = request.json()
    response_store = []
    agent_response_store = []
    for response in responses:
        if response.get('egoAgent') is None and not response.get('Gnaw_Completed', False):
            # Check if egoAgent.txt exists
            if os.path.exists('egoAgent.txt'):
                with open('egoAgent.txt', 'r') as file:
                    EgoSettings.egoAgent = file.read().strip()
            else:
                # If EgoSettings.egoAgent is not set, create a new EGOAgent instance
                data = {}  # Add necessary data here
                agent_response = create_EGOAgent(data, auth_token_json)
                agent_id = agent_response.get('id')  # Assuming the response contains an 'id' key
                # Update EgoSettings.egoAgent with the new agent's ID
                EgoSettings.egoAgent = agent_id
                # Remove special characters and spaces from the string
                EgoSettings.egoAgent = re.sub(r'\W+', '', str(EgoSettings.egoAgent))
                # Write the new agent's ID to egoAgent.txt
                with open('egoAgent.txt', 'w') as file:
                    file.write(EgoSettings.egoAgent)
            # Update the GnawControl instance with the new agent's ID
            ego_id = response.get('id')  # Assuming the response contains an 'id' key
            update_AgentControl(ego_id, EgoSettings.egoAgent, auth_token_json)
            Url_EgoControls = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/{ego_id}"
            request = get_request(Url_EgoControls, auth_token_json)
            response = request.json()    
            response_store.append(response)
            agent_response_store.append(agent_response)
    return response_store, agent_response_store

def update_gnaw_control(sub_domain, ego_id, auth_token_json):
    try:
        # Prepare the URL and headers
        url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/{ego_id}"
        headers = {"Content-type": "application/json", "Accept": "application/json"}
        if auth_token_json:
            headers.update(auth_token_json)
        # Prepare the data with the scannedHost and anotherField
        data = {"scannedHost": sub_domain}
        # Send the PATCH request
        response = requests.patch(url, data=json.dumps(data), headers=headers, verify=False)
    except Exception as E:
        print('Exception')
        print(E)


def gnaw():
    # Check for new items to scan
    cpuCount = round(os.cpu_count())
    print(f'cpu {cpuCount}')
    auth_token_json = {"Authorization": f"Bearer {EgoSettings.api_accessKey}"}
    responseEgo, responseAgent = register_and_update_agent(auth_token_json)
    print('responseEgo',responseEgo)
    print('responseAgent',responseAgent)
    # After registering and updating the agent
    agent_id = EgoSettings.egoAgent
# Update the agent's checkin    
    print('update_agent_checkin')
    update_agent_checkin(agent_id, auth_token_json)
    print('update_agent_checkin2')
    time.sleep(15)    
    responseEgo = responseEgo
    if responseEgo is None:
        print("No empty egoAgent found.")
        return 'No empty egoAgent found.'
    else:
        print("Updated egoAgent:", responseEgo)
        print(responseEgo)
        NukeOut = []
        if type(responseEgo) == dict:
            print('dict')
            responseEgo = [responseEgo]
        elif type(responseEgo) == str:
            responseEgo = [dict(responseEgo)]     
        else:
            responseEgo = (responseEgo)
        for response in responseEgo:
            ego_id = response['id']
            try:
                COMPLETED = response['Gnaw_Completed']
                FAILED = response['failed']
                print(COMPLETED)
                if COMPLETED == True or FAILED == True:
                    continue
                ScanGroupingProject= response["ScanGroupingProject"]
                customerId= response['ScanProjectByID']
                severity= response['severity']
                NucleiScan= response['NucleiScan']
                egoAgent = response['id']
                print('severity', severity)
                Ipv_Scan= response['Ipv_Scan']
                LoopCustomersBool= response['LoopCustomersBool']
                Customer_chunk_size= response['Customer_chunk_size']
                Record_chunk_size= response['Record_chunk_size']
                chunk_timeout= 0.2
                Global_Nuclei_CoolDown= response['Global_Nuclei_CoolDown']
                Global_Nuclei_RateLimit= response['Global_Nuclei_RateLimit']
                Port = response['Port']
                HostAddress= response['HostAddress']
                CUSTOMERS= f"{HostAddress}:{Port}/api/customers/{customerId}"
                BoneGnaw= []
                if LoopCustomersBool == True:
                    print('loops')
                    LoopCustomers= f"{HostAddress}:{Port}/api/customers/"
                    getRecords= get_request(LoopCustomers, auth_token_json)
                    rjsons= getRecords.json()
                    id_list= [i['id'] for i in rjsons]
                    RecordsCheck_chunks = split(id_list, Record_chunk_size)
                    print('count', len(id_list))
                    print('RecordsCheck_chunks', len(RecordsCheck_chunks))
                    chunkout=[]
                    for customerIdLoops in RecordsCheck_chunks:
                        print(customerIdLoops)
                        for customerIdLoop in customerIdLoops:
                            CUSTOMERS= f"{HostAddress}:{Port}/api/customers/{customerIdLoop}"
                            getRecords= get_request(CUSTOMERS, auth_token_json)
                            rjson= getRecords.json()
                            gnawTarget = (ScanGroupingProject.strip())
                            gnawTargets = (rjson['groupingProject'])
                            skipscan = rjson['skipScan']
                            print('gnawTarget', gnawTarget)
                            print('gnawTargets', gnawTargets)
                            if skipscan == True:
                                continue
                            elif str(gnawTarget) == str(gnawTargets):
                                RecordsStore= rjson["customerrecords"]
                                FullDomainNameSeensIt= set()
                                result = {}
                                print('count', len(RecordsStore))
                                headers = {"Content-type": "application/json", "Accept": "application/json"}
                                Bool_Start_chunk_timeout= False
                                if Bool_Start_chunk_timeout:
                                    print('Bool_Start_chunk_timeout')
                                    time.sleep(chunk_timeout)
                                    continue
                                else:
                                    RecordsCheck_chunks2 = Chunky(RecordsStore, Record_chunk_size)
                                    Store= []
                                    for RecordsCheck in RecordsCheck_chunks:
                                        if OutOfScopeString is None:
                            
                                            computations = [dask.delayed(worker_func)(RecordsCheck, NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, ego_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, Ipv_Scan=Ipv_Scan, auth_token_json=auth_token_json)]
                                            Store.extend(computations)
                                        elif OutOfScopeString not in RecordsCheck['subDomain']:
                                            print(RecordsCheck['subDomain'])
                                            continue
                                        else:
                                            computations = [dask.delayed(worker_func)(RecordsCheck, NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, ego_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, Ipv_Scan=Ipv_Scan, auth_token_json=auth_token_json)]
                                            Store.extend(computations)
                                        BoneGnaw.append(Store)
                                    # Compute all the delayed computations in parallel
                                    Nuke_responses = dask.compute(*Store, scheduler='threads', num_workers=workers)
                                    BoneGnaw.append(Nuke_responses)
                                    gnaw_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/{response['id']}"
                                    print(f"going to update gnawcontrols the task has been complete")
                                    dataPUt = {"Gnaw_Completed": True}
                                    recs = json.dumps(dataPUt)
    
                                    headers = {"Content-type": "application/json", "Accept": "application/json"}
                                    if auth_token_json:
                                        headers.update(auth_token_json)
                                    request = requests.patch(gnaw_url, data=recs, headers=headers, verify=False)
                                    response = request.json()          
                            else:
                                print(gnawTarget == gnawTargets)
                    Nuke_responses = dask.compute(*BoneGnaw, scheduler='threads', num_workers=cpuCount)
                    NukeOut.append(Nuke_responses)
                    gnaw_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/{response['id']}"
                    print(f"going to update gnawcontrols the task has been complete")
                    dataPUt = {"Gnaw_Completed": True}
                    recs = json.dumps(dataPUt)
    
                    headers = {"Content-type": "application/json", "Accept": "application/json"}
                    if auth_token_json:
                        headers.update(auth_token_json)
                    request = requests.patch(gnaw_url, data=recs, headers=headers, verify=False)
                    response = request.json()                    
                else:

                    getRecords= get_request(CUSTOMERS, auth_token_json)
                    rjson= json.loads(getRecords.text)
                    OutOfScopeString = rjson['OutOfScopeString']
                    RecordsCheck= rjson["customerrecords"]
                    FullDomainNameSeensIt= set()
                    result = {}
                    RecordsCheck_chunks = list(Chunky(RecordsCheck, Record_chunk_size))
                    headers = {"Content-type": "application/json", "Accept": "application/json"}
                    workers = len(RecordsCheck_chunks)
                    print('RecordsCheck_chunks', len(RecordsCheck_chunks))
                    print('count', len(RecordsCheck))
                    print('Record_chunk_size', Record_chunk_size)                
                    Store= []
                    for RecordsCheck in RecordsCheck_chunks:
                        if OutOfScopeString is None:
                            
                            computations = [dask.delayed(worker_func)(RecordsCheck, NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, ego_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, Ipv_Scan=Ipv_Scan, auth_token_json=auth_token_json)]
                            Store.extend(computations)
                        elif OutOfScopeString not in RecordsCheck['subDomain']:
                            print(RecordsCheck['subDomain'])
                            continue
                        else:
                            computations = [dask.delayed(worker_func)(RecordsCheck, NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, ego_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, Ipv_Scan=Ipv_Scan, auth_token_json=auth_token_json)]
                            Store.extend(computations)
                        BoneGnaw.append(Store)
                    # Compute all the delayed computations in parallel
                    Nuke_responses = dask.compute(*Store, scheduler='threads', num_workers=workers)
                    NukeOut.append(Nuke_responses)
                    gnaw_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/{response['id']}"
                    print(f"going to update gnawcontrols the task has been complete")
                    dataPUt = {"Gnaw_Completed": True}
                    recs = json.dumps(dataPUt)
    
                    headers = {"Content-type": "application/json", "Accept": "application/json"}
                    if auth_token_json:
                        headers.update(auth_token_json)
                    request = requests.patch(gnaw_url, data=recs, headers=headers, verify=False)
                    response = request.json()                    
            except Exception as E:
                print('Exception')
                print(E)  
                traceback.print_exc()
                gnaw_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/{ego_id}"
                print(f"going to update gnawcontrols the task has been complete")
                dataPUt = {"failed": True}
                recs = json.dumps(dataPUt)
                headers = {"Content-type": "application/json", "Accept": "application/json"}
                if auth_token_json:
                    headers.update(auth_token_json)
                request = requests.patch(gnaw_url, data=recs, headers=headers, verify=False)
                response = request.json()
                print('done record ')
                Nuke_responses  = None
        Nuke_responses=NukeOut
        print(f'GNAW IS COMPLETE {Nuke_responses}')         

        # Prepare the URL and headers
        url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/EGOAgent/{agent_id}/"
        headers = {"Content-type": "application/json", "Accept": "application/json"}
        if auth_token_json:
            headers.update(auth_token_json)

        # Prepare the data with the scanning status
        data = {"scanning": False}

        # Send the PATCH request
        response = requests.patch(url, data=json.dumps(data), headers=headers, verify=False)
        print('done record ')
    return 'Done'

from multiprocessing import Process

if __name__ == "__main__":
    processes = []
    while True:
        # If there are less than 3 gnaw functions running, start a new one
        if len(processes) < 3:
            p = Process(target=gnaw)
            p.start()
            processes.append(p)
        else:
            # If there are 3 gnaw functions running, wait for one to finish
            for p in processes:
                if not p.is_alive():
                    processes.remove(p)
                    break
            # Sleep for a while to prevent CPU overload
            time.sleep(1)