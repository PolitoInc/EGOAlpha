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
import dask.array as dd
from nested_lookup import nested_delete
import datetime
# custom imports

import EgoSettings

#from dask.distributed import Client, progress
import numpy as np
import time
import hashlib
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


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
                pass
        except Exception as err:
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
        pass
     

def brain_word_comprehension(data, record_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=None):
    # reads None value from memory
    if data == 'None':
        pass
    else:
        STORED= set()
        DIC= {}
        datatype= type(data)
        itype= type(data)
        i = data
        if itype == None:
            pass
        elif "template" in i:
            
            del i['timestamp']
            if 'curl-command' in i:
                curl_command = i.get('curl-command', '')
                i = (nested_delete(i, 'curl-command'))
                
                md5_hash = hashlib.md5(json.dumps(i, sort_keys=True).encode('utf-8')).hexdigest()
                curl_command = dict.fromkeys(['curl_command'], curl_command)
                i.update(curl_command)
                md5 = dict.fromkeys(['md5'], md5_hash)
                DIC.update(md5)
                template_id = dict.fromkeys(['record_id'], record_id)
                DIC.update(template_id)
                DIC.update(i)
                DIC_OUT = []
                for k in list(DIC):
                    if '-' in k:
                        Removed_underscore = k.replace('-',"_")
                        DIC[Removed_underscore] = DIC.pop(k)
                        
                        if k == 'classification':
                            port_i= i.get('classification',{})
                            for k in port_i:
                                Removed_underscore = k.replace('-',"_")
                                DIC[Removed_underscore] = DIC.pop(k)
                                DIC_OUT.append(DIC)
                        else:
                            DIC_OUT.append(DIC)
                DIC = DIC_OUT[0]
                certificateurlPost= f"{HostAddress}:{Port}/api/Templates/create/"
                recs= json.dumps(DIC)
                if auth_token_json:
                    headers.update(auth_token_json)
                headers.update(auth_token_json)
                postRecords = requests.post(certificateurlPost, data=(recs), headers=headers, verify=False)
            else:
                md5_hash = hashlib.md5(json.dumps(i, sort_keys=True).encode('utf-8')).hexdigest()
                md5 = dict.fromkeys(['md5'], md5_hash)
                DIC.update(md5)
                template_id = dict.fromkeys(['record_id'], record_id)
                DIC.update(template_id)
                DIC.update(i)
                DIC_OUT = []
                for k in list(DIC):
                    if '-' in k:
                        Removed_underscore = k.replace('-',"_")
                        DIC[Removed_underscore] = DIC.pop(k)
                        
                        if k == 'classification':
                            port_i= i.get('classification',{})
                            for k in port_i:
                                Removed_underscore = k.replace('-',"_")
                                DIC[Removed_underscore] = DIC.pop(k)
                                DIC_OUT.append(DIC)
                        else:
                            DIC_OUT.append(DIC)
                            
                DIC = DIC_OUT[0]
                certificateurlPost= f"{HostAddress}:{Port}/api/Templates/create/"
                recs= json.dumps(DIC)
                if auth_token_json:
                    headers.update(auth_token_json)
                headers.update(auth_token_json)
                postRecords = requests.post(certificateurlPost, data=(recs), headers=headers, verify=False)
        else:
            itype= type(i)
            #words = replace_strings(i)
            wordsList = re.split(' ', i)
            itype= type(wordsList)
            if len(wordsList) == 6:
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
                DIC.update(name)
                DIC.update(method)
                DIC.update(severity)
                DIC.update(vulnerable)
                Nuclei_id = dict.fromkeys(['nuclei'], record_id)
                Nuclei_id.update(DIC) 
                certificateurlPost= f"{HostAddress}:{Port}/api/Nuclei/"
                recs= json.dumps(Nuclei_id)
                if auth_token_json:
                    headers.update(auth_token_json)
                postRecords = requests.post(certificateurlPost, data=(recs), headers=headers, verify=False)
            elif len(wordsList) == 7:
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
                DIC.update(name)
                DIC.update(method)
                DIC.update(severity)
                DIC.update(vulnerable)
                Nuclei_id = dict.fromkeys(['nuclei'], record_id)
                Nuclei_id.update(DIC) 
                certificateurlPost= f"{HostAddress}:{Port}/api/Nuclei/"

                recs= json.dumps(Nuclei_id)
                if auth_token_json:
                    headers.update(auth_token_json)
                postRecords = requests.post(certificateurlPost, data=(recs), headers=headers, verify=False)
            else:
                pass
                

        return STORED  


def nuclei_func(domain , NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, Ipv_Scan, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=None):
    tuple = (6, int(Global_Nuclei_RateLimit))
    Global_Nuclei_RateLimit = round(random.uniform(tuple[0], tuple[1]))
    try:
        DIC= {}
        record_id = domain['id']
        alive= domain["alive"]
        p= domain['subDomain']
        port= domain['OpenPorts']
        s= domain['DNSQuery_record']
        a= domain['DNSAuthority_record']
        z= a + s
        domain_set= DomainName_CREATOR(p)
        
        try:
            if any(x == '443' for x in port):
                domainname= domain_set['domainname']
                fulldomain= domain_set['fulldomain']
                url= f"https://{fulldomain}"

            else:
                domainname= domain_set['domainname']
                fulldomain= domain_set['fulldomain']
                url= f"http://{fulldomain}"
        except:
            #print not finished
            fulldomain= domain_set['Ipv']
        Record_NucleiScan = domain['nucleiBool']

        if Record_NucleiScan == NucleiScan:
            if Ipv_Scan == True:
                severity_scored= 'info,low,medium,high,critical,unknown'
                #severity_scored_list= severity_scored.split(",")
                severity_scored_list= re.split(';|,|\*|\n', severity_scored)
                severity_list= severity.split(",")
        
                if any(list == severity_list for list in severity_scored_list):
                    return False
                else:
                    readyson = fulldomain.replace('.', '_')
                    token= 'ReplaceME'
                    failed_search= 'Nothing to report, sorry.' 
                    #'-concurrency', '3'
                    #  nuclei = subprocess.check_output(['nuclei', '-no-color','-vv', '-jsonl', '-u', f'{domain}', '-iserver', 'rabidio.com', '-itoken', f'{token}', '-severity', f'{severity}', '-output', f'./dump/{readyson}.json'], text=True)
                    if os.name == 'posix':
                        path = f"./dump/{readyson}.json"
                    else:
                        #path = f"E:/tools/0_Secret_lab/EGO_old/ego8\EGO/dump/{readyson}.json"
                        path = f"E:/tools/0_Secret_lab/EGO_old/ego8/EGO/dump/{readyson}.json"
                    try:
                        
                        nuclei = subprocess.check_output(['nuclei', '-no-color','-vv', '-silent', '-jsonl', '-interactions-cooldown-period', '30', '-interactions-poll-duration', '10', '-interactions-eviction', '30', '-rate-limit', f'{Global_Nuclei_RateLimit}', '-rate-limit-minute', f'{Global_Nuclei_CoolDown}', '-u', f'{url}', '-iserver', 'rabidio.com', '-itoken', f'{token}', '-severity', f'{severity}', '-output', f"{path}"], text=True)
                    

                        if nuclei is not True: 
                            pass
                        else:
                            nuclei_results= nuclei.split('\n')
                            for i in nuclei_results:
                                nuclei_results = json.loads(i)
                                nuclei_brain= brain_word_comprehension(nuclei_results, record_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=auth_token_json)
                                return True
                    except Exception as E:
                        return False
            else:
                if bool(alive) == False:
                    pass
                else:
                    Subdomain_set= Subdomain_attack(fulldomain)
                    severity_scored= 'info,low,medium,high,critical,unknown'
                #severity_scored_list= severity_scored.split(",")
                    severity_scored_list= re.split(';|,|\*|\n', severity_scored)
                    severity_list= severity.split(",")
                    readyson = fulldomain.replace('.', '_')
                    if any(list == severity_list for list in severity_scored_list):
                        return False
                    else:
                        token= '3da50a43845a62269dc87bfa65dde5ae9e5d859068eb1ce19acc3725bb7cb2e4'
                        failed_search= 'Nothing to report, sorry.' 
                        #'-concurrency', '3'
                        #  nuclei = subprocess.check_output(['nuclei', '-no-color','-vv', '-jsonl', '-u', f'{domain}', '-iserver', 'rabidio.com', '-itoken', f'{token}', '-severity', f'{severity}', '-output', f'./dump/{readyson}.json'], text=True)
                        if os.name == 'posix':
                            path = f"./dump/{readyson}.json"
                        else:
                            #path = f"E:/tools/0_Secret_lab/EGO_old/ego8\EGO/dump/{readyson}.json"
                            path = f"E:/tools/0_Secret_lab/EGO_old/ego8/EGO/dump/{readyson}.json"
                        try:

                            if Global_Nuclei_CoolDown > 0: 
                                Nuclei_rate_limit = "'-rlm', f'Global_Nuclei_CoolDown' ,"
                            else:
                                Nuclei_rate_limit = "'-rate-limit', f'{Global_Nuclei_RateLimit}'"
                            nuclei = subprocess.check_output(['nuclei', '-no-color','-vv', '-jsonl','-silent', '-interactions-cooldown-period', '30', '-interactions-poll-duration', '10', '-interactions-eviction', '30', Nuclei_rate_limit, '-u', f'{url}', '-iserver', 'rabidio.com', '-itoken', f'{token}', '-severity', f'{severity}', '-output', path ], text=True)
                            nuclei_results= nuclei.split('\n')
                            if nuclei:
                                for i in nuclei_results:
                                    nuclei_results = json.loads(i)
                                    nuclei_brain= brain_word_comprehension(nuclei_results, record_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=auth_token_json )
                                    return True
                        except Exception as E:
                            return False
        elif bool(alive) == False:
            pass
        else:
            if Ipv_Scan == True:
                severity_scored= 'info,low,medium,high,critical,unknown'
                #severity_scored_list= severity_scored.split(",")
                severity_scored_list= re.split(';|,|\*|\n', severity_scored)
                severity_list= severity.split(",")
            
                if any(list == severity_list for list in severity_scored_list):
                    return False
                elif 'all' in severity_list:
                    sevrity = 'info,low,medium,high,critical,unknown'
                    readyson = fulldomain.replace('.', '_')
                    token= '3da50a43845a62269dc87bfa65dde5ae9e5d859068eb1ce19acc3725bb7cb2e4'
                    failed_search= 'Nothing to report, sorry.' 
                    #'-concurrency', '3'
                    #  nuclei = subprocess.check_output(['nuclei', '-no-color','-vv', '-jsonl', '-u', f'{domain}', '-iserver', 'rabidio.com', '-itoken', f'{token}', '-severity', f'{severity}', '-output', f'./dump/{readyson}.json'], text=True)
                    if os.name == 'posix':
                        path = f"./dump/{readyson}.json"
                    else:
                        #path = f"E:/tools/0_Secret_lab/EGO_old/ego8\EGO/dump/{readyson}.json"
                        path = f"E:/tools/0_Secret_lab/EGO_old/ego8/EGO/dump/{readyson}.json"
                    try:
                        if Global_Nuclei_CoolDown > 0: 
                            Nuclei_rate_limit = "'-rlm', f'Global_Nuclei_CoolDown' ,"
                        else:
                            Nuclei_rate_limit = "'-rate-limit', f'{Global_Nuclei_RateLimit}'"
                        nuclei = subprocess.check_output(['nuclei', '-no-color','-vv', '-jsonl','-silent', '-interactions-cooldown-period', '30', '-interactions-poll-duration', '10', '-interactions-eviction', '30', Nuclei_rate_limit, '-u', f'{url}', '-iserver', 'rabidio.com', '-itoken', f'{token}', '-severity', f'{severity}', '-output', path ], text=True)
                        nuclei_results= nuclei.split('\n')
                        if nuclei:
                            for i in nuclei_results:
                                nuclei_results = json.loads(i)
                                nuclei_brain= brain_word_comprehension(nuclei_results, record_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=auth_token_json )
                                return True
                    except Exception as E:
                        return False
                else:
                    readyson = fulldomain.replace('.', '_')
                    token= '3da50a43845a62269dc87bfa65dde5ae9e5d859068eb1ce19acc3725bb7cb2e4'
                    failed_search= 'Nothing to report, sorry.' 
                    #'-concurrency', '3'
                    #  nuclei = subprocess.check_output(['nuclei', '-no-color','-vv', '-jsonl', '-u', f'{domain}', '-iserver', 'rabidio.com', '-itoken', f'{token}', '-severity', f'{severity}', '-output', f'./dump/{readyson}.json'], text=True)
                    if os.name == 'posix':
                        path = f"./dump/{readyson}.json"
                    else:
                        path = f"E:/tools/0_Secret_lab/EGO_old/ego8/EGO/dump/"
                    try:
                        if nuclei:
                            if Global_Nuclei_CoolDown > 0: 
                                Nuclei_rate_limit = "'-rlm', f'Global_Nuclei_CoolDown' ,"
                            else:
                                Nuclei_rate_limit = "'-rate-limit', f'{Global_Nuclei_RateLimit}'"
                            nuclei = subprocess.check_output(['nuclei', '-no-color','-vv', '-jsonl','-silent', '-interactions-cooldown-period', '30', '-interactions-poll-duration', '10', '-interactions-eviction', '30', Nuclei_rate_limit, '-u', f'{url}', '-iserver', 'rabidio.com', '-itoken', f'{token}', '-severity', f'{severity}', '-output', path ], text=True)
                            nuclei_results= nuclei.split('\n')
                            for i in nuclei_results:
                                nuclei_results = json.loads(i)
                                nuclei_brain= brain_word_comprehension(nuclei_results, record_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=auth_token_json )
                                return True
                    except Exception as E:
                        return False
            else:
                Subdomain_set= Subdomain_attack(fulldomain)
                severity_scored= 'info,low,medium,high,critical,unknown'
                #severity_scored_list= severity_scored.split(",")
                severity_scored_list= re.split(';|,|\*|\n', severity_scored)
                severity_list= severity.split(",")
                readyson = fulldomain.replace('.', '_')
                if any(list == severity_list for list in severity_scored_list):
                    return False
                else:
                    token= '3da50a43845a62269dc87bfa65dde5ae9e5d859068eb1ce19acc3725bb7cb2e4'
                    failed_search= 'Nothing to report, sorry.' 
                    if os.name == 'posix':
                        path = f"./dump/{readyson}.json"
                    else:
                        #path = f"E:/tools/0_Secret_lab/EGO_old/ego8\EGO/dump/{readyson}.json"
                        path = f"E:/tools/0_Secret_lab/EGO_old/ego8/EGO/dump/"
                    try:
                        if Global_Nuclei_CoolDown > 0: 
                            Nuclei_rate_limit = "'-rlm', f'Global_Nuclei_CoolDown' ,"
                        else:
                            Nuclei_rate_limit = "'-rate-limit', f'{Global_Nuclei_RateLimit}'"
                        nuclei = subprocess.check_output(['nuclei', '-no-color','-vv', '-jsonl','-silent', '-interactions-cooldown-period', '30', '-interactions-poll-duration', '10', '-interactions-eviction', '30', Nuclei_rate_limit, '-u', f'{url}', '-iserver', 'rabidio.com', '-itoken', f'{token}', '-severity', f'{severity}', '-output', path ], text=True)
                        if nuclei:
                            nuclei_results= nuclei.split('\n')
                            for i in nuclei_results:
                                nuclei_results = json.loads(i)
                                nuclei_brain= brain_word_comprehension( nuclei_results, record_id, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=auth_token_json )
                                return True
                    except Exception as E:
                        return False
    except Exception as E:

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

def gnaw():
    cpuCount = round(os.cpu_count())
    username = f"{EgoSettings.EgoAgentUser}"
    password = f"{EgoSettings.EgoAgentPassWord}"
    urlLogin = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/login"
    headers = {"Content-type": "application/json", "Accept": "application/json"}
    creds = {"username": EgoSettings.EgoAgentUser, "password": EgoSettings.EgoAgentPassWord}
    req = requests.post(urlLogin,data=json.dumps(creds),headers=headers, verify=False)
    rjson_auth = req.json()
    if rjson_auth:
        auth_token_json = {"Authorization": f"Token {rjson_auth['token']}"}

    Url_EgoControls = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/"
    if auth_token_json:
        request = requests.get(Url_EgoControls, headers=auth_token_json, verify=False)
    else:
        request = requests.get(Url_EgoControls, verify=False)
    responses = request.json()
    BoneGnaw= []
    for response in responses:
        ego_id = response['id']
        try:
            COMPLETED = response['Gnaw_Completed']
            FAILED = response['failed']
            if COMPLETED == True:
                pass
            elif FAILED == True:
                pass
            else:
                ScanGroupingProject= response["ScanGroupingProject"]
                customerId= response['ScanProjectByID']
                #customerId= "33dbd41c-ddea-4bc6-a1e7-41d3acae519d"
            # info, low, medium, high, critical, unknown
                severity= response['severity']
            #true == false false == true
                NucleiScan= response['NucleiScan']
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
                if LoopCustomersBool == True:
                    LoopCustomers= f"{HostAddress}:{Port}/api/customers/"
                    if auth_token_json:
                        getRecords= requests.get(LoopCustomers, headers=auth_token_json, verify=False)
                    else:
                        getRecords= requests.get(LoopCustomers, verify=False)
                    rjsons= getRecords.json()
                    id_list= [i['id'] for i in rjsons]
                    RecordsCheck_chunks = split(id_list, Record_chunk_size)
                    chunkout=[]
                    for customerIdLoops in RecordsCheck_chunks:
                            
                        for customerIdLoop in customerIdLoops:
                            CUSTOMERS= f"{HostAddress}:{Port}/api/customers/{customerIdLoop}"
                            if auth_token_json:
                                getRecords= requests.get(CUSTOMERS, headers=auth_token_json, verify=False)
                            else:
                                getRecords= requests.get(CUSTOMERS, verify=False)
                            rjson= getRecords.json()
                            gnawTarget = (ScanGroupingProject.strip())
                            gnawTargets = (rjson['groupingProject'])
                            skipscan = rjson['skipScan']
                            if skipscan == True:
                                pass
                            elif str(gnawTarget) == str(gnawTargets):
                                RecordsStore= rjson["customerrecords"]
                                FullDomainNameSeensIt= set()
                                result = {}
                                headers = {"Content-type": "application/json", "Accept": "application/json"}
                                #BoneGnaw= []
                                Bool_Start_chunk_timeout= False
                                if Bool_Start_chunk_timeout:
                                    time.sleep(chunk_timeout)
                                    continue
                                else:
                                    RecordsCheck_chunks2 = split(RecordsStore, Record_chunk_size)
                                    BoneGnaw= []
                                    for RecordsChecks in RecordsCheck_chunks2:
                                        for RecordsCheck in RecordsChecks:
                                            id = RecordsCheck.get('id')
                                            created_date = RecordsCheck.get('created_date')
                                            LastScanned = RecordsCheck.get('LastScanned')
                                            SkipScan = RecordsCheck.get('skipScan')
                                            BoolSkipScan = DATEREADER(created_date, LastScanned)
                                            BoolSkipScan = True
                                            if SkipScan == True:
                                                pass
                                            elif BoolSkipScan == False:
                                                pass
                                            else:
                                                Bool_Start_chunk_timeout =+ True
                                                Nuke_response= dask.delayed(nuclei_func)(RecordsCheck , NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, Ipv_Scan, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=auth_token_json)
                                                BoneGnaw.append(Nuke_response)
                                                url= f"{HostAddress}:{Port}/api/records/{id}"
                                                data = {"lastScan": datetime.datetime.now()}
                                                #resp = requests.patch(url=url, data=data, headers=headers )
                            else:
                else:
                    getRecords= requests.get(CUSTOMERS, headers=auth_token_json, verify=False)
                    rjson= json.loads(getRecords.text)
                    OutOfScopeString = rjson['OutOfScopeString']
                    RecordsCheck= rjson["customerrecords"]
                    FullDomainNameSeensIt= set()
                    result = {}
                    RecordsCheck_chunks = list(split(RecordsCheck, Record_chunk_size))
                    headers = {"Content-type": "application/json", "Accept": "application/json"}
                    for RecordsChecks in RecordsCheck_chunks:
                        for RecordsCheck in RecordsChecks:
                            id = RecordsCheck.get('id')
                            created_date = RecordsCheck.get('created_date')
                            LastScanned = RecordsCheck.get('LastScanned')
                            SkipScan = RecordsCheck.get('skipScan')
                            BoolSkipScan = DATEREADER(created_date, LastScanned)
                            #if SkipScan == True:
                            BoolSkipScan = False
                            if BoolSkipScan == True:
                                pass
                            else:
                                if OutOfScopeString is None:
                                    Nuke_response= dask.delayed(nuclei_func)(RecordsCheck, NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, Ipv_Scan, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=auth_token_json)
                                    BoneGnaw.append(Nuke_response)
                                    url= f"{HostAddress}:{Port}/api/records/{id}"
                                    data = {"lastScan": datetime.datetime.now()}
                                    #resp = requests.patch(url=url, data=data, headers=headers )
                                elif OutOfScopeString not in RecordsCheck['subDomain']:
                                    pass
                                else:
                                    Nuke_response= dask.delayed(nuclei_func)(RecordsCheck, NucleiScan, severity, Global_Nuclei_CoolDown, Global_Nuclei_RateLimit, Ipv_Scan, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=auth_token_json)
                                    BoneGnaw.append(Nuke_response)
                                    url= f"{HostAddress}:{Port}/api/records/{id}"
                                    data = {"lastScan": datetime.datetime.now()}
                                    #resp = requests.patch(url=url, data=data, headers=headers )
        except Exception as E:
            gnaw_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/{ego_id}"
            dataPUt = {"failed": True}
            recs = json.dumps(dataPUt)
            headers = {"Content-type": "application/json", "Accept": "application/json"}
            if auth_token_json:
                headers.update(auth_token_json)
            request = requests.patch(gnaw_url, data=recs, headers=headers, verify=False)
            response = request.json()

    Nuke_responses= dask.compute(*BoneGnaw)
    gnaw_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/{response['id']}"
    dataPUt = {"Gnaw_Completed": True}
    recs = json.dumps(dataPUt)
    headers = {"Content-type": "application/json", "Accept": "application/json"}
    if auth_token_json:
        headers.update(auth_token_json)
    request = requests.patch(gnaw_url, data=recs, headers=headers, verify=False)
    response = request.json()
    gnaw_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/GnawControl/"
                
    dataPUt = {"Gnaw_Completed": True}
    recs = json.dumps(dataPUt)
    if auth_token_json:
        headers.update(auth_token_json)
        request = requests.patch(gnaw_url, data=recs, headers=headers, verify=False)
        response = request.json()



if __name__ == "__main__":
    while True:
        gnaw()
        time.sleep(10)

    



    #    Nuke_responses= dask.compute(*BoneGnaw, scheduler='distributed')
