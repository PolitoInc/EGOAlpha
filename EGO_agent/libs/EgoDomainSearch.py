import dask
import json
import requests
import hashlib
import datetime
import socket
import random
# customer imports
import EgoSettings
from .EgoDomainName import *

import time
from censys.search import CensysCertificates
import censys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def DATEREADER(DATE):
    
    date_time = datetime.datetime.now()
    LastScanned_date = (DATE.replace("T", " ").replace(".000Z", ""))
    when_to_scan = (datetime.datetime.now() + datetime.timedelta(days=30))
    current_date = str(current_date).split(" ")
    when_to_scan = str(when_to_scan).split(" ")

    if LastScanned_date == created_date:
        result = True
    elif str(current_date[0]) < str(when_to_scan[0]):
        result = True
    elif str(current_date[0]) == '2022-08-07':
        result = True
    else:
        result = False

DomainNameseen0= set({"github.com","azurefd.net","zendesk.com","google.com"})
rootSeensIt= set()
DOMAINSeensIt= set()
domains_file = "top_domains.txt"
cert_query_size = 100
hosts_query_size = 100
hosts_query_pages = 1
headers = {"Content-type": "application/json", "Accept": "application/json"}
headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"})
#API KEY WILL MOVE TO LIST OF KEYS ROTATE KEYS THAT HAVEN"T REACHED LIMIT.

# logic board for keys in use n stuff
#InUse = 
#aviabletoscan = 


class tools:
    def SubDater(target,subdomains, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=None):
        if subdomains:
            sub_url = "{HostAddress}:{Port}/api/subIndex/"
            tld_url = "{HostAddress}:{Port}/api/tldIndex/"
            if type(subdomains) is list:
                for i in subdomains: 
                    if i is None:
                        pass
                    else:
                        if target in i:
                            newSubDomain= i.replace(target, '<replace>')
                            data= dict.fromkeys(['sub'],newSubDomain)
                            DIC = {}
                            if auth_token_json:
                                DIC.update(auth_token_json)
                            else:
                                pass
                            DIC.update(headers)
                            if auth_token_json:
                                headers.update(auth_token_json)
                            PostRecords= requests.post(sub_url, data=data, headers=DIC, verify=False)
                        else:
                            DIC = {}
                            if auth_token_json:
                                DIC.update(auth_token_json)
                            else:
                                pass
                            DIC.update(headers)
                            if auth_token_json:
                                headers.update(auth_token_json)
                            PostRecords= requests.post(SubdomainUrl, data=data, headers=DIC, verify=False)
            elif type(subdomains) is dict:
                for i in target:
                    data= dict.fromkeys(['tld'],i)
                    DIC = {}
                    if auth_token_json:
                        DIC.update(auth_token_json)
                    else:
                        pass
                    DIC.update(headers)
                    if auth_token_json:
                        headers.update(auth_token_json)
                    PostRecords= requests.post(sub_url, data=data, headers=DIC, verify=False)
            else:
                return 'No updates'
        else:


class EgoDomainSearch:

    def GetHostName(subdomain, data):
        try:
            if data.startswith('.') and not subdomain.endswith('.'):
                fqdn = f"{subdomain}{data}"
            elif subdomain.endswith('.'):
                fqdn = f"{subdomain}{data}"
            else:
                fqdn = f"{subdomain}.{data}"
            
            Hostname_Domainname = socket.gethostbyname_ex(fqdn)
            if 'Unknown host' in Hostname_Domainname or 'Name or service not' in Hostname_Domainname:
                return False
            else:
                return True
        except Exception as E:
            return False

    def GoogleDorkDomains(data):
        return(data)

    def crtshSearch(data, CoolDown_Between_Queries, OutOfScopeString=None, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, SCOPED=None, SET=None):
        domain_set= DomainNameValidation.CREATOR(data)
        domainname= domain_set['domainname']
        try:
            if type(domain_set) is None:
                return False
            else:
                if any(scope in domainname  for scope in SCOPED['SCOPED_set_domain']):
                    scn= set()
                    OOS= set()
                    Dic= {}
                    suffixList= set()
                    subdomainList=set()
                    Global_Nuclei_CoolDown=(15,300)
                    Sleep_Generator = round(random.uniform(Global_Nuclei_CoolDown[0], Global_Nuclei_CoolDown[1]), 2)
                    time.sleep(Sleep_Generator)
                    url = (f"https://crt.sh/?q={domainname}&output=json")
                    r = requests.get(url, allow_redirects=True, verify=True, timeout=30)
                    
                    status = r.status_code
                    rson = r.json()

                    if status != 200:
                        time.sleep(7)
                        return False
                    else:
                        if rson:
                            listed_rson = ([x["name_value"].split() for x in rson])
                            for listed in listed_rson:
                            
                                i= listed[0]
                                domain_set= DomainNameValidation.CREATOR(i)
                                domainname= domain_set['domainname']
                                fulldomain= domain_set['fulldomain']
                                sub= domain_set['SUBDOMAIN']
                                suf= domain_set['SUFFIX']
                                if domainname not in SCOPED['SCOPED_set_domain']: 
                                    OOS.add(domain_set['fulldomain'])
                                    pass
                                else:
                                    if OutOfScopeString is None:
                                        suffixList.add(domain_set['SUFFIX'])
                                        subdomainList.add(domain_set['SUBDOMAIN'])
                                        scn.add(domain_set['fulldomain'])
                                    elif OutOfScopeString not in domain_set['fulldomain']:
                                        pass
                                    else:
                                        suffixList.add(domain_set['SUFFIX'])
                                        subdomainList.add(domain_set['SUBDOMAIN'])
                                        scn.add(domain_set['fulldomain'])
                        else:
                            return False
                    tools.SubDater(domainname,subdomainList)

                    if (scn) or (OOS):
                        Results = dict.fromkeys(['in_scope'],[y for y in scn])
                        ResultsOOS=dict.fromkeys(['out_of_scope'],[y for y in OOS])
                        Results.update(ResultsOOS)
                        Dic.update(Results)
                        if Dic is not None:
                            return(Dic)
                        else:
                            return False
                    else:
                        return False
                else:
        except Exception as E:
            return False
        
    def censysSearch(line, SCOPED, CoolDown, CoolDown_Between_Queries, OutOfScopeString=None, auth_token_json=None, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port):
        if 'SCOPED_set_domain' in SCOPED:
            SCOPED = SCOPED['SCOPED_set_domain']
        else:
            SCOPED = SCOPED
        try:
            id_secret = EgoSettings.CensysSecretID
            key_secret = EgoSettings.CensysSecretKey
            NON_COMMERCIAL_API_LIMIT = 100
            #fields
            CertFields = [
                    "parsed.names",
                    "parsed.validity.start",
                    "parsed.validity.end",
                    "parsed.subject_dn",
                    "parsed.signature_algorithm.name",
                    "parsed.issuer.country",
                    "parsed.issuer.common_name",
                    "parsed.issuer.organization",
                    "parsed.subject.common_name",
                    "parsed.subject.country",
                    "parsed.__expanded_names"
            ]
            finger = "parsed.finger#print_sha256"
            cnames = "parsed.names"

            domain_set= DomainNameValidation.CREATOR(line)
            DomainName_censys_cert= domain_set['domainname']
            h = CensysCertificates(api_id=id_secret,api_secret=key_secret)
            if type(DomainName_censys_cert) is None:
                pass
            else:
        
                if any(scope in DomainName_censys_cert for scope in SCOPED):
                    scn= set()
                    OOS= set()
                    Dic= {}
                    suffixList= set()
                    subdomainList=set()

                    h = CensysCertificates(api_id=id_secret,api_secret=key_secret)
                    certificate_query = f"parsed.names: .{DomainName_censys_cert}"
                    try:
                        results = h.search(f"parsed.names : {DomainName_censys_cert}", fields=['parsed.names'], max_records=NON_COMMERCIAL_API_LIMIT)
                    except:
                    #cert = censys.CensysCertificates()
                    for c in results:
                        #time.sleep(CoolDown_Between_Queries)
                        names= c["parsed.names"]
                        if not c:
                            #time.sleep(CoolDown)
                            #EgoDomainSearch.censysSearch(line, SCOPED, CoolDown, CoolDown_Between_Queries, OutOfScopeString)
                            pass
                        else:
                            for value in names:
                                domain_set= DomainNameValidation.CREATOR(value)
                                fulldomain= domain_set['fulldomain']
                                if any(scope in fulldomain for scope in SCOPED):
                                    sub= domain_set['SUBDOMAIN']
                                    suf= domain_set['SUFFIX']
                                    suffixList.add(suf)
                                    subdomainList.add(sub)
                                    fqdn= fulldomain
                                    if OutOfScopeString:
                                        if str(OutOfScopeString) in fqdn :
                                            pass
                                        else:
                                            suffixList.add(domain_set['SUFFIX'])
                                            subdomainList.add(domain_set['SUBDOMAIN'])
                                            scn.add(domain_set['fulldomain'])
                                    else:
                                        scn.add(fqdn)
                                else:
                                    if domain_set['domainname'].lower() == '.com':
                                        pass
                                    else:
                                        OOS.add(fulldomain)                                                
                    tools.SubDater(DomainName_censys_cert ,suffixList)
                    tools.SubDater(DomainName_censys_cert ,subdomainList)
                    suffixResults= dict.fromkeys(['Suffix'],suffixList)
                    subdomainResults= dict.fromkeys(['SubDomain'],subdomainList)
                    result = bool(scn)
                    oosResult = bool(OOS)
                    TARGET= dict.fromkeys(['Target'], DomainName_censys_cert)
                    if (result) and (oosResult):
                        Dic.update(TARGET)
                        Results= dict.fromkeys(['in_scope'],scn)
                        ResultsOOS=dict.fromkeys(['out_of_scope'],OOS)
                        Results.update(ResultsOOS)
                        Results.update(subdomainResults)
                        Dic.update(Results)
                        return Dic
                    elif oosResult is not True and result is True:
                        Dic.update(TARGET)
                        Results= dict.fromkeys(['in_scope'],scn)
                        Results.update(subdomainResults)
                        Dic.update(Results)
                        return Dic
                    else:
                        return None
                else:
        except Exception as E:
            pass