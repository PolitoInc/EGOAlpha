import whois
import fuzzywuzzy
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import requests,time,json,re,sys
import os.path
import random
from itertools import repeat
import multiprocessing as mp
from multiprocessing import Pool
from multiprocessing import Process, Value, Array
from collections import defaultdict, ChainMap, defaultdict
import dask
from dask.distributed import Client, progress
from operator import itemgetter
from operator import add
from itertools import groupby
from itertools import repeat
from itertools import chain
from itertools import product
import datetime
from re import sub

# customer imports
import EgoSettings
from libs.EgoDomainName import *
from libs.EgoNetWork import *
from libs.EgoDomainSearch import *
from libs.EgoNmapModule import *
from libs.EgoBox import *
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#####
#loginurl = "{HostAddress}:{Port}/api/login/"
#headers = {"Content-type": "application/json", "Accept": "application/json"}
#data = {"username": username, "password": password}
#recs = json.dumps(data)
#response = requests.post(loginurl, headers=headers, data=recs)
#token_response = response.json()['token']
auth_token_json = {"Authorization": f"Token aaaaaaaaa"}
####


DomainNameseen0= set({"github.com","azurefd.net","zendesk.com","google.com"})
rootSeensIt= set()
DOMAINSeensIt= set()
domains_file = "top_domains.txt"
cert_query_size = 100

hosts_query_size = 100
hosts_query_pages = 1
headers = {"Content-type": "application/json", "Accept": "application/json"}
headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleeWbKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"})
#API KEY WILL MOVE TO LIST OF KEYS ROTATE KEYS THAT HAVEN"T REACHED LIMIT.





def db_name(domain_data):
    domain_data = str(domain_data)
    if "." in domain_data:
        domain = (domain_data.split(".", -2)[-2])
        value = sub(r"[^-.0-9a-zA-Z]+", "", domain)
        return(value)
    else:
        domain = domain_data
        return(domain)

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





def brain(data):
    if data != 'None':
        wordsList = re.split(r'\W', data)
        if 'None' in wordsList:
            pass
        elif '' in wordsList:
            wordsFixed = [ele for ele in wordsList if ele]
            return wordsFixed
        else:
            return wordsList

def db_name(domain_data):
    domain_data = str(domain_data)
    if "." in domain_data:
        domain = (domain_data.split(".", -2)[-2])
        value = sub(r"[^-.0-9a-zA-Z]+", "", domain)
        return(value)
    else:
        domain = domain_data
        return(domain)

def merge(ipv4, cidr, port):
    try:
        merged_list = [(ipv4[i], cidr[i], port[i]) for i in range(0, len(ipv4))]
    except IndexError:
        pass
    return(merged_list)

def names_check_col(domain):
    if domain.count(".") >= 2:
        dbname = (".".join(domain.split(".", -2)[-2:]))
    elif domain.endswith("."):
        pass
    else:
        dbname = domain
    return (dbname)

def Convert(tup, di):
    results= []
    for k, v in tup:
        key= list(k.decode("utf-8") )
        value= v.decode("utf-8") 
        pair= dict.fromkeys(key,value)
        di.update(pair)
        results.append(di)
    return results
        




def Ego(username, password):
    try:
        cpuCount = os.cpu_count()
        urlLogin = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/login"
        creds = {"username": EgoSettings.EgoAgentUser, "password": EgoSettings.EgoAgentPassWord}
        headers = {"Content-type": "application/json", "Accept": "application/json"}
        req = requests.post(urlLogin,data=json.dumps(creds),headers=headers, verify=False, timeout=60)
        rjson_auth = req.json()
        if rjson_auth:
            auth_token_json = {"Authorization": f"Token {rjson_auth['token']}"}
            headers.update(auth_token_json)
        DOMAINseen = []
        Url_EgoControls = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/EgoControls/"

        request = requests.get(Url_EgoControls, headers=auth_token_json, verify=False, timeout=60)
        responses = request.json()
        for response in responses:
            try:
                COMPLETED = bool(response['Completed'])
                response_keys = response.keys()
                if COMPLETED == True:
                    pass
                else:
                    SET = response
                    id_EgoControl = response['id']
                    customerId= response['ScanProjectByID']
                    scanPRojectgroup= response['ScanGroupingProject']
                    scanProjectName = response['ScanProjectByName']
                    chunk_size= response['chunk_size']
                    #chunk_size= int(cpuCount)
                    CoolDown=  response['CoolDown']
                    CoolDown_Between_Queries = response['CoolDown_Between_Queries']
                    Port = response['Port']
                    HostAddress = response['HostAddress']
                    passiveAttack = response['passiveAttack']
                    agressiveAttack = response['agressiveAttack']
                    
                    portscan_bool = response['portscan_bool']
                    versionscan_bool = response['versionscan_bool']
                    Scan_Scope_bool = response['Scan_Scope_bool']
                    scan_records_BruteForce = response['BruteForce']
                    
                    Scan_IPV_Scope_bool = response['Scan_IPV_Scope_bool']
                    Scan_DomainName_Scope_bool = response['Scan_DomainName_Scope_bool']
                    scan_records_censys=  response['scan_records_censys']
                    crtshSearch_bool = response['crtshSearch_bool']
                    Update_RecordsCheck = response['Update_RecordsCheck']
                    LoopCustomersBool= response['LoopCustomersBool']
                    BruteForceBool = response['BruteForce']
                    BruteForce_WL = response['BruteForce_WL']
                    if bool(BruteForceBool) == True:
                        url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/DirectoryWords/"
                        requ = requests.get(url, headers=auth_token_json, verify=False, timeout=60)
                        rjson_word = requ.json()
                        if len(rjson_word) > 0:
                            if BruteForce_WL[0] == 'TLD':
                                Worddsresults = [{"TLD": words['WordList']} for words in rjson_word if BruteForce_WL[0] == (words['groupName']) ]
                            else:
                                Worddsresults = [{"DNS": words['WordList']} for words in rjson_word if BruteForce_WL[0] == (words['groupName']) ]
                    else:
                        Worddsresults = []
                    try:
                        EgoReconScan_object = response['EgoReconScan']
                    except:
                        EgoReconScan_object = False
                    if EgoReconScan_object == True:
                        pass
                    elif LoopCustomersBool == True:
                        LoopCustomers= f"{HostAddress}:{Port}/api/customers/"
                        headers.update(auth_token_json)
                        getRecords= requests.get(LoopCustomers, headers=headers, verify=False, timeout=60)
                        rjsons= getRecords.json()
                        
                        if chunk_size == 0:
                            id_list= [i['id'] for i in rjsons]
                            random.shuffle(id_list)
                            shuffled_id_list= [id_list]
                        else:
                            id_list= [i['id'] for i in rjsons]
                            id_chunks = list(ToolBox.splited(id_list, chunk_size))
                            random.shuffle(id_chunks)
                            shuffled_id_list= id_chunks
                        for customerIds in shuffled_id_list:
                            escape_outmeow = []
                            for customerId in customerIds:
                                TARGET = f"{HostAddress}:{Port}/api/customers/{customerId}"
                                headers.update(auth_token_json)
                                getRecords= requests.get(TARGET, headers=headers, verify=False, timeout=60)
                                rjson= getRecords.json()
                                FoundTLD = rjson.get('FoundTLD')
                                try:
                                    Worddsresults[0].update({"KnownTLD": FoundTLD})
                                except Exception as E:
                                    pass
                                if 'Not found.' in rjson.values():
                                    pass
                                else:
                                    if rjson is None:
                                        pass
                                    else:
                                        KEY= rjson["id"]
                                        customer_name = rjson['nameCustomer']
                                        RecordsCheck = rjson["customerrecords"]
                                        Scope = rjson["domainScope"]
                                        bool_Scope = bool(Scope)
                                        Ipv4Scope = rjson['Ipv4Scope']
                                        try:
                                            skipscan = rjson['skipScan']
                                        except:
                                            skipscan = False
                                        force = False
                                        if skipscan == True:
                                            pass
                                        else:
                                            try:
                                                OutOfScopeString = rjson['OutOfScopeString']
                                            except:
                                                OutOfScopeString = None
                                            bool_Ipv4Scope = bool(Ipv4Scope)
                                            KEY = rjson["id"]
                                            Customer_key= dict.fromkeys(['Customer_id'], KEY)
                                            SCOPED_set= set()
                                            [SCOPED_set.add(m) for m in FoundTLD ]
                                            if bool_Scope  == True:
                                                SCOPED_set_domain = {"SCOPED_set_domain": []}
                                            
                                                if Scan_DomainName_Scope_bool == True:
                                                    for i in rjson["domainScope"]:
                                                        if i:
                                                            domain_set= DomainNameValidation.CREATOR(i)
                                                            if domain_set == False:
                                                                pass
                                                            else:
                                                                SCOPED_set_domain['SCOPED_set_domain'].append(domain_set['domainname'])
                                                    SET.update(SCOPED_set_domain)
                                                    out=[]
                                                    for i in rjson["domainScope"]:
                                                        if i:
                                                            domain_set= DomainNameValidation.CREATOR(i)
                                                            if domain_set == False:
                                                                pass
                                                            else:
                                                                if OutOfScopeString is None:
                                                                
                                                                    if auth_token_json:
                                                                        scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                                        out.append(scan_scoped)
                                                                    else:
                                                                        scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                                        out.append(scan_scoped)
                                                                elif OutOfScopeString not in domain_set['domainname']:
                                                                    pass
                                                                else:
                                                                    if auth_token_json:
                                                                        scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                                        out.append(scan_scoped)
                                                                    else:
                                                                        scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                                        out.append(scan_scoped)
                                                    escape_outmeow= dask.compute(*out)
                                            
                                                elif Scan_IPV_Scope_bool == True:
                                                    SCOPED_set_Ipv = {'Ipv': []}
                                                    for i in Ipv4Scope:
                                                        domain_set= DomainNameValidation.CREATOR(i)
                                                        if domain_set == False:
                                                            pass
                                                        else:
                                                            SCOPED_set_Ipv['Ipv'].append(domain_set)

                                                    out = []
                                                    for i in SCOPED_set_Ipv['Ipv']:
                                                        if auth_token_json:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(i, Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                            SCOPED_set_domain.append(scan_scoped)
                                                        else:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(i, Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                            SCOPED_set_domain.append(scan_scoped)                                                            
                                                    god_store_To_RECON= dask.compute(*out)
                            
                                                    escape_outmeow= dask.compute(*SCOPED_set_domain)
                                                else:
                                 

                                            elif  bool_Ipv4Scope == True:
                                                SCOPED_set_domain = {"SCOPED_set_domain": []}
                                            
                                                if Scan_DomainName_Scope_bool == True:
                                                    for i in rjson["domainScope"]:
                                                        if i:
                                                            domain_set= DomainNameValidation.CREATOR(i)
                                                            if domain_set == False:
                                                                pass
                                                            else:
                                                                SCOPED_set_domain['SCOPED_set_domain'].append(domain_set['domainname'])
                                                    SET.update(SCOPED_set_domain)
                                                    out=[]
                                                    for i in rjson['customerrecords']:

                                                        if i:
                                                            domain_set= DomainNameValidation.CREATOR(i)
                                                            if domain_set == False:
                                                                pass
                                                            else:
                                                                if OutOfScopeString is None:
                                                
                                                                    if auth_token_json:
                                                                        scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                                        out.append(scan_scoped)

                                                                    else:
                                                                        scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                                        out.append(scan_scoped)                                                                          
                                                                elif OutOfScopeString not in domain_set['domainname']:
                                                                    pass
                                                                else:
                                                
                                                                    scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                                    out.append(scan_scoped)
                                                    escape_outmeow= dask.compute(*out)
                                            
                                                elif Scan_IPV_Scope_bool == True:
                                                    SCOPED_set_Ipv = {'Ipv': []}
                                                    for i in Ipv4Scope:
                                                        domain_set= DomainNameValidation.CREATOR(i)
                                                        if domain_set == False:
                                                            pass
                                                        else:
                                                            SCOPED_set_Ipv['Ipv'].append(domain_set)

                                                    out = []
                                                    for i in SCOPED_set_Ipv['Ipv']:
                                                        if auth_token_json:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(i, Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                            out.append(scan_scoped)

                                                        else:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(i, Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                            out.append(scan_scoped)     
                                                    god_store_To_RECON= dask.compute(*out)
                            
                                                    escape_outmeow= dask.compute(*SCOPED_set_domain)
                                                else:
                                            else:
                                                pass
                                    urlhost= f"{HostAddress}:{Port}/api/create/{customerId}"
                                    DIC = {}
                                    datetime_object = datetime.datetime.utcnow().isoformat()[:-3]+'Z'
                                    datetime_object = dict.fromkeys(['EgoReconScan'], datetime_object)
                                    EgoReconScan_object = dict.fromkeys(['EgoReconScan'], True)
                                    DIC.update(datetime_object)
                                    DIC.update(EgoReconScan_object)
                                    recs = json.dumps(DIC)
                                    headers.update(auth_token_json)
                                    getRecords= requests.patch(urlhost, data=recs, headers=headers,verify=False, timeout=60)

                                    urlUpdateComplete = f"{HostAddress}:{Port}/api/EgoControls/{id_EgoControl}"
                                    dataPUt = {"Completed": True}
                                    recs = json.dumps(dataPUt)
                                    headers.update(auth_token_json)
                                    request = requests.patch(urlUpdateComplete, data=recs, headers=headers,verify=False, timeout=60)
                                    response = request.json()

                                

                            escape_outmeow= dask.compute(*escape_outmeow)
                            urlhost= f"{HostAddress}:{Port}/api/create/{customerId}"
                            datetime_object = datetime.datetime.utcnow().isoformat()[:-3]+'Z'
                            datetime_object = dict.fromkeys(['LastScanned'], datetime_object)
                            rjson = json.dumps(datetime_object)
                            headers.update(auth_token_json)
                            getRecords= requests.patch(urlhost, data=rjson, headers=headers,verify=False, timeout=60)
                            urlUpdateComplete = f"{HostAddress}:{Port}/api/EgoControls/{id_EgoControl}"
                            dataPUt = {"Completed": "true"}
                            recs = json.dumps(dataPUt)
                            headers.update(auth_token_json)
                            request = requests.patch(urlUpdateComplete, data=recs, headers=headers,verify=False, timeout=60)
                            response = request.json()
                    else:
                        TARGET = f"{HostAddress}:{Port}/api/customers/{customerId}"
                        headers.update(auth_token_json)
                        getRecords= requests.get(TARGET, headers=headers, verify=False, timeout=60)
                        rjson= getRecords.json()
                        FoundTLD = rjson.get('FoundTLD')
                        try:
                            Worddsresults[0].update({"KnownTLD": FoundTLD})
                        except Exception as E:
                            pass
                        try:
                            OutOfScopeString = rjson['OutOfScopeString']
                        except:
                            OutOfScopeString = None
                        if 'Not found.' in rjson.values():
                            pass
                        else:
                            if rjson is None:
                                pass
                            else:
                                KEY= rjson["id"]
                                customer_name = rjson['nameCustomer']
                                RecordsCheck = rjson["customerrecords"]
                                Scope = rjson["domainScope"]
                                bool_Scope = bool(Scope)
                                Ipv4Scope = rjson['Ipv4Scope']
                                bool_Ipv4Scope = bool(Ipv4Scope)
                                KEY = rjson["id"]
                                Customer_key= dict.fromkeys(['Customer_id'], KEY)
                                SCOPED_set= set()
                                [SCOPED_set.add(m) for m in FoundTLD ]
                                if bool_Scope  == True:
                                    SCOPED_set_domain = {"SCOPED_set_domain": []}
                                            
                                    if Scan_DomainName_Scope_bool == True:
                                        for i in rjson["domainScope"]:
                                            if i:
                                                domain_set= DomainNameValidation.CREATOR(i)
                                                if domain_set == False:
                                                    pass
                                                else:
                                                    SCOPED_set_domain['SCOPED_set_domain'].append(domain_set['domainname'])
                                        SET.update(SCOPED_set_domain)
                                        out=[]
                                        for i in rjson["domainScope"]:
                                            if i:
                                                domain_set= DomainNameValidation.CREATOR(i)
                                                if domain_set == False:
                                                    pass
                                                else:
                                                    if OutOfScopeString is None:
                                      
                                                        if auth_token_json:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                            out.append(scan_scoped)

                                                        else:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                            out.append(scan_scoped)    
                                                    elif OutOfScopeString not in domain_set['domainname']:
                                                        pass
                                                    else:
                                                
                                                        if auth_token_json:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                            out.append(scan_scoped)

                                                        else:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                            out.append(scan_scoped)    
                                        escape_outmeow= dask.compute(*out)
                                            
                                    elif Scan_IPV_Scope_bool == True:
                                        SCOPED_set_Ipv = {'Ipv': []}
                                        for i in Ipv4Scope:
                                            domain_set= DomainNameValidation.CREATOR(i)
                                            if domain_set == False:
                                                pass
                                            else:
                                                SCOPED_set_Ipv['Ipv'].append(domain_set)

                                        out = []
                                        for i in SCOPED_set_Ipv['Ipv']:
                                            if auth_token_json:
                                                scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                out.append(scan_scoped)

                                            else:
                                                scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(i, SET=SET, Customer_key=Customer_key, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                out.append(scan_scoped)    
                                        god_store_To_RECON= dask.compute(*out)
                            
                                        escape_outmeow= dask.compute(*out)
                                    else:
                                 

                                elif  bool_Ipv4Scope == True:
                                    SCOPED_set_domain = {"SCOPED_set_domain": []}
                                            
                                    if Scan_DomainName_Scope_bool == True:
                                        for i in rjson["domainScope"]:
                                            if i:
                                                domain_set= DomainNameValidation.CREATOR(i)
                                                if domain_set == False:
                                                    pass
                                                else:
                                                    SCOPED_set_domain['SCOPED_set_domain'].append(domain_set['domainname'])
                                        SET.update(SCOPED_set_domain)
                                        out=[]
                                        for i in rjson["domainScope"]:
                                            if i:
                                                domain_set= DomainNameValidation.CREATOR(i)
                                                if domain_set == False:
                                                    pass
                                                else:
                                                    if OutOfScopeString is None:
                                                        if auth_token_json:
                                                            scan_scoped= dask.delayed(scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                            out.append(scan_scoped)

                                                        else:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                            out.append(scan_scoped)    
                                                    elif OutOfScopeString not in domain_set['domainname']:
                                                        pass
                                                    else:
                                                        if auth_token_json:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                            out.append(scan_scoped)
                                                        else:
                                                            scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(domain_set['domainname'], Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                            out.append(scan_scoped)    
                                        escape_outmeow= dask.compute(*out)
                                            
                                    elif Scan_IPV_Scope_bool == True:
                                        SCOPED_set_Ipv = {'Ipv': []}
                                        for i in Ipv4Scope:
                                            domain_set= DomainNameValidation.CREATOR(i)
                                            if domain_set == False:
                                                pass
                                            else:
                                                SCOPED_set_Ipv['Ipv'].append(domain_set)

                                        out = []
                                        for i in SCOPED_set_Ipv['Ipv']:
                                            if auth_token_json:
                                                scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(i, Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults, auth_token_json=auth_token_json)
                                                out.append(scan_scoped)

                                            else:
                                                scan_scoped= dask.delayed(EgoReconFunc.scan_scope)(i, Customer_key=Customer_key, SET=SET, SCOPED= SCOPED_set_domain, HostAddress=HostAddress, Port=Port, Worddsresults=Worddsresults)
                                                out.append(scan_scoped)    
                                        god_store_To_RECON= dask.compute(*out)
                            
                                        escape_outmeow= dask.compute(*SCOPED_set_domain)
                                    else:
                                else:
                                    pass
                            urlhost= f"{HostAddress}:{Port}/api/create/{customerId}"
                            datetime_object = datetime.datetime.utcnow().isoformat()[:-3]+'Z'
                            datetime_object = dict.fromkeys(['LastScanned'], datetime_object)
                            recs = json.dumps(datetime_object)
                            headers.update(auth_token_json)
                            getRecords= requests.patch(urlhost, data=recs, headers=headers, verify=False, timeout=60)
                            urlUpdateComplete = f"{HostAddress}:{Port}/api/EgoControls/{id_EgoControl}"
                            dataPUt = {"Completed": True}
                            recs = json.dumps(dataPUt)
                            headers.update(auth_token_json)
                            request = requests.patch(urlUpdateComplete, data=recs, headers=headers, verify=False, timeout=60)
                            response = request.json()
                                
            except Exception as E:
                urlUpdateComplete = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/EgoControls/{id_EgoControl}"
                dataPUt = {"failed": True}
                recs = json.dumps(dataPUt)
                headers.update(auth_token_json)
                request = requests.patch(urlUpdateComplete, data=recs, headers=headers, verify=False, timeout=60)
                response = request.json()
                return True

    except Exception as E:

if __name__ == "__main__":
    username = f"{EgoSettings.EgoAgentUser}"
    password = f"{EgoSettings.EgoAgentPassWord}"
    while True:
        Ego(username, password)
        time.sleep(10)

