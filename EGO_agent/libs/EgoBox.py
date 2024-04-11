import dask
import json
import requests
import hashlib
import datetime
import time
import random
import pyasn
import os
import whois

from bs4 import BeautifulSoup
import fuzzywuzzy
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
# customer imports

from .EgoDomainName import*
from .EgoNetWork import *
from .EgoDomainSearch import *
from .EgoNmapModule import *
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import uuid
from PIL import Image
from ip2geotools.databases.noncommercial import DbIpCity
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

import EgoSettings
seen = []
print(f'{EgoSettings.dump}', f'{EgoSettings.dump}/libs/pyasn/data/ipsn_db_file_name.dat')
if str(os.name) == 'nt':
    asndb = pyasn.pyasn(r'.\pyasn\data\ipsn_db_file_name.dat')
else:
    asndb = pyasn.pyasn(f'{EgoSettings.dump}/libs/pyasn/data/ipsn_db_file_name.dat')

class EgoReconFunc:
    def scan_scope(domain, 
                   SET=None, 
                   Customer_key=None,
                   SCOPED=None,
                   HostAddress=EgoSettings.HostAddress, 
                   Port=EgoSettings.Port, 
                   OutOfScopeString=None,
                   auth_token_json=None,
                   Worddsresults=None
                   ):
        id_EgoControl = SET['id']
        customerId= SET['ScanProjectByID']
        scanPRojectgroup= SET['ScanGroupingProject']
        scanProjectName = SET['ScanProjectByName']
        CoolDown=  SET['CoolDown']
        CoolDown_Between_Queries = SET['CoolDown_Between_Queries']
        Port = SET['Port']
        HostAddress = SET['HostAddress']
        passiveAttack = SET['passiveAttack']
        agressiveAttack = SET['agressiveAttack']
        portscan_bool = SET['portscan_bool']
        versionscan_bool = SET['versionscan_bool']
        Scan_Scope_bool = SET['Scan_Scope_bool']
        scan_records_BruteForce = SET['BruteForce']
                    
        Scan_IPV_Scope_bool = SET['Scan_IPV_Scope_bool']
        Scan_DomainName_Scope_bool = SET['Scan_DomainName_Scope_bool']
        scan_records_censys=  SET['scan_records_censys']
        crtshSearch_bool = SET['crtshSearch_bool']
        Update_RecordsCheck = SET['Update_RecordsCheck']
        LoopCustomersBool= SET['LoopCustomersBool']
        BruteForceBool = SET['BruteForce']
        BruteForce_WL = SET['BruteForce_WL']
        try:
            record_List_store=[]
            if type(domain) is None:
                pass
            elif SET['Scan_IPV_Scope_bool'] == True:
                ipvSomething = domain
                domains= domain.get('Ipv')
                record_List = []
                for domain in domains:
                    if Ego_IP.validIPAddress(domain) == True:
                        a= domain
                        if type(a) is str:
                            if auth_token_json:
                                ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key,SET=SET, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                record_List.append(ipv_scan)

                            else:
                                ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET, HostAddress=HostAddress, Port=Port)
                                record_List.append(ipv_scan)
                        elif type(a) is dict:
                            if auth_token_json:
                                ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                record_List.append(ipv_scan)
                            else:
                                ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                                record_List.append(ipv_scan)
                        else:
                            pass
                results = dask.compute(*record_List)
                record_List_store.append(results)
            elif Scan_DomainName_Scope_bool == True:
        
                domain_set= DomainNameValidation.CREATOR(domain)
                
                if domain_set == False:
                    pass
                else:
                    domainname= domain_set['domainname']
                    FullDomainName= domain_set['fulldomain']
                    skip = False
                    if skip == False:
                        #WHOIS = TLDENUM(FullDomainName, domainname, Customer_key=Customer_key, portscan_bool , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                        w = whois.whois(FullDomainName)
                        WHOISKey = w.keys()
                        if w:
                            if 'expiration_date' in w:
                                del w['expiration_date']
                            if 'creation_date' in w:
                                del w['creation_date']
                            if 'status' in w:
                                del w['status']
                            if 'updated_date' in w:
                                del w['updated_date']
                            if type(w.get('emails')) == str:
                                w.update({"emails": [ w.get('emails') ]})
                            if type(w.get('dnssec')) == str:
                                w.update({"dnssec": [ w.get('dnssec') ]})
                            if type(w.get('address')) == list:
                                address_string = ' '.join(w.get('address'))
                                w.update({"address": address_string})
                            updatewhoisurl = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/whois/create"
                            w.update({"customer_id": Customer_key.get('Customer_id')})
                            #whois_dic = dict.fromkeys(['whois_customers'], w)
                            recs = json.dumps(w, default=EgoReconFunc.serialize_datetime)
                            create_whois = requests.post(updatewhoisurl, data=recs, verify=False, headers=headers)
                            WHOIS =  whois.whois(domainname)
                    if domainname not in DomainNameseen0:
                        if crtshSearch_bool == False:
                            certSearch = None
                        else:
                            Global_Nuclei_CoolDown=(1,300)
                            #Sleep_Generator = round(random.uniform(Global_Nuclei_CoolDown[0], Global_Nuclei_CoolDown[1]), 2)
                            #time.sleep(Sleep_Generator)
                            certSearch= EgoDomainSearch.crtshSearch(domainname, CoolDown_Between_Queries, SCOPED=SCOPED, SET=SET)
                            try:
                                cs= certSearch
                                csbool= bool(cs)
                            except:
                                certSearch = False
                                cs = 'a'
                            if certSearch == False:
                                pass
                            elif certSearch is not None:

                                record_List = []
                                in_scope= cs.get('in_scope',{})
                                for a in in_scope:
                                    if type(a) is str:
                                        if auth_token_json:
                                            ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                            record_List.append(ipv_scan)
                                        else:
                                            ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                                            record_List.append(ipv_scan)
                                    elif type(a) is dict:
                                        if auth_token_json:
                                            ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                            record_List.append(ipv_scan)
                                        else:
                                            ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                                            record_List.append(ipv_scan)
                                    else:
                                        pass
                                results = dask.compute(*record_List)
                                record_List_store.append(results)
                    
                            elif '502 Bad Gateway' in cs:
                                time.sleep(30)
                                pass
                            else:
                                pass
                        if scan_records_censys == False:
                            pass
                        else:
                            censys_Record_List= EgoDomainSearch.censysSearch(domainname, SCOPED, CoolDown, CoolDown_Between_Queries, OutOfScopeString=OutOfScopeString, auth_token_json=auth_token_json)
                            cr= censys_Record_List
                            crbool= bool(cr)
                            if crbool is False:
                                pass
                            else:
                                in_scope= cr.get('in_scope',{})
                                record_List = []
                                for a in in_scope:
                                    if type(a) is str:
                                        dns_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                        record_List.append(dns_scan)
                                    elif type(a) is dict:
                                        if auth_token_json:
                                            ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                            record_List.append(ipv_scan)
                                        else:
                                            ipv_scan= dask.delayed(ToolBox.Uploader)(a, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                                            record_List.append(ipv_scan)
                                    else:
                                        pass
                                results = dask.compute(*record_List)
                                record_List_store.append(results)
                        if bool(scan_records_BruteForce) == False:
                            pass
                        else:
                            Worddsresults = Worddsresults[0]
                            if 'TLD' in Worddsresults.keys():
                                record_List = []
                                prechunkWord = Worddsresults.get('TLD')
                                chunk_size = 6
                                Word_chunks = list(ToolBox.splited(prechunkWord, chunk_size))
                                for values in prechunkWord:
                                    word = values.get('Value').lower()
                                    fqdn = f"{domain_set['DOMAIN']}{word}"
                                    alive = Ego_HostValidation.GetHostNamebyIp(fqdn)
                                    if alive == False:
                                        pass
                                    else:
                                        if auth_token_json:
                                            ip = dask.delayed(EgoReconFunc.TLDENUM)(fqdn,values,domain_set['DOMAIN'], SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , value=WHOIS, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                            record_List.append(ip)
                                        else:
                                            ip = dask.delayed(EgoReconFunc.TLDENUM)(fqdn,values,domain_set['DOMAIN'],SCOPED=SCOPED,  Customer_key=Customer_key, SET=SET , value=WHOIS, HostAddress=HostAddress, Port=Port)
                                            record_List.append(ip)
                                results = dask.compute(*record_List)
                                record_List_store.append(results)
                            else:
                                record_List = []
                                for values in Worddsresults.get('DNS'):
                                    word = values['Value'].lower()
                                    fqdn = f'{word}.{domainname}'
                                    alive = Ego_HostValidation.GetHostNamebyIp(fqdn)
                                    if alive == False:
                                        pass
                                    else:
                                        if auth_token_json:
                                        
                                            ip = dask.delayed(ToolBox.Uploader)(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                            record_List.append(ip)
                                        else:
                                            ip = dask.delayed(ToolBox.Uploader)(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                                            record_List.append(ip)

                                results = dask.compute(*record_List)
                                record_List_store.append(results)
                    else:
                        pass

            else:
                pass
            results = record_List_store
            return results
        except Exception as E:
            print(E)
            print('failed here meow')
            
    def TLDENUM(fqdn, domainname, SCOPED=None, Customer_key=None, SET=None , WHOIS=None, values=None, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=None):
        headers = {"Content-type": "application/json", "Accept": "application/json"}
        fqdn_domain_set = DomainNameValidation.CREATOR(fqdn)
        if WHOIS == None:
            w = whois.whois(fqdn)
            if auth_token_json:
                headers.update(auth_token_json)
            else:
                pass
            w.update({"customer_id": Customer_key.get('Customer_id')})
            recs = json.dumps((w))
            createwhoisurl = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/whois/create"
            create_whois = requests.post(createwhoisurl, data=recs, verify=False, headers=headers)
            return w
        else:
            try:
                WHOISKey = WHOIS.keys()
                w = whois.whois(fqdn)
                if w:
                    if 'expiration_date' in w:
                        del w['expiration_date']
                    if 'creation_date' in w:
                        del w['creation_date']
                    if 'status' in w:
                        del w['status']
                    if 'updated_date' in w:
                        del w['updated_date']
                    child_dic = {}
                    child = [ child_dic.update({k:v}) for k, v in w.items() if v != None and k in WHOISKey]
                    parent_dic = {}
                    parent = [ parent_dic.update({k:v}) for k, v in WHOIS.items() if v != None and k in child_dic]
                    total = fuzz.ratio(child_dic.values(), parent_dic.values())
                    totdic = ({'total': total})
                    w_values = [ x for x in w.values() if x != None ]
                    parent_values = [ x for x in WHOIS.values() if x != None ]
                    DIC_compare = {}
                #######
                    parent_org = WHOIS.get('org')
                    child_org = w.get('org')
                    ratio = {"org": fuzz.ratio(child_org, parent_org)}
                    DIC_compare.update(ratio)
                ########
                    parent_reg = WHOIS.get('registrar')
                    child_reg = w.get('registrar')
                    ratio1 = {"registrar": fuzz.ratio(parent_reg, child_reg)}
                    DIC_compare.update(ratio1)
                ##############
                    parent_reg_org = WHOIS.get('registrant_org')
                    child_reg_org = w.get('registrant_org')
                    ratio2 = {"registrant_org": fuzz.ratio(parent_reg_org, child_reg_org)}
                    DIC_compare.update(ratio2)
                    ratio3 = {"reg&registrantorg": fuzz.ratio(parent_reg, child_reg_org)}
                    DIC_compare.update(ratio3)
                    ratio4 = {"org&registrantorg": fuzz.ratio(parent_reg_org, child_reg)}
                    DIC_compare.update(ratio4)
                ####################
                    compareBoolLoop = [  (k,v) for k,v in DIC_compare.items() if v >= 37 ]
                    if compareBoolLoop:
                        headers = {"Content-type": "application/json", "Accept": "application/json"}
                        url = f"https://{fqdn}"
                        bad_content = ["subdomain.com", "Copyright \u00A9 2023 Subdomain.com. All Rights Reserved."]
                        try:
                            ip = requests.get(url, verify=False, allow_redirects=True, timeout=1)
                            text = ip.text
                            resp_headers= ip.headers
                        except:
                            text = False
                            resp_headers = False
                        if resp_headers:
                            if 'Locations' in resp_headers:
                                if any( x not in text for x in bad_content):
                        
                                    location = resp_headers.get('Locations').replace('https://','').replace('http://', '').replace(r'\/.*(?=\/.*?)',"")
                                    location_domain_set = DomainNameValidation.CREATOR(location)
                                    if fqdn_domain_set['DOMAIN'] == location_domain_set['DOMAIN']:
                                        update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/create/{Customer_key.get('Customer_id')}"
                                        if auth_token_json:
                                            headers.update(auth_token_json)
                                        else:
                                            pass
                                        w.update({"customer_id": Customer_key.get('Customer_id')})
                                        recs = json.dumps(w)
                                        createwhoisurl = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/whois/create/"
                                        create_whois = requests.post(createwhoisurl, data=recs, verify=False, headers=headers)
                                        results = requests.get(update_url, verify=False, headers=headers)
                                        rjson = results.json()
                                        KnownTLD = rjson.get('FoundTLD')
                                        if KnownTLD == None:
                                            try:
                                                found_dic = dict.fromkeys(['FoundTLD'], [f"*.{fqdn}"] + KnownTLD)
                                                recs = json.dumps(found_dic)
                                                update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/create/{Customer_key.get('Customer_id')}"
                                                headers.update(auth_token_json)
                                                requ =  requests.patch(update_url, data=recs, headers=headers)
                                            except Exception as E:
                                                print('failed known tld')
                                        else:
                                            if fqdn in KnownTLD:
                                                pass
                                            else:
                                                try:
                                                    found_dic = dict.fromkeys(['FoundTLD'], [f"*.{fqdn}"] + KnownTLD)
                                                    recs = json.dumps(found_dic)

                                                    update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/create/{Customer_key.get('Customer_id')}"
                                                    headers.update(auth_token_json)
                                                    requ =  requests.patch(update_url, data=recs, headers=headers)
                                                except Exception as E:
                                                    print(E)
                                            #time.sleep(0.05)
                                            dic = {}
                                            found_known = values['foundAt'].append(domainname)
                                            new_Occurance = str(int(values['Occurance']) + 1)
                                            oc_dict = dict.fromkeys(['Occurance'],new_Occurance)
                                            values.update(oc_dict)
                                            values.update({"Occurance":new_Occurance})
                                            dic.update(oc_dict)
                                            dic.update({"Occurance":new_Occurance})
                                            known_domain = values['foundAt']
                                            known_domain.append(domainname)
                                            found_dic = dict.fromkeys(['foundAt'], known_domain)
                                            dic.update(found_dic)
                                            update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/WordList/{values['id']}"
                                            
                                            recs = json.dumps(dic)
                                            requ =  requests.patch(update_url, data=recs, headers=headers)
                                            if auth_token_json:
                                                dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                            else:
                                                dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                                                return dns_scan
                                    else:
                                        pass
                                else:
                                    pass
                            elif text:
                                if any( str(x.lower()) in text.lower() for x in bad_content):
                                    pass
                                else:
                                    update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/create/{Customer_key.get('Customer_id')}"
                                    if auth_token_json:
                                        headers.update(auth_token_json)
                                    else:
                                        pass
                                    results = requests.get(update_url, verify=False, headers=headers)
                                    rjson = results.json()
                                    KnownTLD = rjson.get('FoundTLD')
                                    if KnownTLD == None:
                                        try:
                                            found_dic = dict.fromkeys(['FoundTLD'], [f"*.{fqdn}"] + KnownTLD)
                                            recs = json.dumps(found_dic)
                                            update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/create/{Customer_key.get('Customer_id')}"
                                            headers.update(auth_token_json)
                                            requ =  requests.patch(update_url, data=recs, headers=headers)
                                        except Exception as E:
                                            print(E)
                                    else:
                                        if fqdn in KnownTLD:
                                            pass
                                        else:
                                            try:
                                                found_dic = dict.fromkeys(['FoundTLD'], [f"*.{fqdn}"] + KnownTLD)
                                                recs = json.dumps(found_dic)
                                                update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/create/{Customer_key.get('Customer_id')}"
                                                headers.update(auth_token_json)
                                                requ =  requests.patch(update_url, data=recs, headers=headers)
                                            except Exception as E:
                                                print(E)
                                        #time.sleep(0.05)
                                        dic = {}
                                        found_known = values['foundAt'].append(domainname)
                                        new_Occurance = str(int(values['Occurance']) + 1)
                                        oc_dict = dict.fromkeys(['Occurance'],new_Occurance)
                                        values.update(oc_dict)
                                        values.update({"Occurance":new_Occurance})
                                        dic.update(oc_dict)
                                        dic.update({"Occurance":new_Occurance})
                                        known_domain = values['foundAt']
                                        known_domain.append(domainname)
                                        found_dic = dict.fromkeys(['foundAt'], known_domain)
                                        dic.update(found_dic)
                                        update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/WordList/{values['id']}"
                                            
                                        recs = json.dumps(dic)
                                        requ =  requests.patch(update_url, data=recs, headers=headers)
                                        if auth_token_json:
                                            dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                        else:
                                            dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                                            return dns_scan
                            else:
                                pass
                        else:
                    
                            update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/create/{Customer_key.get('Customer_id')}"
                            if auth_token_json:
                                headers.update(auth_token_json)
                            else:
                                pass
                            results = requests.get(update_url, verify=False, headers=headers)
                            rjson = results.json()
                            KnownTLD = rjson.get('FoundTLD')
                            if KnownTLD == None:
                                try:
                                    found_dic = dict.fromkeys(['FoundTLD'], [f"*.{fqdn}"] + KnownTLD)
                                    recs = json.dumps(found_dic)
                                    update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/create/{Customer_key.get('Customer_id')}"
                                    headers.update(auth_token_json)
                                    requ =  requests.patch(update_url, data=recs, headers=headers)
                                except Exception as E:
                                    print(E)
                            time.sleep(0.05)
                            dic = {}
                            found_known = values['foundAt'].append(domainname)
                            new_Occurance = str(int(values['Occurance']) + 1)
                            oc_dict = dict.fromkeys(['Occurance'],new_Occurance)
                            values.update(oc_dict)
                            values.update({"Occurance":new_Occurance})
                            dic.update(oc_dict)
                            dic.update({"Occurance":new_Occurance})
                            known_domain = values['foundAt']
                            known_domain.append(domainname)
                            found_dic = dict.fromkeys(['foundAt'], known_domain)
                            dic.update(found_dic)
                            update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/WordList/{values['id']}"
                                            
                            recs = json.dumps(dic)
                            requ =  requests.patch(update_url, data=recs, headers=headers)
                            if auth_token_json:
                                dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                            else:
                                dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                            return dns_scan

                    else:
                        return False
                else:
                    pass
            except (whois.parser.PywhoisError):  #NOT FOUND
                return False

    def serialize_datetime(obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        raise TypeError("Type not serializable")

        



class EgoCert:
    def Convert(tup, 
                SET=None,
                SCOPED=None,
                Customer_key=None, 
                portscan_bool=None, 
                versionscan_bool=None, 
                CoolDown_Between_Queries=None, 
                HostAddress=None, 
                Port=5000, 
                auth_token_json=None):
        results= {}
        for k in tup:
            try:
                stuff = tup.get(k)
                if type(stuff) == tuple:
                    for x in stuff:
                        if k == 'subjectAltName':
                            if ('subjectAltName') in results.keys():
                                stuff = x[1:][0]
                                if any(x in stuff for x in None):
                                    if auth_token_json:
                                        dns_scan= ToolBox.Uploader(stuff, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                    else:
                                        dns_scan= ToolBox.Uploader(stuff, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET, HostAddress=HostAddress, Port=Port)                               
                                    results['subjectAltName'].append(stuff) 
                                else:
                                    pass
                            else:
                                stuff = {k: [y[1:][0] for y in stuff]}
                                results.update(stuff)                        
                        elif k == 'subject':
                            stuff = {x[0][0]:x[0][1]} 
                            results.update(stuff)
                        elif k == 'issuer':
                            stuff = {x[0][0]:x[0][1]} 
                            results.update(stuff)
                        else:
                            stuff = {k:x} 
                            results.update(stuff)
            except Exception as E:
                print(E)
                pass
        return results
     
    def certRipper(data,SET=None, SCOPED=None, Customer_key=None, portscan_bool=None, versionscan_bool=None, CoolDown_Between_Queries=None, HostAddress=None, Port=None, auth_token_json=None):
        # data is a dictionary
        print('certRippercertRipper3certRipper3certRipperce3rtRippe3rcertRipper3certRipp3ercertRippe3rcert3RippercertRi3pper')
        KeyAlive= ['CertBool']
        try:
            if data:
                DIC = {}
                ports = data.get('OpenPorts')
                try:
                    hostname = [data.get('subDomain')]
                except:
                    hostname = data.get('ip')
                KeyCert= ['Certificate']
                if '443' in ports:
                    for host in hostname:
                        port= 443
                        store=[]
                        seen=[]
                        serverAddress = (host, port)
                        cert = ssl.get_server_certificate(serverAddress)
                        cert_key= ['PEM']
                        certificate_pem= dict.fromkeys(cert_key,cert)
                        ctx = ssl.create_default_context()
                        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                            s.connect((host, port))
                            cert = s.getpeercert()
                        CertStuff = EgoCert.Convert(cert,
                                                    SCOPED=SCOPED,
                                                    SET=SET,
                                            Customer_key=Customer_key, 
                                            portscan_bool=None, 
                                            versionscan_bool=None, 
                                            CoolDown_Between_Queries=None, 
                                            HostAddress=None, 
                                            Port=5000, 
                                            auth_token_json=None)
                        if CertStuff not in seen:
                            seen.append(CertStuff)
                            aliveResults= dict.fromkeys(KeyAlive,True)
                            DIC.update(aliveResults)
                            DIC.update(certificate_pem)
                            DIC.update(CertStuff)
                            store.append(CertStuff)
                        else:
                            results= dict.fromkeys(KeyAlive,False)
                            DIC.update(results)
                            
                        if store:
                            aliveResults= dict.fromkeys(KeyAlive,True)
                            DIC.update(aliveResults)
                            results= dict.fromkeys(KeyCert,store[0])
                            DIC.update(results)
                        else:
                            results= dict.fromkeys(KeyAlive,False)
                            DIC.update(results)
                    return DIC
                else:
                    results= dict.fromkeys(KeyAlive,False)
                    DIC.update(results)
                    return DIC
            else:
                results= dict.fromkeys(KeyAlive,False)
                DIC.update(results)
                return DIC
        except Exception as E:
            print('certRipper')
            print(E)
            results= dict.fromkeys(KeyAlive,False)
            DIC.update(results)
            return DIC

class Ego_HostValidation:

    def GetHostNamebyIp(data):
        try:
            Hostname_Domainname = socket.gethostbyaddr(data)
            if 'Unknown host' in Hostname_Domainname:
                return False
            else:
                return Hostname_Domainname[0]
        except Exception as E:
            return False

    def HostNameBool(data):

        try:
            ip = socket.gethostbyname_ex(data)
            if ip[0] == '1':
                pass
            else:
                alive= dict.fromkeys(["alive"],True)
                ip= dict.fromkeys(["ip"],ip[2])
                alive.update(ip)
                return alive
        except Exception:
            alive= dict.fromkeys(["alive"],False)
            return alive

class ToolBox:

    def ASN(values):

        try:
            result = asndb.lookup(values)
            if str(result[0]) and result[1]:
                cidr = str(result[0])
                asn = result[1]
            else:
                cidr = "None"
                asn = 'None'
            return([cidr, asn])
                
        except Exception as E:
            return False  
        
    def GeoCodes(values, record_id,  HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=None):
        time.sleep(2)
        if type(values) is list:
            for value in values:
                try:
                    
                    response = DbIpCity.get(value, api_key='free')
                    responsejson = json.loads(response.to_json())
                    responsejson.update({"latitude": f"{responsejson['latitude']}"})
                    responsejson.update({"longitude": f"{responsejson['longitude']}"})
                    record_dict = dict.fromkeys(['record_id'], record_id)
                    responsejson.update(record_dict)
                    recs = json.dumps(responsejson)
                    url = f"{EgoSettings.HostAddress}:{Port}/api/GEOCODES/create/"
                    headers = {"Content-type": "application/json", "Accept": "application/json"}
                    if auth_token_json is not None:
                        headers.update(auth_token_json)
                        request = requests.post(url, headers=headers, data=recs, verify=False)
                    else:
                        request = requests.post(url, headers=headers, data=recs, verify=False)
                except Exception as E:
                    print(E)
            return True
        else:
            try:
                response = DbIpCity.get(values, api_key='free')
                responsejson = json.loads(response.to_json())
                responsejson.update(record_id)
                url = f"{EgoSettings.HostAddress}:{Port}/api/GEOCODES/create/"
                headers = {"Content-type": "application/json", "Accept": "application/json"}
                if auth_token_json is not None:
                    headers.update(auth_token_json)
                    request = requests.post(url, headers=headers, data=responsejson, verify=False)
                else:
                    request = requests.post(url, headers=headers, data=response, verify=False)
                
            except Exception as E:
                print(E)
            return True

    def Selenium(url):
        try:
            ## Setup chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless") # Ensure GUI is off
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument('--disable-dev-shm-usage')
            # Set path to chromedriver as per your configuration
            driver = webdriver.Chrome(executable_path=r"/mnt/e/tools/0_Secret_lab/EGO_old/ego7/EGO/chromedriver/stable/chromedriver", options=chrome_options)
            driver.get(f"https://{url}")
            driver.save_screenshot(f"/mnt/e/tools/0_Secret_lab/EGO_old/ego7/egodev/RecordPictures/{uuid.UUID}.png")
            return (f"/mnt/e/tools/0_Secret_lab/EGO_old/ego7/egodev/RecordPictures/{uuid.UUID}.png")
        except Exception as E:
            print(E)
            return False

    def RandomTime(time=(6,60)):
        return round(random.uniform(time[0], time[1]), 2)

    def html_parse(strings):
        out_results = []
        for string in strings:
            if type(string) == list:
                string_parse = string[0]
            else:
                string_parse = string
            if type(string_parse) is tuple:
                string = string_parse
                if 'http' in string[0] :
                    parameters = re.findall('(\?|\&)([^=]+)\=([^&]+)', string[2])
                    if parameters:
                        stripped_Parms = [ {"key": n[1], "value": n[2]} for n in parameters ]
                    else:
                        stripped_Parms = ["None"]
                    complete = {"schema": string[0], "domain": string[1], 'path': [{"path_values": string[2], "parameters": stripped_Parms}] }
                    if complete.get('domain') in str(out_results):
                        [ (i['path'].append(complete.get('path')[0])) for i in out_results ]
                    elif bool(out_results) == False:
                        out_results.append(complete)
                    else:
                        pass
                elif string[1]:
                    parameters = re.findall('(\?|\&)([^=]+)\=([^&]+)', string[2])
                    if parameters:
                        stripped_Parms = [ {"key": n[1], "value": n[2]} for n in parameters ]
                    else:
                        stripped_Parms = ["None"]
                    complete = {"schema": "https", "domain": string[1], 'path': [{"path_values": string[2], "parameters": stripped_Parms}] }
                    if complete.get('domain') in str(out_results):
                        [ (i['path'].append(complete.get('path')[0])) for i in out_results ]
                    elif bool(out_results) == False:
                        out_results.append(complete)
                    else:
                        pass
                else:
                    parameters = re.findall('(\?|\&)([^=]+)\=([^&]+)', string[2])
                    stripped_Parms = [ {"key": n[1], "value": n[2]} for n in parameters ]
                    complete = { 'path': [{"path_values": string[2], "parameters": stripped_Parms }] }
                    if out_results:
                        out_results.append(complete)          
                    else:
                        out_results.append(complete.get('path'))
            else:
                complete = {"schema": string[0], "domain": string[1]}
                if complete.get('domain') in str(out_results):
                    out_results.append(complete)
                elif bool(out_results) == False:
                    out_results.append(complete)
                else:
                    parameters = re.findall('(\?|\&)([^=]+)\=([^&]+)', string)
                    stripped_Parms = [ {"key": n[1], "value": n[2]} for n in parameters ]
                    complete = { 'path': [{"path_values": string[2], "parameters": [stripped_Parms]}] }

                    if out_results:
                        [ y['path'].append(complete.get('path')[0]) for y in out_results if y ]           
                    else:
                        out_results.append(complete)
        return(out_results)




    def MantisRequester(domain, 
                        record_id, 
                        SET=None,
                        Customer_key=None,
                        SCOPED=None, 
                        depth=0, 
                        path=None, 
                        method='GET', 
                        data=None, 
                        postData=None, 
                        proxy=None, 
                        debug=False, 
                        allow_redirects=True, 
                        additional_headers=None, 
                        HostAddress=EgoSettings.HostAddress, 
                        Port=EgoSettings.Port, 
                        auth_token_json=None,
                        GRandTime=30,
                        CoolDown_Between_Queries=None):
        seen =[]
        portscan_bool = SET['portscan_bool']
        versionscan_bool = SET['versionscan_bool']
        depth = depth
        url = f"https://{domain}/"
        with requests.Session() as session:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"}
            if additional_headers:
                headers_dic = dict(additional_headers[0])
                headers.update(headers_dic)
                if str(additional_headers) != str(headers):
                    headers.update({
                        # Retrieve the headers configured as extra headers but not controlled
                        # by the application in this specific request
                        h_name: h_value
                        for h_name, h_value in additional_headers[0].items()
                        if h_name not in headers
                    })

            if not proxy:
                proxy = {}
            else:
                pass
            if method == 'GET':
                #sleep_gen = ToolBox.RandomTime()
                #time.sleep(sleep_gen)                
                resp = requests.get(url, headers=headers, proxies=proxy, verify=False, timeout=GRandTime, allow_redirects=allow_redirects)
                cookies = dict(resp.cookies)
                headers = dict(resp.headers)
                #byte data
                html_store = resp.content
                #string data
                text = resp.text
                #beautiful soup
                raw_html = dict.fromkeys(['rawHTML'], text)
                PathOrDomain = dict.fromkeys(['htmlValues'], html_store)
                object_store = []
                recorded_domains = []
                hout = { "InScope": [], "Buckets": [], "AWSObject": [] , "OutScope": [], "Azure": [] }
                out = { "InScope": [], "Buckets": [], "AWSObject": [] , "OutScope": [], "Azure": [] }
                p= domain
                html = html_store 
                if headers:
                    csp = headers.get('Content-Security-Policy')
                    cspRO = headers.get('Content-Security-Policy-Report-Only')
                    if csp:
                        csp=csp
                    else:
                        csp = headers.get('content-security-policy')
                    if csp:
                        csp = csp.replace('\'','').split()
                        for c in csp:
                            regex = r"^(.*:\/\/)?([\*A-Za-z0-9\-\.]+\.\w+)(:[0-9]+)?(.*)$"
                            found = re.findall(regex, str(c))
                            if found:
                                found = found
                                foundProcessed = ToolBox.html_parse(found)
                                for x in foundProcessed:
                                    domain = x.get('domain')
                                    if bool(domain) == False:
                                        pass     
                                    elif 'cloudfront' in str(domain) and domain.lower() not in out['Buckets']:
                                        
                                        out['Buckets'].append(domain)
                                    elif 'amazonaws' in str(domain) and domain.lower() not in out['AWSObject']:
                                        out['AWSObject'].append(domain)
                                    elif 'azure' in str(domain) and domain.lower() not in out['Azure']:
                                        out['Azure'].append(domain)                                    
                                    elif any( x in domain for x in SCOPED):
                                        out['InScope'].append(x)
                                        if auth_token_json:
                                            dns_scan= ToolBox.Uploader(domain, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                        else:
                                            dns_scan= ToolBox.Uploader(domain, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET, HostAddress=HostAddress, Port=Port)
                                    else:
                                        pass

                            else:
                                pass
                                #found
                        
                    elif cspRO:                  
                        csp = cspRO.replace('\'','').split()
                        for c in csp:
                            regex = r"^(.*:\/\/)?([\*A-Za-z0-9\-\.]+\.\w+)(:[0-9]+)?(.*)$"
                            found = re.findall(regex, str(c))
                            if found:
                                found = found
                                foundProcessed = ToolBox.html_parse(found)
                                for x in foundProcessed:
                                    domain = x.get('domain')
                                    if bool(domain) == False:
                                        pass     
                                    elif 'cloudfront' in str(domain) and domain.lower() not in out['Buckets']:
                                        out['Buckets'].append(domain)
                                    elif 'amazonaws' in str(domain) and domain.lower() not in out['AWSObject']:
                                        out['AWSObject'].append(domain)
                                    elif 'azure' in str(domain) and domain.lower() not in out['Azure']:
                                        out['Azure'].append(domain)                                    
                                    elif any( x in domain for x in SCOPED):
                                        out['InScope'].append(x)
                                        if auth_token_json:
                                            dns_scan= ToolBox.Uploader(domain, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                        else:
                                            dns_scan= ToolBox.Uploader(domain, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET, HostAddress=HostAddress, Port=Port)
                                    else:
                                        pass
                            else:
                                pass
                                #found
                    else:
                        pass
                        #csp
                else:
                    pass

                if html:
                    soup = BeautifulSoup(html, 'html.parser')
                    href = [a.get('href') for a in soup.find_all('a')]    
                    regex = r"(\w+):\/\/([\w\-\.]+)(\/...+)"
                    found = [ re.findall(regex, h) for h in href if h ]
                    found = [ ('https',domain,(f[0])[2]) for f in found if f and len(f) == 1 ]
                    if len(found) > 0:
                        found = found
                        foundProcessed = ToolBox.html_parse(found)
                        for x in foundProcessed:
                            x=x
                            try:
                                domain= x.get('domain')
                            except:
                                domain = False
                            if bool(domain) == False:
                                pass                      
                            elif 'cloudfront' in str(domain) and domain.lower() not in out['Buckets']:
                                out['Buckets'].append(domain)
                            elif 'amazonaws' in str(domain) and domain.lower() not in out['AWSObject']:
                                out['AWSObject'].append(domain)
                            elif 'azure' in str(domain) and domain.lower() not in out['Azure']:
                                out['Azure'].append(domain)                            
                            elif any( x in domain for x in SCOPED):
                                if domain in seen:
                                    pass
                                else:
                                    seen.append(domain)
                                    out['InScope'].append(x)

                            else:
                                pass
                                #found
                    else:
                        pass
                        #csp
                else:      
                    pass
                NEWDIC = {}
                NEWDIC.update(out)
                NEWDIC.update(hout)
                for item in NEWDIC.get('InScope'):
                    schema = item.get('schema')
                    domain = item.get('domain')
                    paths = item.get('path')
                    # needs parm add for complete page resolution sometimes params you know chicken anwyho do this important
                    # fix it later
                    urls = [f"{schema}://{domain}{path.get('path_values')}" for path in paths]
                    length = len(urls)
                    for url in urls:
                        try:
                            #sleep_gen = ToolBox.RandomTime()
                            #time.sleep(sleep_gen)                        
                            resp = requests.get(url, proxies=proxy, verify=False, timeout=GRandTime, allow_redirects=allow_redirects)
                            cookies = dict(resp.cookies)
                            headers = dict(resp.headers)
                            #byte data
                            html = resp.content
                            #string data
                            text = resp.text
                            #beautiful soup
                            
                            raw_html = dict.fromkeys(['rawHTML'], text)
                            PathOrDomain = dict.fromkeys(['htmlValues'], html)
                            object_store = []
                            recorded_domains = []
                            p= domain

                            if headers:
                                try:
                                    csp = re.headers(' ', csp)
                                except:
                                    csp = False
                                if csp:
                                    for c in csp:
                                        
                                        regex = r"^(.*:\/\/)?([\*A-Za-z0-9\-\.]+\.\w+)(:[0-9]+)?(.*)$"
                                        found = re.findall(regex, str(c))
                                        if found:
                                            found = found
                                            foundProcessed = ToolBox.html_parse(found)
                                            for x in foundProcessed:
                                                domain = x.get('domain')
                                                if bool(domain) == False:
                                                    pass
                                                elif 'cloudfront' in domain.lower() and x.get('domain').lower() not in out['Buckets']:
                                                    out['Buckets'].append(domain)
                                                elif 'amazonaws' in domain.lower() and x.get('domain').lower() not in out['AWSObject']:
                                                    out['AWSObject'].append(domain)
                                                elif 'azure' in domain.lower() and x.get('domain').lower() not in out['Azure']:
                                                    out['Azure'].append(domain)                                                
                                                elif any( x in domain for x in SCOPED ):
                                                    out['InScope'].append(x)
                                                    if auth_token_json:
                                                        dns_scan= ToolBox.Uploader(domain, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                                    else:
                                                        dns_scan= ToolBox.Uploader(domain, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET, HostAddress=HostAddress, Port=Port)
                                                else:
                                                    pass
                                        else:
                                            pass
                                else:
                                    pass
                            else:
                                pass
                            if html:
                                soup = BeautifulSoup(html, 'html.parser')
                                href = [a.get('href') for a in soup.find_all('a')]    
                                regex = r"(\w+):\/\/([\w\-\.]+)(\/...+)"
                                found = [ re.findall(regex, h) for h in href if h ]
                                found = [ f for f in found if f ]
                                if len(found) > 0:
                                    found = found
                                    foundProcessed = ToolBox.html_parse(found)
                                    for x in foundProcessed:
                                        domain= x.get('domain')
                                        path = x.get('path')
                                        if bool(domain) == False:
                                            hout['InScope'].append(x.get('path'))
                                        elif 'cloudfront' in domain.lower() and domain.lower() not in out['Buckets']:
                                            hout['Buckets'].append(domain)
                                        elif 'amazonaws' in domain.lower() and domain.lower() not in out['AWSObject']:
                                            hout['AWSObject'].append(domain)
                                        elif 'azure' in domain.lower() and domain.lower() not in out['Azure']:
                                            hout['Azure'].append(domain)                                            
                                        elif any( x in domain for x in SCOPED):
                                            hout.append(x)  
                                            for z in hout['InScope']:
                                                scope_domain = z.get('domain') 
                                                knownPaths = str(z.get('path'))
                                                if scope_domain == None:
                                                    pass
                                                elif scope_domain in domain:
                                                    if len(path) > 0:
                                                        if any(p.get('path_values') == q for q in knownPaths for p in path):
                                                            pass
                                                        else:
                                                            z['path'].append(x.get('path'))
                                                    else:
                                                        pass
                                                else:
                                                    pass
                                        else:
                                            pass
                                else:
                                    pass
                            else:
                                pass
                        except:
                            pass
                PathOrDomain = dict.fromkeys(['htmlValues'], hout )
                csp_dict = dict.fromkeys(['headerValues'], out )
                #href = [ html['href'] for html in soup ]
                status_dict = dict.fromkeys(['status'], resp.status_code)
                header_dict = dict.fromkeys(['headers'], headers)
                cookies_dict = dict.fromkeys(['cookies'], cookies)
                path_dict = dict.fromkeys(['paths'], [])
                recordId_id = dict.fromkeys(['record_id'], record_id)
                object_dict = dict.fromkeys(['FoundObjects'], object_store)
                try:    
                    if bool(headers['location']):
                        redirect_dict = dict.fromkeys(['location'], True)
                    else:
                        redirect_dict  = dict.fromkeys(['location'], False)
                except:
                    pass
                DIC ={}
                DIC.update(object_dict)
                DIC.update(csp_dict)
                DIC.update(raw_html)
                DIC.update(PathOrDomain)                        
                DIC.update(status_dict)
                DIC.update(header_dict)
                #DIC.update(href)
                DIC.update(status_dict)
                DIC.update(cookies_dict)
                DIC.update(path_dict)
                RAW_MD5= hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()
                md5_dict = dict.fromkeys(['md5'], RAW_MD5)
                DIC.update(md5_dict)
                DIC.update(recordId_id)
                recs = json.dumps(DIC)
                urls = f"{EgoSettings.HostAddress}:{Port}/api/RequestMetaData/create/"
                headers = {"Content-type": "application/json", "Accept": "application/json"}
                headers.update(auth_token_json)
                request = requests.post(urls, data=recs, headers=headers, verify=False)
                return(out)

    def PostRequests(url,headers=None,data=None):

        try:
            Global_Nuclei_CoolDown=(1,50)
            Sleep_Generator = round(random.uniform(Global_Nuclei_CoolDown[0], Global_Nuclei_CoolDown[1]), 2)
            time.sleep(Sleep_Generator)
            resp = requests.post(url,headers=headers,data=data)
            return resp
        except Exception as E:
            print(E)

    def clean_newlines(data):
        return data.strip('\n')

    def splited(list_a, chunk_size):
        if list_a == None:
            pass
        else:
            results= []
            for i in range(0, len(list_a), chunk_size):
              chunk= list_a[i:i + chunk_size]
              results.append(chunk)
            return results 
    
    def Uploader(a, SCOPED=None, SET=None, CoolDown_Between_Queries=2, Customer_key=None, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, OutOfScopeString=None, auth_token_json=None):
        domain_set = DomainNameValidation.CREATOR(a)
        subDomain = domain_set['fulldomain']
        id_EgoControl = SET['id']
        customerId= SET['ScanProjectByID']
        scanPRojectgroup= SET['ScanGroupingProject']
        scanProjectName = SET['ScanProjectByName']
        CoolDown=  SET['CoolDown']
        CoolDown_Between_Queries = SET['CoolDown_Between_Queries']
        Port = SET['Port']
        HostAddress = SET['HostAddress']
        passiveAttack = SET['passiveAttack']
        agressiveAttack = SET['agressiveAttack']
        portscan_bool = SET['portscan_bool']
        versionscan_bool = SET['versionscan_bool']
        Scan_Scope_bool = SET['Scan_Scope_bool']
        scan_records_BruteForce = SET['BruteForce']
        Scan_IPV_Scope_bool = SET['Scan_IPV_Scope_bool']
        Scan_DomainName_Scope_bool = SET['Scan_DomainName_Scope_bool']
        scan_records_censys=  SET['scan_records_censys']
        crtshSearch_bool = SET['crtshSearch_bool']
        Update_RecordsCheck = SET['Update_RecordsCheck']
        LoopCustomersBool= SET['LoopCustomersBool']
        BruteForceBool = SET['BruteForce']
        BruteForce_WL = SET['BruteForce_WL']
        try:
            if subDomain in seen:
                pass
            else:
                seen.append(subDomain)
                headers = {"Content-type": "application/json", "Accept": "application/json"}
                if a is None:
                    pass
                else:
                    DIC= {}
                    if type(a) is str:
                        #
                        #
                        #       IP STUFF
                        #
                        #
                        if Ego_IP.validIPAddress(a) == True:
                            DomainName = Ego_HostValidation.GetHostNamebyIp(a)
                            DIC = {}
                            ip = dict.fromkeys(['ip'],a)
                            DIC.update(ip)
                            HostName= Ego_HostValidation.HostNameBool(a)
                            aliveBool= HostName['alive']
                            DIC.update(HostName)
                            if type(a) == list:
                                asn_store = []
                                for b in a:
                                    n = ToolBox.ASN(b)
                                    asn_store.append(n)
                                asn = asn_store
                            else:
                                asn = ToolBox.ASN(a)
                            if asn == False:
                                asnDict = dict.fromkeys(["ASN"], [])
                            else:
                                asnDict = dict.fromkeys(["ASN"], asn)
                            DIC.update(asnDict)
                            # alive bool
                            if aliveBool == False:
                                pass
                            else:
                                for a in DIC:
                                    portscan_bool = True
                                    versionscan_bool_before_version = False
                                    nmap_scan= EgoNmap.NmapScan(DIC, portscan_bool, versionscan_bool_before_version, auth_token_json=auth_token_json)
                                    if nmap_scan is None:
                                        pass
                                    else:
                                        DIC.update(nmap_scan)
                                    if DomainName == False:
                                        cert= EgoCert.certRipper(DIC, SET=SET, portscan_bool=portscan_bool, versionscan_bool=versionscan_bool, CoolDown_Between_Queries=CoolDown_Between_Queries , SCOPED=SCOPED, Customer_key=Customer_key, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                        CertBool= cert['CertBool']
                                        CertBool_set= dict.fromkeys(['CertBool'], CertBool)
                                        DIC.update(CertBool_set)
                                        domain_set= dict.fromkeys(['domainname'], "")
                                        DIC.update(domain_set)
                                        subDomain_set= dict.fromkeys(['subDomain'], "") 
                                        DIC.update(subDomain_set)
                                        md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()
                                        results = dict.fromkeys(['md5'],md5_hash)
                                        DIC.update(results)
                                        record_id= dict.fromkeys(['customer_id'], Customer_key['Customer_id'])

                                        DIC.update(record_id)

                                        recs= json.dumps(DIC)

                                        DIC_headers = {}
                                        #DIC_headers.update(auth_token_json)
                                        DIC_headers.update(headers)
                                        urlPost = f"{EgoSettings.HostAddress}:{Port}/api/records/create/" 
                                        if auth_token_json:
                                            DIC_headers.update(auth_token_json)
                                        responseRecords = requests.post(urlPost, data=recs, headers=DIC_headers,verify=False)
                                        jsonresponseRecords = responseRecords.json()
                                        try:
                                            ToolBox.MantisRequester(FullDomainName, jsonresponseRecords['id'], SET=SET, Customer_key=Customer_key, SCOPED=SCOPED, path=None, method='GET', HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json, CoolDown_Between_Queries=CoolDown_Between_Queries)
                                                
                                        except Exception as E:
                                            continue
                                        try:
                                            dnsquery= EgoDns.Dns_Resolver(jsonresponseRecords, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)                                            
                                        except Exception as E:
                                            continue
                                        #try:
                                        #    #ToolBox.GeoCodes(DIC['ip'], jsonresponseRecords['id'],  HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                        #except Exception as E:
                                        #    pass 
                                        status = responseRecords.status_code
                                        if status != 201:
                                            print('201nmap')
                                            pass
                                        elif "record with this already exists." in responseRecords:
                                            print('record with this already exists.')
                                            pass
                                        else:
                                            #nmap
                                            portscan_bool = False
                                            versionscan_bool_before_version = True
                                            print('333333333333333333333333versionscan_bool_before_version3333333333333333333333333333333')
                                            nmap_scan=  EgoNmap.NmapScan(jsonresponseRecords, portscan_bool, versionscan_bool_before_version, auth_token_json=auth_token_json )
                                            #dns
                                            jsonresponseRecords_id= jsonresponseRecords['id']

                                            
                                            portscan_bool_temp = False
                                            dns_id= dict.fromkeys(['record_id'], jsonresponseRecords_id)
                                            DIC.update(dns_id)
                                            # cerrt
                                            if CertBool != False:
                                                jsonresponseRecords_id= jsonresponseRecords['id']
                                                certificate_id= dict.fromkeys(['record_id'], jsonresponseRecords_id)
                                                Certificate_= cert['Certificate']
                                                certificate_id.update(Certificate_) 
                                                md5_hash = hashlib.md5(json.dumps(certificate_id, sort_keys=True).encode('utf-8')).hexdigest()
                                                results = dict.fromkeys(['md5'],md5_hash)
                                                certificate_id.update(results)
                                                DIC_headers = {}
                                                #DIC_headers.update(auth_token_json)
                                                DIC_headers.update(headers)

                                                recs= json.dumps(certificate_id)
                                                certificateurlPost= f"{EgoSettings.HostAddress}:{Port}/api/Certificate/create/"
                                                if bool(auth_token_json):
                                                    DIC_headers.update(auth_token_json)
                                                print('DIC_headersDIC_headersDIC_headersDIC_headers',DIC_headers)
                                                print('DIC_headersDIC_headersDIC_headersDIC_headers',DIC_headers)
                                                print('DIC_headersDIC_headersDIC_headersDIC_headers',DIC_headers)
                                                print('DIC_headersDIC_headersDIC_headersDIC_headers',DIC_headers)
                                                postRecords = requests.post(certificateurlPost, data=(recs), headers=DIC_headers,verify=False)
                                                responseRecords = json.loads(postRecords.text)
                                                return True
                                    else:
                                        print('fffffffffff4444444444versionscan_bool4444444ffffffffffffffffffffff')
                                        cert= EgoCert.certRipper(DIC, SET=SET, portscan_bool=portscan_bool, versionscan_bool=versionscan_bool, CoolDown_Between_Queries=CoolDown_Between_Queries , SCOPED=SCOPED, Customer_key=Customer_key, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                        CertBool= cert['CertBool']
                                    
                                        CertBool_set= dict.fromkeys(['CertBool'], CertBool)
                                        DIC.update(CertBool_set)
                                        domain_set = DomainNameValidation.CREATOR(DomainName)
                                        if domain_set == False:
                                            pass
                                        else:
                                            domainname= domain_set['domainname']
                                            FullDomainName= domain_set['fulldomain']  
                                            domain_set= dict.fromkeys(['domainname'], domainname)
                                            DIC.update(domain_set)
                                            subDomain= dict.fromkeys(['subDomain'], FullDomainName) 
                                            DIC.update(subDomain)
                                            md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()
                                            results = dict.fromkeys(['md5'],md5_hash)
                                            DIC.update(results)
                                            record_id= dict.fromkeys(['customer_id'], Customer_key['Customer_id'])
                                            DIC_headers = {}
                                            #DIC_headers.update(auth_token_json)

                                            DIC_headers.update(headers)
                                            DIC.update(record_id)

                                            recs= json.dumps(DIC)
                                            urlPost = f"{EgoSettings.HostAddress}:{Port}/api/records/create/"   
                                            if bool(auth_token_json):
                                                DIC_headers.update(auth_token_json)
                                            responseRecords = requests.post(urlPost, data=recs, headers=DIC_headers,verify=False)
                                            jsonresponseRecords = json.loads(responseRecords.content)
                                            status = responseRecords.status_code
                                            try:
                                                ToolBox.MantisRequester(FullDomainName, jsonresponseRecords['id'], SET=SET, Customer_key=Customer_key, SCOPED=SCOPED, path=None, method='GET', HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json, CoolDown_Between_Queries=CoolDown_Between_Queries)
                                                
                                            except Exception as E:
                                                pass
                                            try:
                                                dnsquery= EgoDns.Dns_Resolver(jsonresponseRecords, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)                                            
                                            except Exception as E:
                                                pass
                                            #try:
                                                #ToolBox.GeoCodes(DIC['ip'], jsonresponseRecords['id'],  HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                            #except Exception as E:
                                            #    pass                                            
                                            versionscan_bool_before_version = False
                                            #nmap
                                            portscan_bool = False
                                            versionscan_bool_before_version = True
                                            print('versionscan_bool_before_versionversionscan_bgol_before_versionversionscan_bool_gefore_versionversignscan_bool_before_version')
                                            nmap_scan= EgoNmap.NmapScan(jsonresponseRecords, portscan_bool, versionscan_bool_before_version, auth_token_json=auth_token_json )
                                            #dns
                                            print('dnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdns')
                                            jsonresponseRecords_id= jsonresponseRecords['id']
                                            dns_id= dict.fromkeys(['record_id'], jsonresponseRecords_id)
                                            subDomain.update(dns_id)
                                            print('dnsupdatednsupdatednsupdatednsupdatednsupdatednsupdatednsupdatednsupdatednsupdatednsupdatednsupdate')
                                            portscan_bool_temp = False
                                            # cerrt
                                            if CertBool != False:
                                                jsonresponseRecords_id= jsonresponseRecords['id']
                                                certificate_id= dict.fromkeys(['record_id'], jsonresponseRecords_id)
                                                Certificate_= cert['Certificate']
                            
                                                certificate_id.update(Certificate_) 
                                                md5_hash = hashlib.md5(json.dumps(certificate_id, sort_keys=True).encode('utf-8')).hexdigest()
                                                results = dict.fromkeys(['md5'],md5_hash)
                                                certificate_id.update(results)
                                                DIC_headers = {}

                                                #DIC_headers.update(auth_token_json)
                                                DIC_headers.update(headers)
                                                recs= json.dumps(certificate_id)
                                                certificateurlPost= f"{EgoSettings.HostAddress}:{Port}/api/Certificate/create/"
                                                if bool(auth_token_json):
                                                    DIC_headers.update(auth_token_json)
                                                postRecords = requests.post(certificateurlPost, data=(recs), headers=DIC_headers,verify=False)
                                                responseRecords = postRecords.json()
                                                return True
                        else:
                            domain_set= DomainNameValidation.CREATOR(a)
                            if domain_set == False:
                                pass
                            else:
                                domainname= domain_set['domainname']
                                domainname_dict= dict.fromkeys(['domainname'], domainname)
                                DIC.update(domainname_dict)
                                FullDomainName= domain_set['fulldomain']  
                                subDomain= dict.fromkeys(['subDomain'], FullDomainName) 
                                DIC.update(subDomain)
                                HostName= Ego_HostValidation.HostNameBool(FullDomainName)
                                DIC.update(HostName)
                                aliveBool= HostName['alive']
                                if aliveBool == False:
                                    md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()
                                    record_id= dict.fromkeys(['customer_id'], Customer_key['Customer_id'])
                                    md5_dicft = dict.fromkeys(['md5'],md5_hash)
                                    DIC.update(md5_dicft)
                                    DIC_headers = {}
                                    #DIC_headers.update(auth_token_json)
                                    DIC_headers.update(headers)
                                    DIC.update(record_id)
                                    recs= json.dumps(DIC)
                                    urlPost = f"{EgoSettings.HostAddress}:{Port}/api/records/create/"    
                                    if bool(auth_token_json):
                                        DIC_headers.update(auth_token_json)
                                    postRecords = requests.post(urlPost, data=recs, headers=DIC_headers,verify=False)
                                    jsonresponseRecords = postRecords.json()

                                    pass
                                else:
                                    portscan_bool = True
                                    versionscan_bool_before_version = False
                                    nmap_scan= EgoNmap.NmapScan(DIC, portscan_bool, versionscan_bool_before_version, auth_token_json=auth_token_json )
                                    if nmap_scan is None:
                                        pass
                                    else:
                                        
                                        DIC.update(nmap_scan)
                                        print('4444444444444ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                                        cert= EgoCert.certRipper(DIC, SET=SET, portscan_bool=portscan_bool, versionscan_bool=versionscan_bool, CoolDown_Between_Queries=CoolDown_Between_Queries ,Customer_key=Customer_key, SCOPED=SCOPED, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                        if cert == 'None' or type(cert) is None:
                                            print('certNonecertNonecertNonecertNonecertNonecertNonecertNonecertNonecertNonecertNone')
                                            print('certNonecertNonecertNonecertNonecertNonecertNonecertNonecertNonecertNonecertNone')
                                            print('certNonecertNonecertNonecertNonecertNonecertNonecertNonecertNonecertNonecertNone')
                                            pass
                                        else:
                                            #check for certificate records before attempting to append them
                                            #try:
                                            #    CertificateBool= bool(cert['Certificate'])
                                            #except:
                                            #    CertificateBool= False
                                            # value given by the certripper function
                                      
                                            CertBool= cert['CertBool']
                                            CertBool_set= dict.fromkeys(['CertBool'], CertBool)
                                            DIC.update(CertBool_set)
                                            md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()
                                            results_md5 = dict.fromkeys(['md5'],md5_hash)
                                            DIC.update(results_md5)
                                            Customer_id = Customer_key['Customer_id']
                                            record_id= dict.fromkeys(['customer_id'], Customer_id)

                                            DIC.update(record_id)
                                            DIC_headers = {}
                                            #DIC_headers.update(auth_token_json)
                                            DIC_headers.update(headers)
                                            ipDIC = DIC['ip']
                                            if type(ipDIC) == list:
                                                asn_store = []
                                                for b in ipDIC:
                                                    n = ToolBox.ASN(b)
                                                    asn_store.append(n)
                                                asn = asn_store
                                            else:
                                                asn = ToolBox.ASN(ipDIC)
 

                                            if asn == False:
                                                asnDict = dict.fromkeys(["ASN"], [])
                                            else:
                                                asnDict = dict.fromkeys(["ASN"], asn)
                                            DIC.update(asnDict)
                                            recs= json.dumps(DIC)
                                            urlPost = f"{EgoSettings.HostAddress}:{Port}/api/records/create/"    
                                            if bool(auth_token_json):
                                                DIC_headers.update(auth_token_json)
                                            postRecords = requests.post(urlPost, data=(recs), headers=DIC_headers,verify=False)
                                            responseRecords = postRecords.text
                                            jsonresponseRecords = json.loads(responseRecords)
                                            status = postRecords.status_code

                                            try:
                                                ToolBox.MantisRequester(FullDomainName, jsonresponseRecords['id'], SET=SET, Customer_key=Customer_key, SCOPED=SCOPED, path=None, method='GET', HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json, CoolDown_Between_Queries=CoolDown_Between_Queries)
                                                
                                            except Exception as E:
                                                pass
                                            try:
                                                dnsquery= EgoDns.Dns_Resolver(jsonresponseRecords, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)                                            
                                            except Exception as E:
                                                pass
                                            #try:
                                            #    ToolBox.GeoCodes(DIC['ip'], jsonresponseRecords['id'],  HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                                            #except Exception as E:
                                            #    pass                

                                            if status != 201:
                                                print('nmap 201')
                                                pass
                                            elif "record with this subDomain already exists." in responseRecords:
                                                print("record with this subDomain already exists.")
                                                pass
                                            else:
                                                #nmap
                                                portscan_bool = False
                                                versionscan_bool_before_version = True
                                                nmap_scan= EgoNmap.NmapScan(jsonresponseRecords, portscan_bool, versionscan_bool_before_version, auth_token_json=auth_token_json )
                                                
                                                if CertBool != False:
                                                    jsonresponseRecords_id= jsonresponseRecords['id']
                                                    certificate_id= dict.fromkeys(['record_id'], jsonresponseRecords_id)
                                                    print('certcertcertcertcertcertcertcertcertcertcertcertcertcertcertcertcertcertcertcertcertcertcertc')
                                                    Certificate_= cert['Certificate']
                                                    certificate_id.update(Certificate_) 
                                                    md5_hash = hashlib.md5(json.dumps(certificate_id, sort_keys=True).encode('utf-8')).hexdigest()
                                                    results = dict.fromkeys(['md5'],md5_hash)
                                                    certificate_id.update(results)
                                                    recs= json.dumps(certificate_id)
                                                    print('certificatecertificatecertificatecertificatecertificate')
                                                    print('certificatecertificatecertificatecertificatecertificate')
                                                    print('certificatecertificatecertificatecertificatecertificate')
                                                    print('certificatecertificatecertificatecertificatecertificate')                                                         
                                                    certificateurlPost= f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/Certificate/create/"
                                                    DIC_headers = {}
                                                    print('certificateurlPostcertificateurlPostcertificateurlPost', certificateurlPost)
                                                    #DIC_headers.update(auth_token_json)
                                                    DIC_headers.update(headers)
                                                    if bool(auth_token_json):
                                                        DIC_headers.update(auth_token_json)
                                                    postRecords = requests.post(certificateurlPost, data=(recs), headers=DIC_headers,verify=False)
                                                    responseRecords = json.loads(postRecords.text)
                                                    return(f'responseRecords    certcertcertcertcertcertcertcertcertcertcertcertcertcertcert   {responseRecords}')
                                                #dns
                                                jsonresponseRecords_id= jsonresponseRecords['id']
                                                dns_id= dict.fromkeys(['record_id'], jsonresponseRecords_id)
                                                subDomain.update(dns_id)
                                                portscan_bool_temp = False                                                
                    elif type(a) is dict:
                        subDomain= a['subDomain']
                        ports= a['OpenPorts']
                        Record_id= a['record_id']
                        domain_set= DomainNameValidation.CREATOR(subDomain)
                        domainname= domain_set['domainname']
                        domainname_dict= dict.fromkeys(['domainname'], domainname)
                        DIC.update(domainname_dict)
                        FullDomainName= domain_set['fulldomain']  
                        subDomain= dict.fromkeys(['subDomain'], FullDomainName) 
                        DIC.update(subDomain)
                        md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()
                        results_md5 = dict.fromkeys(['md5'],md5_hash)
                        DIC.update(results_md5)
                        Customer_id = Customer_key['Customer_id']
                        record_id= dict.fromkeys(['customer_id'], Customer_id)

                        DIC.update(record_id)
                        DIC_headers = {}
                        #DIC_headers.update(auth_token_json)
                        DIC_headers.update(headers)
                        ipDIC = DIC['ip']
                        if type(ipDIC) == list:
                            asn_store = []
                            for b in ipDIC:
                                n = ToolBox.ASN(b)
                                asn_store.append(n)
                            asn = asn_store
                        else:
                            asn = ToolBox.ASN(ipDIC)


                        if asn == False:
                            asnDict = dict.fromkeys(["ASN"], [])
                        else:
                            asnDict = dict.fromkeys(["ASN"], asn)
                        DIC.update(asnDict)
                        recs= json.dumps(DIC)
                        urlPost = f"{EgoSettings.HostAddress}:{Port}/api/records/create/"    
                        if bool(auth_token_json):
                            DIC_headers.update(auth_token_json)
                        postRecords = requests.post(urlPost, data=(recs), headers=DIC_headers,verify=False)
                        responseRecords = postRecords.text
                        jsonresponseRecords = json.loads(responseRecords)
                        try:

                            ToolBox.MantisRequester(FullDomainName, jsonresponseRecords['id'], SET=SET, Customer_key=Customer_key, SCOPED=SCOPED, path=None, method='GET', HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json,CoolDown_Between_Queries=CoolDown_Between_Queries)
                            dnsquery= EgoDns.Dns_Resolver(jsonresponseRecords, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                            #ToolBox.GeoCodes(DIC['ip'], jsonresponseRecords['id'],  HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                            portscan_bool = False
                            versionscan_bool_before_version = True
                            nmap_scan= EgoNmap.NmapScan(a, portscan_bool, versionscan_bool_before_version, auth_token_json=auth_token_json )
                            portscan_bool = True
                            versionscan_bool_before_version = False
                            nmap_scan= EgoNmap.NmapScan(a, portscan_bool, versionscan_bool_before_version, auth_token_json=auth_token_json )
                        except Exception as E:
                            pass                       
                        cert= EgoCert.certRipper(FullDomainName, SET=SET, portscan_bool=portscan_bool, versionscan_bool=versionscan_bool, CoolDown_Between_Queries=CoolDown_Between_Queries ,Customer_key=Customer_key, SCOPED=SCOPED, HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json) 
                        CertBool= cert['CertBool']
                        if CertBool == False:
                            pass
                        else:
                            Certificate_= cert['Certificate']
                            certificate_id= dict.fromkeys(['record_id'], Record_id)
                            Certificate_.update(certificate_id) 
                            md5_hash = hashlib.md5(json.dumps(Certificate_, sort_keys=True).encode('utf-8')).hexdigest()
                            results = dict.fromkeys(['md5'],md5_hash)
                            Certificate_.update(results)
                            DIC_headers = {}
                            #DIC_headers.update(auth_token_json)
                            DIC_headers.update(headers)

                            if bool(auth_token_json):
                                DIC_headers.update(auth_token_json)
                            recs= json.dumps(Certificate_)
                            certificateurlPost= f"{EgoSettings.HostAddress}:{Port}/api/Certificate/create/"
                            postRecords = requests.post(recs, data=(recs), headers=DIC_headers,verify=False)
                            responseRecords = json.loads(postRecords.text)
                            return(f'responseRecords2       {responseRecords}')
        except Exception as E:
            print('EGOBOX')
            print('EGOBOX', E)


