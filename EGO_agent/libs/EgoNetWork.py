import dask
import json
import requests
import hashlib
import datetime
import ssl
import OpenSSL
import socket
import EgoSettings
import nmap3 
import time
import dns
import dns.resolver
import dns.zone
import dns.ipv4
import hashlib
from requests.packages.urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#EgoCert.


def dict_merge(dict1,dict2):
    return(dict2.update(dict1))

def DNSCRESOLVER(rec, idsList):
    try:
        storea = {}
        for i in idsList:
            try:
                t = dns.resolver.resolve(rec, i)
                for rdata in t:
                    temp = rdata.to_text()
                    set=dict.fromkeys([i],temp)
                    storea.update(set)
            except Exception as E:
                pass
        return(storea)
    except Exception as E:
        print(E)
        
class EgoDns:
    def Dns_Resolver(domain_key_set, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=None):
        try:
            print('DNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNS')
            print('DNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNS', domain_key_set)
            print('DNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNSDNS')
            print(bool(domain_key_set['subDomain']))
            if bool(domain_key_set['subDomain']) == True:
                subDomain= domain_key_set['subDomain']
                Record_id= domain_key_set['id']
                DNS_id= dict.fromkeys(['record_id'],Record_id)
                Dns_Resolver_KEY= dict.fromkeys(['dns'], Record_id)
                headers = {"Content-type": "application/json", "Accept": "application/json"}
                if bool(auth_token_json):
                    headers.update(auth_token_json)
                else:
                    pass
                # addd mx txt 
                ids = [
                "A",
                "AAAA",
                "ALIAS",                
                "CNAME",
                'DNAME',
                'ISDN',
                'GPOS',
                'LOC',
                'MX',
                'MD',
                'MB',
                "NS",
                'PTP',
                'SOA',
                'SRV',
                'TXT'
                ]
                d = subDomain
                rec_stor = {}
                metaRecords = {}
                counter = 0
                for i in ids:
                    try:
                        answers = dns.resolver.resolve(d, i)
                        for rdata in answers:
                            i = i
                            s = (rdata.to_text())
                            sd = dict.fromkeys([i],s)
                            rec_stor.update(sd)
                            if i == "A":
                                Recordsdata = DNSCRESOLVER(s, ["NS","CNAME"])
                    
                                if Recordsdata:
                                    metaRecords.update(Recordsdata)
                                else:
                                    pass
                            elif i == "AAAA":
                                Recordsdata = DNSCRESOLVER(s, ["NS","CNAME"])
                                if Recordsdata:
                                    metaRecords.update(Recordsdata)
                                else:
                                    pass
                            elif i == "CNAME":
                                Recordsdata = DNSCRESOLVER(s, ["NS","AAAA","A"])
                                if Recordsdata:
                                    metaRecords.update(Recordsdata)
                                else:
                                    pass
                            else:
                                pass
                    except Exception as E:
                        print('rec_stor', E)
                        continue
                CHECKSrec_stor= bool(rec_stor)
                CHECKSmetaRecords= bool(metaRecords)
                if CHECKSmetaRecords is True:
                    DIC = {}
                    DIC.update(rec_stor)
                    DIC.update(DNS_id)
                    md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()
                    results = dict.fromkeys(['md5'],md5_hash)
                    DIC.update(results)
                    recs= json.dumps(DIC)
                    DNSAuthCertRipperUrlPost = f"{HostAddress}:{Port}/api/DNSAuth/"
                    postRecords = requests.post(
                        DNSAuthCertRipperUrlPost, 
                        data=(recs), 
                        headers=headers,
                        verify=False,
                        timeout=60
                        )
                    responseRecords = postRecords.content
                    jsonresponseRecords = json.loads(responseRecords)
                    status = postRecords.status_code

                if CHECKSrec_stor is True:
                    DIC = {}
                    DIC.update(rec_stor)
                    DIC.update(DNS_id)
                    md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()
                    results = dict.fromkeys(['md5'],md5_hash)
                    DIC.update(results)
                    recs= json.dumps(DIC)
                    DNSAuthCertRipperUrlPost = f"{HostAddress}:{Port}/api/DNS/"
                    postRecords = requests.post(
                        DNSAuthCertRipperUrlPost, 
                        data=(recs), 
                        headers=headers,
                        verify=False,
                        timeout=60
                        )
                    responseRecords = postRecords.text
                    jsonresponseRecords = json.loads(responseRecords)
                    status = postRecords.status_code
                else:
                    return False
                return True
            else:
                print('dfart')
                return False
        except Exception as E:
            print('dns excpt', E)
            return False

    def dnsenum(fqdn,values,domainname, SCOPED=None, Customer_key=None, SET=None, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=None):
        headers = {"Content-type": "application/json", "Accept": "application/json"}
        try:
            ip = socket.gethostbyname_ex(fqdn)
            if domainname in str(values):
                if ip:
                    dic = {}
                    new_Occurance = str(int(values['Occurance']) + 1)
                    oc_dict = dict.fromkeys(['Occurance'],new_Occurance)
                    values.update(oc_dict)
                    oc_dict = dict.fromkeys(['Occurance'],new_Occurance)
                    dic.update(oc_dict)
                    update_url = f"{EgoSettings.HostAddress}:{EgoSettings.Port}/api/WordList/{values['id']}"
                    recs = json.dumps(dic)
                    time.sleep(0.05)
                    req = requests.patch(update_url, data=recs, headers=headers, verify=False, timeout=60)
                    print(req.status_code)
                    if auth_token_json:
                        dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                    else:
                        dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                    return dns_scan
            else:
                if ip:
                    dic = {}
                    #print(values['Occurance'])
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
                                            
                    #print('FindingUpdate',dic)
                    recs = json.dumps(dic)
                    #print(recs)
                    time.sleep(0.05)
                    if auth_token_json:
                        dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port, auth_token_json=auth_token_json)
                    else:
                        dns_scan= ToolBox.Uploader(fqdn, SCOPED=SCOPED, Customer_key=Customer_key, SET=SET , HostAddress=HostAddress, Port=Port)
                    return dns_scan
        except Exception as E:
            #print(E)
            pass


