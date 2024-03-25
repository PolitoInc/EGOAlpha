import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import tldextract, random, time, re, base64
from collections import namedtuple
import json, itertools
from string import ascii_letters
from itertools import product, permutations, repeat

import itertools
import ipaddress
from random import choice, randint
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import dask
import ast
import dask.array as dd

import EgoSettings

from libs.EgoDomainName import *
from libs.EgoNetWork import *
from libs.EgoDomainSearch import *
from libs.EgoNmapModule import *
from libs.EgoBox import *

from ast import literal_eval
def random_string(length=10):
    return ''.join([choice(ascii_letters) for _ in range(length)])



headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"}
#PACKMGR = itertools.product(('/crx/packmgr/index.jsp', '///crx///packmgr///index.jsp', '///crx///packmgr///.jsp'),
#                            ('', ';%0a{0}.css', ';%0a{0}.html', ';%0a{0}.ico',
#                                '?{0}.css', '?{0}.html', '?{0}.ico')
#)
#r = random_string(3)
#PATH = list('{0}{1}'.format(p1, p2.format(r)) for p1, p2 in PACKMGR)

global_seen = set()

def splited(list_a, chunk_size):
    if list_a == None:
        pass
    else:
        results= []
        for i in range(0, len(list_a), chunk_size):
            chunk= list_a[i:i + chunk_size]
            results.append(chunk)
        return results 

def HostNameBool(data):
    Address = data
    nmap = nmap3.NmapHostDiscovery()
    try:
        ClearHostName = nmap.nmap_no_portscan(Address)
        ip =[ i for i in ClearHostName]
        runtime= (ClearHostName.get('runtime',{}))
        summary= (runtime['summary'])
        if '0 hosts up' in summary:
            alive= dict.fromkeys(["alive"],False)
            return alive
        else:
            alive= dict.fromkeys(["alive"],True)
            ip= dict.fromkeys(["ip"],ip[0])
            alive.update(ip)
            return alive
    except Exception:
        return("False")

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



def FindingForge(domain, url, matcher_set, resp, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=None, Vuln=None, RECORD=None, creds=None, headers=None, VulnData=None, auth_token_json=None):  
    try:

        if resp is None:
            pass
        else:
            matchers_status = matcher_set['matchers_status']
            if bool(matchers_status):
                matchers_status = matchers_status
                if str(resp.status_code) in matchers_status:
                    Resp_Headers = resp.headers
                    Resp_Body = resp.content
                    Resp_Words = resp.text
                    matchers_headers = (matcher_set.get("matchers_headers", {}))
                    domainfqdn = urlparse(domain)
                    FOUND = {}
                    
                    if bool(matchers_headers):
                        matchers_headers = matchers_headers
                        if bool(creds):
                            found_Resp_Headers = [{ "match_headers":  str(match), "matchedAt_headers": str(Resp_Headers)[:1500], "creds": [creds, headers['Authorizaiton']], "DomainName": domainfqdn.netloc} for match in matchers_headers if str(match) in str(Resp_Headers)]
                            FOUND.update(found_Resp_Headers)
                        else:
                            found_Resp_Headers = [{ "match_headers":  str(match), "matchedAt_headers": str(Resp_Headers)[:1500], "creds": [], "DomainName": domainfqdn.netloc} for match in matchers_headers if str(match) in str(Resp_Headers)]
                            FOUND.update(found_Resp_Headers)
                    else:
                        FOUND =FOUND

                    matchers_bodys = matcher_set['matchers_bodys']
                    if bool(matchers_bodys):
                        if '{{space}}' in matchers_bodys:
                            matchers_bodys = [" "]
                            if bool(creds):
                                found_Resp_Body = [ {"match_bodys":  f"{str(match)}", "matchedAt_bodys": f"{str(Resp_Body)[:1500]}", "creds": [ creds ], "match_headers": headers['Authorization'], "DomainName": domainfqdn.netloc} for match in matchers_bodys if bytes(match, encoding= 'utf-8') in Resp_Body]
                            else:
                                found_Resp_Body = [ {"match_bodys":  f"{str(match)}", "matchedAt_bodys": f"{str(Resp_Body)[:1500]}", "creds": [], "DomainName": domainfqdn.netloc} for match in matchers_bodys if bytes(match, encoding= 'utf-8') in Resp_Body]
                            if bool(found_Resp_Body):
                                FOUND.update(found_Resp_Body[0])
                            else:
                                FOUND = FOUND   
                        else:
                            matchers_bodys = matchers_bodys
                            if bool(creds):
                                found_Resp_Body = [ {"match_bodys":  f"{str(match)}", "matchedAt_bodys": f"{str(Resp_Body)[:1500]}", "creds": [ creds ], "match_headers":headers['Authorization'], "DomainName": domainfqdn.netloc} for match in matchers_bodys if bytes(match, encoding= 'utf-8') in Resp_Body]
                            else:
                                found_Resp_Body = [ {"match_bodys":  f"{str(match)}", "matchedAt_bodys": f"{str(Resp_Body)[:1500]}", "creds": [], "DomainName": domainfqdn.netloc} for match in matchers_bodys if bytes(match, encoding= 'utf-8') in Resp_Body]
                            if bool(found_Resp_Body):
                                FOUND.update(found_Resp_Body[0])
                            else:
                                FOUND = FOUND
                    else:
                        FOUND = FOUND
                    if FOUND:
                        
                        
                        if 'vulnClass' in str(RECORD):
                            _id = RECORD['record_id']
                        else:
                            _id = RECORD['id']
                        records_id = dict.fromkeys(['record_id'], _id)
                        dict_local = dict.fromkeys(['location'], [url])
                        vulncard = vulnCard.get("vulnCard", {})
                        FOUND.update(records_id)
                        FOUND.update(vulncard)
                        FOUND.update(dict_local)
                        FOUND.update({"exploitDB": []})
                        FOUND.update({"status": matchers_status})
                        FOUND.update({"exploitDB": []})
                        del FOUND['pictures']
                        urlFoundVuln = f"{HostAddress}:{Port}/api/FoundVuln/"
                        req = requests.get(urlFoundVuln, headers=auth_token_json,verify=False)
                        RJSON = req.json()
                        FoundVulnresp = RJSON

                        del VulnData['id']
                        for_FoundVulnresp = [x for x in FoundVulnresp if x['name'] == VulnData['name'] ]
                        len_FoundVulnresp = len(FoundVulnresp)
                        len_for_FoundVulnresp = len(for_FoundVulnresp)
                        domainname = DomainNameValidation.CREATOR(domain)
                        FQDN = domainname['fulldomain']
                        CreateurlFoundVuln = f"{HostAddress}:{Port}/api/FoundVuln/create/"
                        if len_FoundVulnresp == 0 or len_for_FoundVulnresp == 0 :
                           
                            
                            VulnData_data = VulnData['vulnCard_id']
                            vullndata_dic = dict.fromkeys(['vuln_cardId'], VulnData_data)
                            FOUND.update(vullndata_dic)
                            Domain_dic = dict.fromkeys(['DomainName'], FQDN)
                            FOUND.update(Domain_dic)
                            recs = json.dumps(FOUND)
                            headers = {"Content-type": "application/json", "Accept": "application/json"}
                            authheaders=auth_token_json
                            headers.update(authheaders)
                            request = requests.post(CreateurlFoundVuln, headers=headers, data=recs,verify=False)
                            resp = request.json()
                            return resp 
                        else:
                            found_creds = creds
                        #creds 
                            SameCreds_FoundVulnresp_sets = [ x for x in FoundVulnresp if  x['name'] == FOUND['name'] and x['DomainName'] == FOUND['DomainName'] and found_creds in x['creds'] and found_creds]
                            NewCredsFoundVulnresp_sets = [ x for x in FoundVulnresp if x['name'] == FOUND['name'] and x['DomainName'] == FOUND['DomainName'] and found_creds not in x['creds'] and found_creds and not x['creds']]

                            Len_SameCredsboolfoundvulns = len(SameCreds_FoundVulnresp_sets)
                            Len_NewCredsFoundVulnresp_sets = len(NewCredsFoundVulnresp_sets)

                        # non creds
                            NewFoundVulnresp_sets = [ x for x in FoundVulnresp if x['name'] == FOUND['name'] and x['DomainName'] != FOUND['DomainName'] and bool(VulnData['Elevate_Vuln']) == False ]
                            NewVulnSameNameFoundVulnresp_sets = [ x for x in FoundVulnresp if x['name'] == FOUND['name'] and x['DomainName'] == FOUND['DomainName'] and bool(VulnData['Elevate_Vuln']) == False]

                            Len_NewFoundVulnresp_sets= len(NewFoundVulnresp_sets)
                            Len_sameVulnresp_sets = len(NewVulnSameNameFoundVulnresp_sets)

                        #elevate x['name'] == FOUND['name']                             
                            NewElevate_Vulnresp_sets = [ x for x in FoundVulnresp if VulnData['Elevate_Vuln'] and x['name'] == FOUND['name'] and x['DomainName'] != FOUND['DomainName']]
                            SameElevate_FoundVulnresp = [ x for x in FoundVulnresp if VulnData['Elevate_Vuln'] and x['name'] == FOUND['name'] and x['DomainName'] == FOUND['DomainName']]

                            Len_NewElevate_VulnName = len(NewElevate_Vulnresp_sets)
                            Len_SameElevate_FoundVulnresp_sets = len(SameElevate_FoundVulnresp)                         

                            FOUNDOUT= []
                            if Len_SameCredsboolfoundvulns > 0:

                                for vulnresp in SameCreds_FoundVulnresp_sets:
                                    PatchurlFoundVuln = f"{HostAddress}:{Port}/api/FoundVuln/{vulnresp['id']}"
                                    headers={}
                                    headers.update(auth_token_json)
                                    request_get = requests.get(PatchurlFoundVuln, headers=headers,verify=False)
                                    rjson = request_get.json()
                                    Locations = rjson['location']
                                    locationbool = [l for l in Locations if FQDN in l]
                                    len_locationbool= len(locationbool)
                                    dict_loations = dict.fromkeys(['location'], Locations)
                                    dict_loations['location'].append(url)

                                    DIC = {}
                                    DIC.update(dict_loations)
                                    recs= json.dumps(DIC)
                                    headers = {"Content-type": "application/json", "Accept": "application/json"}
                                    headers.update(auth_token_json)
                                    request = requests.patch(PatchurlFoundVuln, headers=headers, data=recs,verify=False)
                                    resp = request.json()
                                    FOUNDOUT.append(resp)

                                return FOUNDOUT 




                            elif Len_NewCredsFoundVulnresp_sets > 0:
                                #del FOUND['exploitDB']
                                VulnData_data = VulnData['vulnCard_id']
                                vullndata_dic = dict.fromkeys(['vuln_cardId'], VulnData_data)
                                FOUND.update(vullndata_dic)
                                Domain_dic = dict.fromkeys(['DomainName'], FQDN)
                                FOUND.update(Domain_dic)
                                recs = json.dumps(FOUND)
                                headers = {"Content-type": "application/json", "Accept": "application/json"}
                                headers.update(auth_token_json)
                                request = requests.post(urlFoundVuln, headers=headers, data=recs,verify=False)
                                resp = request.json()

                                FOUNDOUT.append(resp)
                            elif Len_sameVulnresp_sets > 0:
                                for vulnresp in NewVulnSameNameFoundVulnresp_sets:
                                    headers={}
                                    headers.update(auth_token_json)
                                    PatchurlFoundVuln = f"{HostAddress}:{Port}/api/FoundVuln/{vulnresp['id']}"
                                    request_get = requests.get(PatchurlFoundVuln, headers=headers,verify=False)
                                    rjson = request_get.json()
                                    Locations = rjson['location']
                                    locationbool = [l for l in Locations if FQDN in l]
                                    len_locationbool= len(locationbool)
                                    dict_loations = dict.fromkeys(['location'], Locations)
                                    dict_loations['location'].append(url)
                                    if len_locationbool > 0 and len_locationbool < 10:
                                        DIC = {}
                                        DIC.update(dict_loations)
                                        recs= json.dumps(DIC)
                                        headers = {"Content-type": "application/json", "Accept": "application/json"}
                                        headers.update(auth_token_json)
                                        request = requests.patch(PatchurlFoundVuln, headers=headers, data=recs,verify=False)
                                        resp = request.json()
                                        FOUNDOUT.append(resp)



                            elif Len_SameElevate_FoundVulnresp_sets > 0 :
                                for vulnresp in SameElevate_FoundVulnresp:
                                    headers={}
                                    headers.update(auth_token_json)
                                    PatchurlFoundVuln = f"{HostAddress}:{Port}/api/FoundVuln/{vulnresp['id']}"
                                    request_get = requests.get(PatchurlFoundVuln, headers=headers,verify=False)
                                    rjson = request_get.json()
                                    Locations = rjson['location']
                                    locationbool = [l for l in Locations if FQDN in l]
                                    len_locationbool= len(locationbool)
                                    dict_loations = dict.fromkeys(['location'], Locations)
                                    dict_loations['location'].append(url)
                                    if len_locationbool > 0 and len_locationbool < 10:
                                        DIC = {}
                                        DIC.update(dict_loations)
                                        recs= json.dumps(DIC)
                                        headers = {"Content-type": "application/json", "Accept": "application/json"}
                                        headers.update(auth_token_json)
                                        request = requests.patch(PatchurlFoundVuln, headers=headers, data=recs,verify=False)
                                        resp = request.json()
                                        FOUNDOUT.append(resp)
                            elif Len_NewElevate_VulnName > 0 :
                                #del FOUND['exploitDB']
                                VulnData_data = VulnData['vulnCard_id']
                                vullndata_dic = dict.fromkeys(['vuln_cardId'], VulnData_data)
                                FOUND.update(vullndata_dic)
                                Domain_dic = dict.fromkeys(['DomainName'], FQDN)
                                FOUND.update(Domain_dic)
                                recs = json.dumps(FOUND)
                                headers = {"Content-type": "application/json", "Accept": "application/json"}
                                headers.update(auth_token_json)
                                request = requests.post(CreateurlFoundVuln, headers=headers, data=recs,verify=False)
                                resp = request.json()

                                FOUNDOUT.append(resp)
                            elif Len_NewFoundVulnresp_sets > 0 :
                                #del FOUND['exploitDB']
                                VulnData_data = VulnData['vulnCard_id']
                                vullndata_dic = dict.fromkeys(['vuln_cardId'], VulnData_data)
                                FOUND.update(vullndata_dic)
                                Domain_dic = dict.fromkeys(['DomainName'], FQDN)
                                FOUND.update(Domain_dic)
                                recs = json.dumps(FOUND)
                                headers = {"Content-type": "application/json", "Accept": "application/json"}
                                headers.update(auth_token_json)
                                request = requests.post(CreateurlFoundVuln, headers=headers, data=recs,verify=False)
                                resp = request.json()

                                FOUNDOUT.append(resp)

                            else:
                                pass
                    else:
                        pass
                else: 
                    pass
            else:
                pass

    except Exception as E:
        pass

def normalize_url(base_url, path):
    try:
        if base_url[-1] == '/' and base_url[-1] == './' and (path[0] == '/' or path[0] == '\\'):
            url = base_url[:-1] + path
        else:
            url = base_url + path

        return url
    except:
        return base_url + path

duds = []

def http_request(domain, path, Global_Nuclei_CoolDown=(0,120), method='GET', data=None, postData=None, proxy=None, debug=False, allow_redirects=None, additional_headers=None, matcher_set=None, 
                HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=None, Vuln=None, RECORD=None, creds=None, VulnData=None, auth_token_json=None):
    Sleep_Generator = ToolBox.RandomTime(Global_Nuclei_CoolDown)
    time.sleep(Sleep_Generator)
    grandtime = 30

    if path is None:
        pass
    else:
        base_url = normalize_url(domain, path)
        url = f"https://{base_url}"
        if '{{base_url}}' in str(additional_headers):
            headers.update({"Referer": f"https://{url}"})
        global_seen.add(domain)
        if domain in duds:
            pass
        else:
            try:
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
                    session.get(url, verify=False, timeout=grandtime, allow_redirects=allow_redirects)
                    if method == 'GET':
                        resp = session.get(url, headers=headers, proxies=proxy, verify=False, timeout=grandtime, allow_redirects=allow_redirects)
                        stat = resp.status_code
                        if f"{stat}" == '200':
                        if matcher_set is None:
                            return resp
                        else:
                            Found = FindingForge(domain, url, matcher_set, resp, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vulnCard, Vuln=Vuln, RECORD=RECORD,headers=headers, creds=creds, VulnData=VulnData, auth_token_json=auth_token_json)
                            return Found
                    elif method == 'POST':
                        resp = session.post(url, data=data, headers=headers, proxies=proxy, verify=False, timeout=grandtime, allow_redirects=allow_redirects)
                        if matcher_set is None:
                            return resp
                        else:
                            Found = FindingForge(domain, url, matcher_set, resp, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vulnCard, Vuln=Vuln, RECORD=RECORD, headers=headers, creds=creds, VulnData=VulnData, auth_token_json=auth_token_json)
                            return Found
                    else:
                        pass

                    if debug:
                        pass

            except Exception as E:
                duds.append(domain)
                pass

def Shredder(url, Global_Nuclei_CoolDown=[1, 2], creds=None, method='GET', paths=None, path_complex=None, data=None, additional_headers=None, proxy=None, debug=False, allow_redirects=None, extra_headers=None, matcher_set=None, Vuln=None, Finding=None, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=None, RECORD=None, VulnData=None, auth_token_json=None):

    matcher_set = {}
    matchers_status = Vuln.get("matchers_status", {})
    callback = Vuln.get('callbackServer')
    if bool(matchers_status):
        matchers_status = dict.fromkeys(["matchers_status"], matchers_status)
        matcher_set.update(matchers_status)
    else:
        pass
    matchers_headers = (Vuln.get("matchers_headers", {}))
    if bool(matchers_headers):
        matchers_headers = dict.fromkeys(["matchers_headers"], matchers_headers)
        matcher_set.update(matchers_headers)
    else:
        pass
    matchers_bodys = (Vuln.get("matchers_bodys", {}))
    if bool(matchers_bodys):
        matchers_bodys = dict.fromkeys(["matchers_bodys"], matchers_bodys)
        matcher_set.update(matchers_bodys)
    else:
        pass
    matchers_words = (Vuln.get("matchers_words", {}))
    if bool(matchers_words):
        matchers_words = dict.fromkeys(["matchers_words"], matchers_words)
        matcher_set.update(matchers_words)
    else:
        pass
# request formation
    Request_set = {}
    request_method = Vuln.get("request_method", {})
    if bool(request_method):
        dic_request_method = dict.fromkeys(['request_method' ], request_method)
        Request_set.update(dic_request_method)
    else:
        pass
    payloads = Vuln.get("payloads", {})
    if bool(payloads):
        dic_ = dict.fromkeys(['payloads' ], payloads)
        Request_set.update(dic_)
    else:
        pass

    postData = Vuln.get("postData", "")
    if bool(postData):
        
        if bool(callback):
            dic_postData = re.sub('{{callback_server}}', callback, postData)
            dic_postData = dict.fromkeys(['postData'], dic_postData)
            Request_set.update(dic_postData)
        else:
            dic_postData = dict.fromkeys(['postData'], postData)
            Request_set.update(dic_postData)
    else:
        pass
    ComplexPathPython = Vuln.get("ComplexPathPython", "")
    if bool(ComplexPathPython):
        dic_ComplexPathPython = dict.fromkeys(['ComplexPathPython'], ComplexPathPython)
        Request_set.update(dic_ComplexPathPython)
    else:
        pass
    #if bool(ComplexAttackPython):
    #    ComplexAttackPython =  Vuln.get("ComplexAttackPython", {})
    #    Request_set.update(ComplexAttackPython)
    #else:
    #    pass
    #if bool(path):
    #    path = Vuln.get("path", {})
    #    Request_set.update(path)
    #else:
    #    pass
    #if bool(pathDeveloper):
    #    pathDeveloper = Vuln.get("pathDeveloper", {})
    #    Request_set.update(pathDeveloper)
    #else:
    #    pass
    SSL = Vuln.get("SSL", "")
    if bool(SSL):
        dic_= dict.fromkeys(["SSL"], SSL)
        Request_set.update(dic_)
    else:
        pass
    timeout_betweenRequest = Vuln.get("timeout_betweenRequest", "")
    if bool(timeout_betweenRequest):
        dic_= dict.fromkeys(["timeout_betweenRequest"], timeout_betweenRequest)
        Request_set.update(dic_)
    else:
        dic_= dict.fromkeys(["rawRequest"], False)
        Request_set.update(dic_)
    repeatnumb = Vuln.get("repeatnumb", "")
    if bool(repeatnumb):
        dic_= dict.fromkeys(['repeatnumb'], repeatnumb)
        Request_set.update(dic_)
    else:
        dic_= dict.fromkeys(['repeatnumb'], "0")
        Request_set.update(dic_)
    redirect = Vuln.get("redirect", "")
    if bool(redirect):
        dic_= dict.fromkeys(["redirect"], redirect)
        Request_set.update(dic_)
    else:
        dic_ =  dict.fromkeys(["redirect"], False)
        Request_set.update(dic_)
    if paths is not None:
        if type(paths) is str:
            if matcher_set is None:
                if Request_set['request_method'] == 'GET':
                    org_headers = Vuln.get("headers", {})
                    if bool(org_headers):

                        Keys = ["{{BasicBase64CredEncode}}","{{base_url}}", "{{callback_server}}"]
                        reg = r"{{(.*?)}}"
                        base_url = f"https://{url}"

                        zeroheaders = org_headers[0]
                        headers= dict(zeroheaders)

                        if '{{callback_server}}' in str(org_headers):
                            headers = [v.replace('{{callback_server}}', callback) for k,v in org_headers if '{{callback_server}}' in v]

                        if '{{BasicBase64CredEncode}}' in str(org_headers):
                            out_resp=[]
                            for cred in creds:
                                auth_header = {"Authorization": f"Basic {format(base64.b64encode(cred.encode()).decode())}"}
                                for path in paths:
                                    resp = http_request(url, path, Global_Nuclei_CoolDown, allow_redirects=Request_set["redirect"], matcher_set=matcher_set, method=Request_set['request_method'], 
                                                        additional_headers=headers.update(auth_header), postData=postData, creds=cred, VulnData=VulnData, auth_token_json=auth_token_json)
                                    out_resp.append(resp)
                            return resp_Out
                        else:
                            out_resp=[]
                            for path in paths:

                                resp = http_request(url, path, Global_Nuclei_CoolDown, allow_redirects=Request_set["redirect"], matcher_set=matcher_set, method=Request_set['request_method'], 
                                                    additional_headers=headers, postData=postData, VulnData=VulnData, auth_token_json=auth_token_json)
                                out_resp.append(resp)
                            return resp_Out
                    else:
                        headers = {"User-Agent": "curl/7.30.0"}
                        out_resp=[]
                        for path in paths:

                            resp = http_request(url, path, Global_Nuclei_CoolDown, allow_redirects=Request_set["redirect"], matcher_set=matcher_set, method=Request_set['request_method'], 
                                                additional_headers=headers, postData=postData, VulnData=VulnData, auth_token_json=auth_token_json)
                            out_resp.append(resp)
                        return resp_Out
                elif Request_set['request_method'] == 'POST':

                    org_headers = Vuln.get("headers", {})
                    if bool(org_headers):
                        Keys = ["{{BasicBase64CredEncode}}","{{base_url}}", "{{callback_server}}"]
                        reg = r"{{(.*?)}}"
                        zeroheaders = org_headers[0]
                        headers= dict(zeroheaders)


                        if '{{BasicBase64CredEncode}}' in str(org_headers):
                            resp_Out= []
                            for cred in creds:
                                auth_header = {"Authorization": f"Basic {format(base64.b64encode(cred.encode()).decode())}"}
                                headers.update(auth_header)
                                for path in paths:
 
                                    resp = dask.delayed(http_request)(url, paths, Global_Nuclei_CoolDown, allow_redirects=Request_set["redirect"], matcher_set=matcher_set, 
                                                                      method=Request_set['request_method'], additional_headers=headers, postData=postData ,Port=Port, vulnCard=vuln_set, 
                                                                      Vuln=Vuln, RECORD=RECORD, creds=cred, VulnData=VulnData, auth_token_json=auth_token_json)
                                    resp_Out.append(resp)
                            return resp_Out
                        else:
                            resp_Out=[]
                            for path in paths:

                                resp = dask.delayed(http_request)(url, paths, Global_Nuclei_CoolDown, allow_redirects=Request_set["redirect"], matcher_set=matcher_set, method=Request_set['request_method'],
                                                                  additional_headers=headers, postData=postData, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, 
                                                                  Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                                resp_Out.append(resp)
                            Dask_Shredder= dask.compute(*resp_Out)
                            return Dask_Shredder
                    else:
                        #headers = {"User-Agent": "curl/7.30.0"}
                        resp_Out=[]
                        for path in paths:

                            resp = dask.delayed(http_request)(url, paths, Global_Nuclei_CoolDown, allow_redirects=Request_set["redirect"], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=headers, 
                                                              postData=postData,Port=Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                            resp_Out.append(resp)
                        Dask_Shredder= dask.compute(*resp_Out)
                        return Dask_Shredder

            else:
                pass
        elif type(paths) is list:
            org_headers = Vuln.get("headers", {})
            if '{{base_url}}' in str(org_headers):
                headers.update({"Referer": f"https://{url}"})

            resp_Out=[]
            for p in paths:

                additional_headers = Vuln.get("headers", {})
                if bool(additional_headers):

                    p=p.replace('&#x2c;',',')
       

                    if additional_headers == None:
                        headers_len = 0
                    else:
                        headers_len = len(additional_headers)
                    if headers_len > 1 :
                        for header in additional_headers:
    
                            header = [v.replace('{{callback_server}}', callback) for k,v in header if '{{callback_server}}' in v]
                            resp = dask.delayed(http_request)(url, p, Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=header, postData=postData, 
                                                              HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                            resp_Out.append(resp)
                    else:
                        headers = [v.replace('{{callback_server}}', callback) for k,v in headers if '{{callback_server}}' in v]
                        resp = dask.delayed(http_request)(url, p, Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=additional_headers, postData=postData, 
                                                            HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                        resp_Out.append(resp)
                else:
                    p=p.replace('&#x2c;',',')
       

                    if additional_headers == None:
                        headers_len = 0
                    else:
                        headers_len = len(additional_headers)
                    if headers_len > 1 :
                        for header in additional_headers:
                            header = [v.replace('{{callback_server}}', callback) for k,v in header if '{{callback_server}}' in v]
                            resp = dask.delayed(http_request)(url, p, Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], postData=postData, 
                                                              HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                            resp_Out.append(resp)
                    else:
                        resp = dask.delayed(http_request)(url, p, Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], postData=postData, 
                                                            HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                        resp_Out.append(resp)
            Dask_Shredder= dask.compute(*resp_Out)
            return Dask_Shredder
        else:
            return('path is not present.')
            pass
    elif type(path_complex) is not None:
        if len(path_complex) == 3:
            SERVLET, SERVLET2, SERVLET3= path_complex
            Mule = itertools.product(SERVLET, SERVLET2, SERVLET3)
            nodename2 = random_string()
            r = random_string(3)  
            try:
                SERVLET =  list('{0}{1}{2}'.format(p1, p2.format(r), p3) for p1, p2, p3 in Mule)
            except:
                SERVLET =  list('{0}{1}{2}'.format(p1, p2.format(nodename2, r), p3) for p1, p2, p3 in Mule)
            resp_Out=[]
            for path in SERVLET:
                if path is None:
                    pass
                else:
                    if method == 'POST':

                        org_headers = Vuln.get("headers", {})
                        if bool(org_headers):
                            reg = r"{{(.*?)}}"

                            Keys = ["{{BasicBase64CredEncode}}","{{base_url}}", "{{callback_server}}"]
                            zeroheaders = org_headers[0]
                            headers= dict(zeroheaders)
                            postData = Request_set["postData"]
                            if '{{base_url}}' in str(org_headers):
                                headers.update({"Referer": base_url})

                            if '{{BasicBase64CredEncode}}' in str(org_headers):
                                for cred in creds:
                                    auth = {"Authorization": f"Basic {format(base64.b64encode(cred.encode()).decode())}"}
                                    headers.update(auth)
                                    resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown, allow_redirects=Request_set["redirect"], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=headers, 
                                                                      postData=postData, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, 
                                                                      creds=cred , VulnData=VulnData, auth_token_json=auth_token_json)
                                    resp_Out.append(resp)
                            elif 'None' in postData:
                                resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=headers, 
                                                                  HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                                resp_Out.append(resp)
                            else:
                                resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown, data=Request_set["postData"], allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], 
                                                                  additional_headers=headers, postData=postData, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, 
                                                                  RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                                resp_Out.append(resp)
                        else:
                            headers = {"User-Agent": "curl/7.30.0"}
                            resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown, data=Request_set["postData"], allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], 
                                                              additional_headers=headers, postData=postData, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, 
                                                              vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                            resp_Out.append(resp)
    
                    
                    elif method in ['GET', 'get']:
                        org_headers = Vuln.get("headers", {})
                        if bool(org_headers):

                            if '{{callback_server}}' in str(org_headers):
                                org_headers = [v.replace('{{callback_server}}', callback) for k,v in org_headers if '{{callback_server}}' in v]

                            resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], 
                                                              additional_headers=org_headers, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                            resp_Out.append(resp)
                        else:

                            resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], 
                                                              additional_headers=org_headers, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                            resp_Out.append(resp)
                    else:
                        pass
            Dask_Shredder= dask.compute(*resp_Out)
            return Dask_Shredder
        if len(path_complex) == 2:
            #('/content/..;/crx/packmgr/list.jsp;aa.css','/crx/packmgr/index.jsp', '///crx///packmgr///index.jsp', '///crx///packmgr///.jsp'),('', ';%0a{0}.css', ';%0a{0}.html', ';%0a{0}.ico', '?{0}.css', '?{0}.html', '?{0}.ico')
            SERVLET, SERVLET2 = path_complex
            Mule = itertools.product(SERVLET, SERVLET2)
            nodename2 = random_string()
            r = random_string(3)    
            try:
                SERVLET =  list('{0}{1}'.format(p1, p2.format(r)) for p1, p2 in (Mule))

            except:
                SERVLET =  list('{0}{1}'.format(p1, p2.format(nodename2, r)) for p1, p2 in (Mule))
            resp_Out=[]
            for path in SERVLET:
                if path is None:
                    pass
                else:
                    if Request_set['request_method'] == 'POST':
                        org_headers = Vuln.get("headers", {})
                        if bool(org_headers):                            
                            reg = r"{{(.*?)}}"                            

                            Keys = ["{{BasicBase64CredEncode}}","{{base_url}}", "{{callback_server}}"]
                            zeroheaders = org_headers[0]
                            headers= dict(zeroheaders)
                            postData = Request_set["postData"]
                            #headers = [dic.update({k: }) for k in thing]
                            if '{{base_url}}' in str(org_headers):
                                headers.update({"Referer": base_url})

                            if '{{BasicBase64CredEncode}}' in str(org_headers):
                                for cred in creds:
                                    auth = {"Authorization": f"Basic {format(base64.b64encode(cred.encode()).decode())}"}
                                    headers.update(auth)
                                    resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown, allow_redirects=Request_set["redirect"], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=headers, postData=postData, HostAddress=EgoSettings.HostAddress, 
                                                                      Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, creds=cred, VulnData=VulnData, auth_token_json=auth_token_json)
                                    resp_Out.append(resp)
                            elif 'None' in postData:
                                resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=headers, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, 
                                                                  vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                                resp_Out.append(resp)
                            else:
                                resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown, data=Request_set["postData"], allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=headers, postData=postData, 
                                                                  HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                                resp_Out.append(resp)
                        else:
                            headers = {"User-Agent": "curl/7.30.0"}
                            resp = dask.delayed(http_request)(base_url, path, Global_Nuclei_CoolDown, data=Request_set["postData"], allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=headers, postData=postData, 
                                                              HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                            resp_Out.append(resp)
    
                            
                    elif Request_set['request_method'] == 'GET':
                        org_headers = Vuln.get("headers", {})
                        if bool(org_headers):
                            headers ={}

                            if '{{callback_server}}' in str(org_headers):
                                headers = [v.replace('{{callback_server}}', callback) for k,v in org_headers if '{{callback_server}}' in v]
                            resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=headers, HostAddress=EgoSettings.HostAddress, 
                                                              Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                            resp_Out.append(resp)
                        else:
                            resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], HostAddress=EgoSettings.HostAddress, 
                                                              Port=EgoSettings.Port, vulnCard=vuln_set, Vuln=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                            resp_Out.append(resp)
                    else:
                        pass
            Dask_Shredder= dask.compute(*resp_Out)
            return Dask_Shredder
        elif len(path_complex) == 1:
            SERVLET = itertools.product(path_complex)
            nodename1 = random_string()
            r1 = random_string(3)    
            SERVLET =  list('{0}'.format(p1.format(nodename1, r1)) for p1 in SERVLET)
            resp_Out = []

            for path in SERVLET:
                resp = dask.delayed(http_request)(url, path, Global_Nuclei_CoolDown, allow_redirects=Request_set['redirect'], matcher_set=matcher_set, method=Request_set['request_method'], additional_headers=Request_set['headers'], postData=Request_set['postData'], HostAddress=EgoSettings.HostAddress, 
                                                  Port=EgoSettings.Port, VULN=Vuln, RECORD=RECORD, VulnData=VulnData, auth_token_json=auth_token_json)
                resp_Out.append(resp)
            Dask_Shredder= dask.compute(*resp_Out)
            return Dask_Shredder
        else:
            pass
    else:
        pass



if __name__ == "__main__":
    Global_Nuclei_CoolDown = [1, 5]
    HostAddress = EgoSettings.HostAddress
    Port = EgoSettings.Port
    #matcher_set = ({"matchers_status": "200", "matchers_headers": None, "matchers_bodys": ['"results":[', '"path":"'], "matchers_words": None})
    username = f"{EgoSettings.EgoAgentUser}"
    password = f"{EgoSettings.EgoAgentPassWord}"
    urlLogin = f"{HostAddress}:{Port}/api/login"
    headers = {"Content-type": "application/json", "Accept": "application/json"}
    creds = {"username": EgoSettings.EgoAgentUser, "password": EgoSettings.EgoAgentPassWord}
    req = requests.post(urlLogin,data=json.dumps(creds),headers=headers,verify=False)
    rjson_auth = req.json()
    if rjson_auth:
        auth_token_json = {"Authorization": f"Token {rjson_auth['token']}"}

    chunk_size  = 20
    target = '27a63100-86cf-4b2a-8ccb-7f67760ba07d'
    customer_id = '1f906516-5bd6-4226-b84c-09e1adb69be6'
    #customer_id = 'f4f63b12-3b21-495b-9c7c-9cde1cf9d3df'
    #customer_id = '7cc6c56a-e201-4062-babf-db79ab2fef42'
    loop= False   
    
    VulnUrl = f'{HostAddress}:{Port}/api/PythonMantis/286c96ff-7cf3-48a6-9301-39bee68f1d0c'

    if auth_token_json:
        getRecords= requests.get(VulnUrl, headers=auth_token_json,verify=False)
    else:
        getRecords= requests.get(VulnUrl,verify=False)
    resp = getRecords
    resp = resp.json()
    if resp is list:
        resp = resp
    else:
        resp = [resp]
    #PATH = ['/admin.php', '/wp-admin', '/wp-login.php']
    PATH = None
    
    for Vuln in resp:
        VulnData = Vuln
        #Elevate_Vuln = Vuln.get("Elevate_Vuln")
        Elevate_Vuln = False
        request_method= Vuln.get("request_method", {})
        path_complex = Vuln.get("ComplexPathPython", {})
        allow_redirects_var = Vuln.get("allow_redirects")
        vulnCard_id = VulnData['vulnCard_id']

        vulnCard_url = f"{HostAddress}:{Port}/api/VulnCard/{vulnCard_id}"        
        if auth_token_json:
            getVulnCard= requests.get(vulnCard_url, headers=auth_token_json,verify=False)
        else:
            getVulnCard= requests.get(vulnCard_url,verify=False)
        rjson= getVulnCard.json()

        vuln_set = dict.fromkeys(['vulnCard'], rjson)
        VulnData.update(vuln_set)
        if Elevate_Vuln:
            urlKnownVulns = f'{HostAddress}:{Port}/api/FoundVuln/'
            if auth_token_json:
                getRecords= requests.get(urlKnownVulns, headers=auth_token_json,verify=False)
            else:
                getRecords= requests.get(urlKnownVulns,verify=False)
            resp_vulns = getRecords.json()
            targets = [ r for r in resp_vulns if r['name'] == Elevate_Vuln]
            path_complex = (Vuln.get("ComplexPathPython"), ())
            PATH = Vuln.get("path", "")
            PATH_CHECK = bool(PATH)
        #matcher area things to find break down put into set for concuption for shredder
            matcher_set = {}
            matchers_status = Vuln.get("matchers_status", {})
            if bool(matchers_status):
                matchers_status = dict.fromkeys(["matchers_status"], matchers_status)
                matcher_set.update(matchers_status)
            else:
                pass
            matchers_headers = (Vuln.get("matchers_headers", {}))
            if bool(matchers_headers):
                matchers_headers = dict.fromkeys(["matchers_headers"], matchers_headers)
                matcher_set.update(matchers_headers)
            else:
                pass
            matchers_bodys = (Vuln.get("matchers_bodys", {}))
            if bool(matchers_bodys):
                matchers_bodys = dict.fromkeys(["matchers_bodys"], matchers_bodys)
                matcher_set.update(matchers_bodys)
            else:
                pass
            matchers_words = (Vuln.get("matchers_words", {}))
            if bool(matchers_words):
                matchers_words = dict.fromkeys(["matchers_words"], matchers_words)
                matcher_set.update(matchers_words)
            else:
                pass
            outset=[]
            for i in targets:
                creds = (Vuln.get("creds", []))
                path_complex = Vuln.get("ComplexPathPython", ())
                if PATH_CHECK == False and bool(path_complex) is True and bool(creds) is True:
                    path_complex =  ast.literal_eval(str(path_complex))
                    resp = dask.delayed(Shredder)(i['DomainName'], Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, creds=creds, path_complex=path_complex, allow_redirects=allow_redirects_var, Vuln=Vuln, matcher_set=matcher_set, 
                                                  HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, RECORD=i, VulnData=VulnData, auth_token_json=auth_token_json)
                    outset.append(resp)

                elif PATH_CHECK == False and bool(path_complex) is True and bool(creds) is False:
                    path_complex =  ast.literal_eval(str(path_complex))
                    resp = dask.delayed(Shredder)(i['DomainName'], Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, creds=creds, path_complex=path_complex, allow_redirects=allow_redirects_var, Vuln=Vuln, matcher_set=matcher_set, 
                                                  HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, RECORD=i, VulnData=VulnData, auth_token_json=auth_token_json)
                    outset.append(resp)
                else:
                    resp = dask.delayed(Shredder)(i['DomainName'], Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, creds=creds, paths=PATH, path_complex=False, allow_redirects=allow_redirects_var, Vuln=Vuln, matcher_set=matcher_set, 
                                                  HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, RECORD=i, VulnData=VulnData, auth_token_json=auth_token_json)
                    
                    outset.append(resp)
            Nuke_responses= dask.compute(*outset)
        elif loop == True:
            LoopCustomers= f"{HostAddress}:{Port}/api/customers/"
            if auth_token_json:
                getRecords= requests.get(LoopCustomers, headers=auth_token_json,verify=False)
            else:
                getRecords= requests.get(LoopCustomers,verify=False)
            
            rjsons= json.loads(getRecords.text)
            id_list= [i['id'] for i in rjsons]
            for customerId in id_list:
                urlhost= f"{HostAddress}:{Port}/api/customers/{customerId}"
                if auth_token_json:
                    getRecords= requests.get(urlhost, headers=auth_token_json,verify=False)
                else:
                    getRecords= requests.get(urlhost,verify=False)
                try:
                    rjson= getRecords.json()
                    RecordsCheck= rjson["customer_records"]
                    Scope= rjson["domainScope"]
                    SCOPE_set= set()
                    SCOPED_set= []
                    for i in rjson["domainScope"]:
                        domain_set= DomainNameValidation.CREATOR(i)
                        if type(domain_set) == str:
                            pass
                        else:
                            SCOPE_set.add(domain_set['domainname'])
                    for i in RecordsCheck:
                        if i["alive"] == False:
                            pass
                        elif '443' not in i['OpenPorts']:
                            pass
                        else:
                            subdomain = i["subDomain"]
                            domain_set= DomainNameValidation.CREATOR(subdomain)
                            domainname = domain_set["domainname"]
                            fulldomain = domain_set["fulldomain"]
                            SCOPED_set.append(i)
                except:
                    pass
                
                
                path_complex = (Vuln.get("ComplexPathPython"), ())
                PATH = Vuln.get("path", "")
                PATH_CHECK = bool(PATH)
            #matcher area things to find break down put into set for concuption for shredder
                matcher_set = {}
                matchers_status = Vuln.get("matchers_status", {})
                if bool(matchers_status):
                    matchers_status = dict.fromkeys(["matchers_status"], matchers_status)
                    matcher_set.update(matchers_status)
                else:
                    pass
                matchers_headers = (Vuln.get("matchers_headers", {}))
                if bool(matchers_headers):
                    matchers_headers = dict.fromkeys(["matchers_headers"], matchers_headers)
                    matcher_set.update(matchers_headers)
                else:
                    pass
                matchers_bodys = (Vuln.get("matchers_bodys", {}))
                if bool(matchers_bodys):
                    matchers_bodys = dict.fromkeys(["matchers_bodys"], matchers_bodys)
                    matcher_set.update(matchers_bodys)
                else:
                    pass
                matchers_words = (Vuln.get("matchers_words", {}))
                if bool(matchers_words):
                    matchers_words = dict.fromkeys(["matchers_words"], matchers_words)
                    matcher_set.update(matchers_words)
                else:
                    pass
                if chunk_size == 0:
                    id_list= [i for i in SCOPED_set]
                    random.shuffle(id_list)
                    shuffled_SCOPED_set= [id_list]
                else:
                    id_list= [i for i in SCOPED_set]
                    id_chunks = list(ToolBox.splited(SCOPED_set, chunk_size))
                    random.shuffle(id_chunks)
                    shuffled_SCOPED_set= id_chunks

                outset= []
                for shuff in shuffled_SCOPED_set:
                    for i in shuff:
                        creds = (Vuln.get("creds", []))
                        path_complex = Vuln.get("ComplexPathPython", ())
                        if PATH_CHECK == False and bool(path_complex) is True and bool(creds) is True:
                            path_complex =  ast.literal_eval(str(path_complex))
                            resp = dask.delayed(Shredder)(i['subDomain'], Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, creds=creds,  path_complex=path_complex, allow_redirects=allow_redirects_var, Vuln=Vuln, matcher_set=matcher_set, 
                                                          HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, RECORD=i, VulnData=VulnData, auth_token_json=auth_token_json)
                            outset.append(resp)

                        elif PATH_CHECK == False and bool(path_complex) is True and bool(creds) is False:
                            path_complex =  ast.literal_eval(str(path_complex))
                            resp = dask.delayed(Shredder)(i['subDomain'], Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, creds=creds, path_complex=path_complex, allow_redirects=allow_redirects_var, Vuln=Vuln, matcher_set=matcher_set, 
                                                          HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, RECORD=i, VulnData=VulnData, auth_token_json=auth_token_json)
                            outset.append(resp)
                        else:
                            resp = dask.delayed(Shredder)(i['subDomain'], Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, creds=creds, paths=PATH, path_complex=False, allow_redirects=allow_redirects_var, Vuln=Vuln, matcher_set=matcher_set, 
                                                          HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, RECORD=i, VulnData=VulnData, auth_token_json=auth_token_json)
                    
                            outset.append(resp)
                Nuke_responses= dask.compute(*outset)
        else:
            urlhost= f"{HostAddress}:{Port}/api/customers/{customer_id}"
            if auth_token_json:
                getRecords= requests.get(urlhost, headers=auth_token_json,verify=False)
            else:
                getRecords= requests.get(urlhost,verify=False)
            rjson= getRecords.json()
            RecordsCheck= rjson["customer_records"]
            Scope= rjson["domainScope"]
            SCOPE_set= set()
            SCOPED_set= []

            for i in rjson["domainScope"]:
                domain_set= DomainNameValidation.CREATOR(i)
                if type(domain_set) == str:
                    pass
                else:
                    SCOPE_set.add(domain_set['domainname'])
            for i in RecordsCheck:
                if i["alive"] == False:
                    pass
                else:
                    subdomain = i["subDomain"]
                    domain_set= DomainNameValidation.CREATOR(subdomain)
                    domainname = domain_set["domainname"]
                    fulldomain = domain_set["fulldomain"]
                    SCOPED_set.append(i)
            
            path_complex = (Vuln.get("ComplexPathPython"), ())
            PATH = Vuln.get("path", "")
            PATH_CHECK = bool(PATH)
        #matcher area things to find break down put into set for concuption for shredder
            matcher_set = {}
            matchers_status = Vuln.get("matchers_status", {})
            if bool(matchers_status):
                matchers_status = dict.fromkeys(["matchers_status"], matchers_status)
                matcher_set.update(matchers_status)
            else:
                pass
            matchers_headers = (Vuln.get("matchers_headers", {}))
            if bool(matchers_headers):
                matchers_headers = dict.fromkeys(["matchers_headers"], matchers_headers)
                matcher_set.update(matchers_headers)
            else:
                pass
            matchers_bodys = (Vuln.get("matchers_bodys", {}))
            if bool(matchers_bodys):
                matchers_bodys = dict.fromkeys(["matchers_bodys"], matchers_bodys)
                matcher_set.update(matchers_bodys)
            else:
                pass
            matchers_words = (Vuln.get("matchers_words", {}))
            if bool(matchers_words):
                matchers_words = dict.fromkeys(["matchers_words"], matchers_words)
                matcher_set.update(matchers_words)
            else:
                pass
            if chunk_size == 0:
                id_list= [i for i in SCOPED_set]
                random.shuffle(id_list)
                shuffled_SCOPED_set= [id_list]
            else:
                id_list= [i for i in SCOPED_set]
                id_chunks = list(ToolBox.splited(SCOPED_set, chunk_size))
                random.shuffle(id_chunks)
                shuffled_SCOPED_set= id_chunks
            outset= []
            for shuff in shuffled_SCOPED_set:
                for i in shuff:
                    creds = (Vuln.get("creds", []))
                    path_complex = Vuln.get("ComplexPathPython", ())
                    if PATH_CHECK == False and bool(path_complex) is True and bool(creds) is True:
                        path_complex =  ast.literal_eval(str(path_complex))
                        resp = dask.delayed(Shredder)(i['subDomain'], Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, creds=creds, path_complex=path_complex, allow_redirects=allow_redirects_var, Vuln=Vuln, matcher_set=matcher_set, 
                                                      HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, RECORD=i, VulnData=VulnData, auth_token_json=auth_token_json)
                        outset.append(resp)

                    elif PATH_CHECK == False and bool(path_complex) is True and bool(creds) is False:
                        path_complex =  ast.literal_eval(str(path_complex))
                        resp = dask.delayed(Shredder)(i['subDomain'], Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, creds=creds, path_complex=path_complex, allow_redirects=allow_redirects_var, Vuln=Vuln, matcher_set=matcher_set, 
                                                      HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, RECORD=i, VulnData=VulnData, auth_token_json=auth_token_json)
                        outset.append(resp)
                    else:
                        resp = dask.delayed(Shredder)(i['subDomain'], Global_Nuclei_CoolDown=Global_Nuclei_CoolDown, creds=creds, paths=PATH, path_complex=False, allow_redirects=allow_redirects_var, Vuln=Vuln, matcher_set=matcher_set, 
                                                      HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, vulnCard=vuln_set, RECORD=i, VulnData=VulnData, auth_token_json=auth_token_json)
                    
                        outset.append(resp)
            Nuke_responses= dask.compute(*outset)




