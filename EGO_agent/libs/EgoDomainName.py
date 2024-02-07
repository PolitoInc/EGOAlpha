import dask
import json
import requests
import hashlib
import datetime
import tldextract
import dns.zone
import dns.ipv4
import ipaddress
import hashlib
import re

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def db_name(domain_data):
    domain_data = str(domain_data)
    if "." in domain_data:
        domain = (domain_data.split(".", -2)[-2])
        value = sub(r"[^-.0-9a-zA-Z]+", "", domain)
        return(value)
    else:
        domain = domain_data
        return(domain)

class Ego_IP:
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
        
class DomainNameValidation:
    
    def CREATOR( domains):
        try:
            if type(domains) is not str:
                return False
            elif 'https://' in str(domains) or 'http://' in str(domains):
                reg = r'^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)'
                finddomain= re.findall(reg, domains)
                domain = (finddomain[0]).strip()
                D_bool= bool(domain)
                if Ego_IP.validIPNetWorks(domain) == True:
                    if domain is None:
                        set = {"Ipv": ["None"]}
                    else:
                        set = {"Ipv": [str(ip) for ip in ipaddress.IPv4Network(domain)]}
                        return set

                elif Ego_IP.validIPAddress(domain) == True:
                    if domain is None:
                        set = {"Ipv": ["None"]}
                    else:
                        set = {"Ipv": [domain]}
                        return set
        
                elif Ego_IP.validIPAddress(domain) == False:
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
            else:
                D_bool= bool(domains)
                if Ego_IP.validIPNetWorks(domains) == True:
                    domain= domains
                    if domain is None:
                        set = {"Ipv": ["None"]}
                    else:
                        set = {"Ipv": [str(ip) for ip in ipaddress.IPv4Network(domains)]}
                        return set
                elif Ego_IP.validIPAddress(domains) == True:
                    if domains is None:
                        set = {"Ipv": ["None"]}
                    else:
                        set = {"Ipv": [domains]}
                        return set
        
                elif Ego_IP.validIPAddress(domains) == False:
                    if domains is None:
                        pass
                    else:
                        tldExtracted= tldextract.extract(domains)
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
        except Exception as E:
            print('domainname 1', E)