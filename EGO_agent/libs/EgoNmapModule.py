import dask
import json
import requests
import hashlib
import datetime
import nmap3 


from re import sub
# custom imports
import EgoSettings
from libs.EgoDomainName import *
from libs.EgoNetWork import *
from libs.EgoDomainSearch import *


#EgoNmap.NmapScan

class EgoNmap:
    

    def NmapScan( data, portscan_bool, versionscan_bool, HostAddress=EgoSettings.HostAddress, Port=EgoSettings.Port, auth_token_json=None):
        scan_all_ports = False
        scriptscan_bool = False
        try:

            headers = {"Content-type": "application/json", "Accept": "application/json"}
            if bool(auth_token_json):
                headers.update(auth_token_json)
            else:
                pass
            alive= bool(data['alive'])
            if alive == False:
                pass
            else:
                if portscan_bool == True:
                    alive= bool(data['alive'])
                    if scan_all_ports == False:
                        Scan_target = data['ip']
                        for domain in Scan_target:
                            nmap = nmap3.NmapHostDiscovery()
                            top_1000_ports = '1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4200,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389'
                            top_1000_port_scan_result = nmap.nmap_portscan_only(domain, args=f'-p {top_1000_ports} -Pn --max-retries 6 --min-parallelism 7')
                            top_1000_results = top_1000_port_scan_result.get(domain, {})
                            top_1000_ports = top_1000_results.get('ports', {})
                            top_1000_open_ports = [n['portid'] for n in top_1000_ports if n['state'] == 'open']
                            results= dict.fromkeys(['OpenPorts'] , top_1000_open_ports)
                            data.update(results)
                            return data
                        else:
                            data.update({"alive": False})
                            return data
                    elif scan_all_ports == True:
                        Scan_target = data['ip']
                        for domain in Scan_target:
                            nmap = nmap3.NmapHostDiscovery()
                            top_1000_ports = '1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4200,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389'
                            top_1000_port_scan_result = nmap.nmap_portscan_only(domain, args=f'-p {top_1000_ports} -Pn --max-retries 5 --min-parallelism 3')
                            top_1000_results = top_1000_port_scan_result.get(domain, {})
                            top_1000_ports = top_1000_results.get('ports', {})
                            top_1000_open_ports = [n['portid'] for n in top_1000_ports if n['state'] == 'open']
                            results= dict.fromkeys(['OpenPorts'] , top_1000_open_ports)
                            data.update(results)
                            return data
                        else:
                            data.update({"alive": False})
                            return data
                    else:
                        domain= data['subDomain']
                        domain_set= DomainNameValidation.CREATOR(domain)
                        domainname= domain_set['domainname']
                        Scan_target= domain_set['fulldomain']
                        alive= bool(data['alive'])
                        if alive == False:
                            pass
                        else:
                            nmap = nmap3.NmapHostDiscovery()
                            port_scan_result = nmap.nmap_portscan_only(Scan_target, args='-p 21,22,23,25,53,80,636,43,70,69,88,443,445,110,111,135,139,143,993,995,1723,3306,3389,4200,5900,8080,8443 -Pn --max-retries 6 --min-parallelism 7')
                            StorePorts= []
                            for i in port_scan_result:
                                i= port_scan_result[i]
                                try:
                                    if 'ports' in i:
                                        ports= i['ports']
                                        for i in ports:
                                            state= i['state']
                                            if state == 'open':
                                                state= i['state']
                                                ports= i['portid']
                                                StorePorts.append(ports)
                                except Exception as E:
                                    pass
                            if None not in StorePorts:
                                keys= ["OpenPorts"]
                                results= dict.fromkeys(keys,StorePorts)
                                data.update(results)
                                return data
                            else:
                                return data
                elif versionscan_bool == True:
                    if len(data['ip']) > 0:
                        domains = data['ip']
                    else:
                        host = data['subDomain']
                        domain_set= DomainNameValidation.CREATOR(host)
                        if domain_set == False:
                            domains = False
                        else:
                            domainname= domain_set['domainname']
                            domains = [domain_set['fulldomain']]
                            Record_ID= data['id']
                            alive= bool(data['alive'])
                    Record_ID= data['id']
                    ports = data.get('OpenPorts', {})
                    if domains:
                        for domain in domains:
                            try:
                                list_string_ports = ",".join(ports)
                                nmap = nmap3.Nmap()
                                version_scan_result = nmap.nmap_version_detection(domain,args=f' -p {list_string_ports} -Pn --max-retries 6 --min-parallelism 6')
                                #results_fromkeys = dict.fromkeys(['version_scan_result'], version_scan_result)
                                for i in version_scan_result:
                                    i = version_scan_result[i]
                                    if 'ports' not in str(i):
                                        pass
                                    else:
                                        ports_results = i['ports']
                                        for i in ports_results:
                                            DIC= {}
                                            name_i= i.get('name',{})
                                            port_i= i.get('portid',{})
                                            port_i = dict.fromkeys(['port'], port_i)
                                            protocol_i= i.get('protocol',{})
                                            protocol_i = dict.fromkeys(['protocol'], protocol_i)
                                            cpe=i.get('cpe')
                                            forline = [ c['cpe'].replace('cpe:/','') for c in cpe ]
                                            try:
                                                forline_dict = dict.fromkeys(['cpe'], f"{forline[0]}")

                                            except:
                                                forline_dict = dict.fromkeys(['cpe'], f"")
                                            scripts_i= i.get('scripts')

                                            scripts_dict = dict.fromkeys(['scripts'], scripts_i)
                                            service_i= i.get('service',{})
                                            conf_i= i.get('conf',{})
                                            extrainfo_i= i.get('extrainfo',{})
                                            method_i= i.get('method',{})
                                            ostype_i= i.get('ostype',{})
                                            product_i= i.get('product',{})
                                            version_i= i.get('version',{})
                                            servicefp_i= i.get('servicefp',{})
                                            hostname_i = i.get('hostname',{})
                                            macaddress_i = i.get('macaddress',{})
                                            state_i = i.get('state',{})
                                            state_i = dict.fromkeys(['state'], state_i)
                                            CPE = forline
                                            version = version_i
                                            service= service_i['name']
                                            dict_CPE= dict.fromkeys(['CPE'], CPE)
                                            dict_service = dict.fromkeys(['service'], service)
                                            #nmapNistVulns_i = dict.fromkeys(['nmapNistVulns'], [])
                                            if len(CPE) > 0 and version and not service:
                                                TOTALCPE = f'{CPE[0]}:{version}'
                                            elif len(CPE) > 0 and service and not version:
                                                TOTALCPE = f'{CPE[0]}:{service}'
                                            elif len(CPE) > 0 and version and service:
                                                TOTALCPE = f'{CPE[0]}:{version}:{service}'
                                            else:
                                                TOTALCPETOTALCPE = 'null'
                                            
                                            #DIC.update(nmapNistVulns_i)
                                            DIC.update(name_i)
                                            DIC.update(port_i)
                                            DIC.update(forline_dict)
                                            DIC.update(scripts_dict)
                                            DIC.update(method_i)
                                            DIC.update(protocol_i)
                                            DIC.update(service_i)
                                            DIC.update(conf_i)
                                            DIC.update(extrainfo_i)
                                            DIC.update(method_i)
                                            DIC.update(ostype_i)
                                            DIC.update(product_i)
                                            DIC.update(version_i)
                                            DIC.update(servicefp_i)
                                            DIC.update(hostname_i)
                                            DIC.update(macaddress_i)
                                            DIC.update(state_i)
                                            record_id= dict.fromkeys(['record_id'], Record_ID)
                                            DIC.update(record_id)
                                            md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()
                                            results = dict.fromkeys(['md5'], md5_hash)
                                            DIC.update(results)
                                            urlPost = f"{HostAddress}:{Port}/api/Nmap/create" 
                                            recs= json.dumps(DIC)
                                            DIC_headers = {}
                                            if auth_token_json:
                                                DIC_headers.update(auth_token_json)
                                            else:
                                                pass                                        
                                            DIC_headers.update(headers)
                                            postRecords = requests.post(urlPost, data=recs, headers=DIC_headers, verify=False, timeout=60)
                                            pass 
                            except Exception as E:
                                return('nmap failed nested nmap failed out')
                elif scriptscan_bool == True:
                    if len(data['ip']) > 0:
                        domains = data['ip']
                    else:
                        host = data['subDomain']
                        domain_set= DomainNameValidation.CREATOR(host)
                        if domain_set == False:
                            domains = False
                        else:
                            domainname= domain_set['domainname']
                            domains = [domain_set['fulldomain']]
                            Record_ID= data['id']
                            alive= bool(data['alive'])
                    Record_ID= data['id']
                    ports = data.get('OpenPorts', {})
                    if domains:
                        for domain in domains:
                            if alive == False:
                                pass
                            else:
                                try:
                                    list_string_ports = ",".join(ports)
                                    nmap = nmap3.Nmap()
                                    version_scan_result = nmap.nmap_version_detection(domain,args=f' -sC -p {list_string_ports} -Pn --max-retries 6 --min-parallelism 6')
                                    #results_fromkeys = dict.fromkeys(['version_scan_result'], version_scan_result)
                                    for i in version_scan_result:
                                        i = version_scan_result[i]
                                        if 'ports' not in str(i):
                                            pass
                                        else:
                                            ports_results = i['ports']
                                            for i in ports_results:
                                                DIC= {}
                                                name_i= i.get('name',{})
                                                port_i= i.get('portid',{})
                                                port_i = dict.fromkeys(['port'], port_i)
                                                protocol_i= i.get('protocol',{})
                                                protocol_i = dict.fromkeys(['protocol'], protocol_i)
                                                cpe=i.get('cpe')
                                                forline = [ c['cpe'].replace('cpe:/','') for c in cpe ]
                                                try:
                                                    forline_dict = dict.fromkeys(['cpe'], f"{forline[0]}")

                                                except:
                                                    forline_dict = dict.fromkeys(['cpe'], f"")
                                                scripts_i= i.get('scripts')

                                                scripts_dict = dict.fromkeys(['scripts'], scripts_i)
                                                service_i= i.get('service',{})
                                                conf_i= i.get('conf',{})
                                                extrainfo_i= i.get('extrainfo',{})
                                                method_i= i.get('method',{})
                                                ostype_i= i.get('ostype',{})
                                                product_i= i.get('product',{})
                                                version_i= i.get('version',{})
                                                servicefp_i= i.get('servicefp',{})
                                                hostname_i = i.get('hostname',{})
                                                macaddress_i = i.get('macaddress',{})
                                                state_i = i.get('state',{})
                                                state_i = dict.fromkeys(['state'], state_i)
                                                CPE = forline
                                                version = version_i
                                                service= service_i['name']
                                                dict_CPE= dict.fromkeys(['CPE'], CPE)
                                                dict_service = dict.fromkeys(['service'], service)
                                                if len(CPE) > 0 and version and not service:
                                                    TOTALCPE = f'{CPE[0]}:{version}'
                                                elif len(CPE) > 0 and service and not version:
                                                    TOTALCPE = f'{CPE[0]}:{service}'
                                                elif len(CPE) > 0 and version and service:
                                                    TOTALCPE = f'{CPE[0]}:{version}:{service}'
                                                else:
                                                    TOTALCPE = 'null'
                                                if TOTALCPE == 'null':
                                                    #nmapNistVulns_i = dict.fromkeys(['nmapNistVulns'], [])
                                                    #DIC.update(nmapNistVulns_i)
                                                    DIC.update(name_i)
                                                    DIC.update(port_i)
                                                    DIC.update(forline_dict)
                                                    DIC.update(scripts_dict)
                                                    DIC.update(method_i)
                                                    DIC.update(protocol_i)
                                                    DIC.update(service_i)
                                                    DIC.update(conf_i)
                                                    DIC.update(extrainfo_i)
                                                    DIC.update(method_i)
                                                    DIC.update(ostype_i)
                                                    DIC.update(product_i)
                                                    DIC.update(version_i)
                                                    DIC.update(servicefp_i)
                                                    DIC.update(hostname_i)
                                                    DIC.update(macaddress_i)
                                                    DIC.update(state_i)
                                                    record_id= dict.fromkeys(['record_id'], Record_ID)
                                                    DIC.update(record_id)
                                                    md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()

                                                    results = dict.fromkeys(['md5'], md5_hash)
                                                    DIC.update(results)
                                                    urlPost = f"{HostAddress}:{Port}/api/Nmap/create"    
                                                    recs= json.dumps(DIC)
                                                    DIC_headers = {}
                                                    postRecords = requests.post(
                                                        urlPost, 
                                                        data=recs, 
                                                        headers=headers,
                                                        verify=False,
                                                        timeout=60
                                                        )
                                                    pass 
                                                else:
                                                    CPEID_i = dict.fromkeys(['CPEID_id'], TOTALCPE)
                                                    url = f"{HostAddress}:{Port}/api/Nist/"
                                                    nist_url = requests.get(
                                                        url=url,
                                                        verify=False,
                                                        headers=headers,
                                                        timeout=60
                                                        )
                                                    nist_rjson = nist_url.json()
                                                    nist_cpe_check = [ cpe for cpe in nist_rjson if cpe['cpeId'] == CPE ]
                                                    if len(nist_cpe_check) > 0:
                                                        pass
                                                    else:
                                                        CPEID = f'{CPE}:{service}'
                                                        dict_cpeid = dict.fromkeys(['cpeId'], CPEID)
                                                        CPEServiceID_id = dict.fromkeys(['CPEServiceID'], CPEID)
                                                        headers = {"Content-type": "application/json", "Accept": "application/json"}
                                            
                                                        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:{TOTALCPE}"
                                                        header = {"Authorization": "bearer  ee7d9713-3103-4285-a191-e8e582864dd8"}
                                                        try:
                                                            nist_rjson_response = requests.get(
                                                                url=url,
                                                                headers=header, 
                                                                timeout=60
                                                            )
                                                            nist_rjson = nist_rjson_response.json()
                                                            vulns = (nist_rjson.get('vulnerabilities'))



                                                            nist_dict=[]
                                                            for vuln in vulns:
                                                                cve=vuln.get('cve')
                                                                for k in cve:
                                                                    if k == 'descriptions':
                                                                        DICnist_rjson ={}
                                                                        descript= cve.get('descriptions')
                                                                        descout = descript[0]
                                                                        descout = descout.get('value')
                                                                        DESCRIPT= dict.fromkeys(['descriptions'], descout)
                                                                        DICnist_rjson.update(DESCRIPT)
                                                                        references=[ ref.get('url') for ref in cve.get('references') ]
                                                                        refeDict= dict.fromkeys(['references'], references)
                                                                        DICnist_rjson.update(refeDict)
                                                                        for d in descript:
                                                                            metrics = (cve.get('metrics'))
                                                                            cvs = metrics.get('cvssMetricV2', {})

                                                                            for score in cvs:

                                                                                s = score.get('cvssData')
                                                                                DICnist_rjson.update(s)
                                                                                nist_dict.append(DICnist_rjson)
                                                                                csv_url = f'{HostAddress}:{Port}/api/csv_version/'
                                                                                resp = requests.get(
                                                                                    url=csv_url,
                                                                                    headers=headers,
                                                                                    verify=False, 
                                                                                    timeout=60
                                                                                    )
                                                                                csv_resp = resp.json()
                                                                                csv_id_found_Not = [ csv['vectorString'] for csv in csv_resp if csv['vectorString'] != s['vectorString'] ]
                                                                                csv_id_found_True = [ csv['vectorString'] for csv in csv_resp if csv['vectorString'] == s['vectorString'] ]

                                                                                nisturl= f'{HostAddress}:{Port}/api/Nist/'
                                                                                request = requests.get(
                                                                                    url=nisturl,
                                                                                    headers=headers,
                                                                                    verify=False, 
                                                                                    timeout=60
                                                                                    )
                                                                                recs = request.json()
                                                                                csv_id_found_dict = dict.fromkeys(['csv_version_id'],csv_id_found_Not[0])
                                                                                if len(recs) == 0:
                                                                                    dic={}
                                                                                    dic.update(dict_cpeid)
                                                                                    dic.update(dict_CPE)
                                                                                    dic.update(dict_service)
                                                                                    nisturl_create= f'{HostAddress}:{Port}/api/Nist/create'
                                                                                    recs = json.dumps(dic)
                                                                                    request = requests.post(
                                                                                        url=nisturl_create,
                                                                                        headers=headers,
                                                                                        data=recs,
                                                                                        verify=False, 
                                                                                        timeout=60)

                                                                                if len(csv_resp) == 0:
                                                                                    dic = {}
                                                                                    dic.update(s)
                                                                                    csv_urlcreate = f'{HostAddress}:{Port}/api/csv_version/create'
                                                                                    recs = json.dumps(s)
                                                                                    request = requests.post(
                                                                                        url=csv_urlcreate, 
                                                                                        headers=headers, 
                                                                                        data=recs,
                                                                                        verify=False, 
                                                                                        timeout=60
                                                                                        )
                                                                                    csv_urlcreateresp= request.json()

                                                                                    nistdesp_url = f'{HostAddress}:{Port}/api/NistDescription/'
                                                                                    deresp = requests.get(url=nistdesp_url)
                                                                                    deresp_json = deresp.json()
                                                                                    if len(deresp_json) == 0:
                                                                                        nistdesp_create_url = f'{HostAddress}:{Port}/api/NistDescription/create'
                                                                                        dic = {}
                                                                                        dic.update(dict_CPE)
                                                                                        dic.update(refeDict)
                                                                                        dic.update(DESCRIPT)
                                                                                        dic.update(dict_service)
                                                                                        dic.update(CPEServiceID_id)
                                                                                        dic.update(csv_id_found_dict)
                                                                                        recs = json.dumps(dic)
                                                                                        request = requests.post(
                                                                                            url=nistdesp_create_url, 
                                                                                            headers=headers, 
                                                                                            data=recs,
                                                                                            verify=False, 
                                                                                            timeout=60
                                                                                            )
                                                                                        resp= request.json()
                                                                                        #nmapNistVulns_i = dict.fromkeys(['nmapNistVulns'], resp['id']) 
                                                                                        descr_check = [resp for resp in deresp_json if resp['descriptions'] == str(descript)]
                                                                                    else:
                                                                                        pass
                                                                                        #nmapNistVulns_i = dict.fromkeys(['nmapNistVulns'], [])
                                                                                else:
                                                                                    if len(csv_id_found_Not) == 0 :
                                                                                        dic = {}
                                                                                        dic.update(s)

                                                                                        csv_urlcreate = f'{HostAddress}:{Port}/api/csv_version/create'
                                                                                        recs = json.dumps(s)
                                                                                        request = requests.post(
                                                                                            url=csv_urlcreate , 
                                                                                            headers=headers, 
                                                                                            data=recs,
                                                                                            verify=False, 
                                                                                            timeout=60
                                                                                            )

                                                                                        csv_urlcreateresp= request.json()

                                                                                        nistdesp_url = f'{HostAddress}:{Port}/api/NistDescription/'
                                                                                        deresp = requests.get(
                                                                                            url=nistdesp_url,
                                                                                            headers=headers,
                                                                                            verify=False, 
                                                                                            timeout=60
                                                                                            )
                                                                                        deresp_json = deresp.json()
                                                                                        if len(deresp_json) == 0:
                                                                                            nistdesp_create_url = f'{HostAddress}:{Port}/api/NistDescription/create'
                                                                                            dic = {}
                                                                                            dic.update(dict_CPE)
                                                                                            dic.update(refeDict)
                                                                                            dic.update(DESCRIPT)
                                                                                            dic.update(dict_service)
                                                                                            dic.update(CPEServiceID_id)
                                                                                            dic.update(csv_id_found_dict)
                                                                                            recs2 = json.dumps(dic)
                                                                                            request = requests.post(
                                                                                                url=nistdesp_create_url, 
                                                                                                headers=headers, 
                                                                                                data=recs2,
                                                                                                verify=False, 
                                                                                                timeout=60
                                                                                                )
                                                                                            resp= request.json()
                                                                                            #nmapNistVulns_i = dict.fromkeys(['nmapNistVulns'], resp['id']) 
                                                                                            descr_check = [resp for resp in deresp_json if resp['descriptions'] == str(descript)]
                                                                                        else:
                                                                                            pass
                                                                                            #nmapNistVulns_i = dict.fromkeys(['nmapNistVulns'], [])
                                                                                    elif len(csv_id_found_True) > 0:
                                                                                        csv_id_found_dict = dict.fromkeys(['csv_version_id'],csv_id_found_True[0])
                                                                                        nistdesp_url = f'{HostAddress}:{Port}/api/NistDescription/'
                                                                                        deresp = requests.get(
                                                                                            url=nistdesp_url,
                                                                                            headers=headers,
                                                                                            verify=False, 
                                                                                            timeout=60
                                                                                            )
                                                                                        deresp_json = deresp.json()

                                                                                        nistdesp_create_url = f'{HostAddress}:{Port}/api/NistDescription/create'
                                                                                        dic = {}
                                                                                        dic.update(dict_CPE)
                                                                                        dic.update(refeDict)
                                                                                        dic.update(DESCRIPT)
                                                                                        dic.update(dict_service)
                                                                                        dic.update(CPEServiceID_id)

                                                                                        dic.update(csv_id_found_dict)
                                                                                        recs = json.dumps(dic)
                                                                                        request = requests.post(
                                                                                            url=nistdesp_create_url, 
                                                                                            headers=headers, 
                                                                                            data=recs,
                                                                                            verify=False, 
                                                                                            timeout=60
                                                                                            )
                                                                                        resp= request.json()

                                                                                        #nmapNistVulns_i = dict.fromkeys(['nmapNistVulns'], resp['id']) 
                                                                                        descr_check = [resp for resp in deresp_json if resp['descriptions'] == str(descript)]
                                                                                    else:
                                                                                        #nmapNistVulns_i = dict.fromkeys(['nmapNistVulns'], [])
                                                                                        pass
                                                        except Exception as E:
                                                            #nmapNistVulns_i = dict.fromkeys(['nmapNistVulns'], [])
                                                            pass
                                                        #DIC.update(nmapNistVulns_i)
                                                        DIC.update(name_i)
                                                        DIC.update(port_i)
                                                        DIC.update(forline_dict)
                                                        DIC.update(scripts_dict)
                                                        DIC.update(method_i)
                                                        DIC.update(protocol_i)
                                                        DIC.update(service_i)
                                                        DIC.update(conf_i)
                                                        DIC.update(extrainfo_i)
                                                        DIC.update(method_i)
                                                        DIC.update(ostype_i)
                                                        DIC.update(product_i)
                                                        DIC.update(version_i)
                                                        DIC.update(servicefp_i)
                                                        DIC.update(hostname_i)
                                                        DIC.update(macaddress_i)
                                                        DIC.update(state_i)
                                                        record_id= dict.fromkeys(['record_id'], Record_ID)
                                                        DIC.update(record_id)
                                                        md5_hash = hashlib.md5(json.dumps(DIC, sort_keys=True).encode('utf-8')).hexdigest()

                                                        results = dict.fromkeys(['md5'], md5_hash)
                                                        DIC.update(results)
                                                        urlPost = f"{HostAddress}:{Port}/api/Nmap/create"    
                                                        recs= json.dumps(DIC)
                                                        DIC_headers = {}
                                                        if auth_token_json:
                                                            DIC_headers.update(auth_token_json)
                                                        else:
                                                            pass
                                                        DIC_headers.update(headers)
                                                        postRecords = requests.post(
                                                            urlPost, 
                                                            data=recs, 
                                                            headers=DIC_headers, 
                                                            verify=False, 
                                                            timeout=60
                                                            )
                                except Exception as E:
                                    return('nmap failed nested nmap failed out')

                else:
                    return('nmap failed nested nmap failed out')
        except Exception as E:

