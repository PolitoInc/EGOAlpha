# rc'on/serializers
from rest_framework import serializers, viewsets
from django.db.models import Count
import uuid
from ego.models import * 
from ego.forms import *
from collections import Counter, OrderedDict
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User

#user creation user serializer with two factor 

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']
        
#########################
####    Customer serializers
#######################   
class RecordSerializer(serializers.ModelSerializer):
    supportingTechnologyHeaders = serializers.SerializerMethodField()
    class Meta:
        model = Record
        fields = (
            'id',
            'customer_id',
            'md5',
            'domainname',
            'subDomain',
            'supportingTechnologyHeaders',
            'lastScan',
            'skipScan',
            'dateCreated',
            'alive',
            'nucleiBool',
            'ip',
            'OpenPorts',
            'CertBool',
            'OpenPorts',
            'CMS',
            'ASN',
            'Images',
        )

    def get_supportingTechnologyHeaders(self, obj):
        results = RequestMetaData.objects.filter(record_id=obj.id)
        server_list = None
        # Iterate over the QuerySet
        for result in results:
            # Now you can access 'headers' because 'result' is a RequestMetaData instance
            if result.headers:
                if 'server' in result.headers.keys():
                    server_list = result.headers['server']
                    break
        return server_list

# the html pages for the scanned domain includes cookies, headers, and paths 
class RequestMetaDataSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = RequestMetaData
        fields = (
            'id',
            'record_id',
            'md5',
            'status',
            'redirect',
            'paths',
            'cookies',
            'headers',
            'backend_headers',
            'headerValues',
            'htmlValues',
            'rawHTML'
            )


    

class limitedCustomerSerializer(serializers.ModelSerializer):
    record_count = serializers.SerializerMethodField()
    active = serializers.SerializerMethodField()
    inactive = serializers.SerializerMethodField()
    activeSubdomains = serializers.SerializerMethodField()
    InactiveSubdomains = serializers.SerializerMethodField()
    supportingTechnologyNmap = serializers.SerializerMethodField()
    supportingTechnologyHeaders = serializers.SerializerMethodField()    
    class Meta:
        model = Customers
        fields = (
            'id',
            'groupingProject',
            'nameProject',
            'nameCustomer',
            'dateCreated',
            'egoOnly',
            'toScanDate',
            'endToScanDate',
            'lastEgoScan',
            'EgoReconScan',
            'customDaysUntilNextScan',
            'FoundTLD',
            'FoundASN',
            'skipScan',
            'record_count',
            'supportingTechnologyNmap' ,
            'supportingTechnologyHeaders',
            'active',
            'activeSubdomains',
            'inactive',
            'InactiveSubdomains',
            )
    def get_supportingTechnologyHeaders(self, obj):
        server_list = []
        # Access the records for the customer
        records = Record.objects.filter(customer_id=obj.id)
        for record in records:
            # Access the RequestMetaData for the record
            request_metadata = RequestMetaData.objects.filter(record_id=record.id)
            for result in request_metadata:
                headers = result.headers
                if 'server' in headers.keys():
                    server_list.append(headers['server'])
                elif 'Sever' in headers.keys():
                    server_list.append(headers['Sever'])
        # Count the occurrences of each server
        server_dict = dict(Counter(server_list))
        return server_dict

    def get_supportingTechnologyNmap(self, obj):
        product_list = []
        # Access the records for the customer
        records = Record.objects.filter(customer_id=obj.id)
        for record in records:
            # Access the RequestMetaData for the record
            Nmap_metadata = Nmap.objects.filter(record_id=record.id)
            nes_product_list = []
            for result in Nmap_metadata:
                product = result.product
                if product is not None and bool(product) == True and product not in nes_product_list:
                    nes_product_list.append(product)
            if len(nes_product_list) > 0:
                product_list.extend(nes_product_list)  # Use extend instead of append
        # Count the occurrences of each product
        product_dict = dict(Counter(product_list))
        return product_dict

    def get_record_count(self, obj):
        return Record.objects.filter(customer_id=obj.id).count()   

    def get_active(self, obj):
        return Record.objects.filter(alive=True, customer_id=obj.id).count()

    def get_inactive(self, obj):
        return self.get_record_count(obj) - self.get_active(obj)
    
    def get_activeSubdomains(self, obj):
        # Get the Records associated with the Customer
        records = Record.objects.filter(customer_id=obj.id)

        # Extract the subDomain values and convert to a list
        subdomain_list = [record.subDomain for record in records if record.alive == True]

        return subdomain_list

    def get_InactiveSubdomains(self, obj):
        # Get the Records associated with the Customer
        records = Record.objects.filter(customer_id=obj.id)

        # Extract the subDomain values and convert to a list
        subdomain_list = [record.subDomain for record in records if record.alive == False]

        return subdomain_list

class CustomerSerializer(serializers.ModelSerializer):

    class Meta:
        model = Customers
        fields = (
            'id',
            'groupingProject',
            'nameProject',
            'nameCustomer',
            'dateCreated',
            'customDaysUntilNextScan',
            'toScanDate',
            'endToScanDate',
            'URLCustomer',
            'lastEgoScan',
            'EgoReconScan',
            'egoOnly',
            'passiveAttack',
            'agressiveAttack',
            'notes',
            'OutOfScopeString',
            'urlScope',
            'outofscope',
            'domainScope',
            'Ipv4Scope',
            'Ipv6Scope',
            'FoundTLD',
            'FoundASN',
            'skipScan',
            )
 
    
#########################
####    Whois serializers
#######################
class Whois_serializers(serializers.ModelSerializer):
    class Meta:
        model = whois
        fields = [
            'id',
            'customer_id',
            'domain_name',
            'registrar',
            'whois_server',
            'referral_url',
            'updated_date',
            'creation_date',
            'expiration_date',
            'name_servers',
            'status',
            'emails',
            'dnssec',
            'name',
            'org',
            'address',
            'city',
            'state',
            'registrant_postal_code',
            'country',
            'map_image',
            ]

#########################
####    Nist serializers
#######################
class csv_version_version_serializers(serializers.ModelSerializer):
    class Meta:
        model = csv_version
        fields = (

                'version',
                'vectorString',
                'accessVector',
                'accessComplexity',
                'authentication',
                'confidentialityImpact',
                'integrityImpact',
                'availabilityImpact',
                'baseScore',
                'baseSeverity'
                )

class nist_description_serializers(serializers.ModelSerializer):
    class Meta:
        model = nist_description
        fields = (
            'id',
            'CPEServiceID',
            'csv_version_id',
            'CPE',
            'service',
            'descriptions',
            'references'
            )

class nistCPEID_serializers(serializers.ModelSerializer):
    class Meta:
        model = CPEID
        fields = (
            'cpeId',
            'CPE', 
            'service',
            'version'
            )


    
#########################
####    word list serializers
#######################

class WordListSerializer(serializers.ModelSerializer):
    class Meta:
        model = WordList
        fields = (
            'id',
            'WordList',
            'type',
            'Value',
            'Occurance',
            'foundAt'
            )

class WordListGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = WordListGroup
        fields = (
            'id',
            'groupName',
            'type',
            'description',
            'count',
            )
        

#########################
####    Control serializers
#######################

class GnawControlSerializer(serializers.ModelSerializer):
    class Meta:
        model = GnawControl
        fields = '__all__'

class EgoControlSerializer(serializers.ModelSerializer):
    class Meta:
        model = EgoControl
        fields = (
            'id',
            #'agent',
            'OutOfScope',
            'ScanProjectByID',
            'ScanGroupingProject',
            'ScanProjectByName',
            'chunk_size',
            'CoolDown',
            'CoolDown_Between_Queries',
            'Port',
            'HostAddress',
            'passiveAttack',
            'agressiveAttack',
            'portscan_bool',
            'versionscan_bool',
            'Scan_Scope_bool',
            'Scan_IPV_Scope_bool',
            'Scan_DomainName_Scope_bool',
            'BruteForce',
            'BruteForce_WL',
            'scan_records_censys',
            'Update_RecordsCheck',
            'crtshSearch_bool',
            'LoopCustomersBool',
            'Completed',
            'Gnaw_Completed',
            'failed',
            )

class MantisControlSerializer(serializers.ModelSerializer):
    class Meta:
        model = MantisControls
        fields = (
            'id',
            #'agent',
            'OutOfScope',
            'NucleiScan',
            'Ipv_Scan',
            'LoopCustomersBool',
            'ScanProjectByID',
            'ScanGroupingProject',
            'ScanProjectByName',
            'Customer_chunk_size',
            'Record_chunk_size',
            'Global_Nuclei_CoolDown',
            'Global_Nuclei_RateLimit',
            'Port',
            'HostAddress',
            'severity',
            'Elavate',
            'Gnaw_Completed',
            'failed'
            )

##############################
##### manager/api/credentials
##############################


class FindingMatrixSerializer(serializers.ModelSerializer):
    class Meta:
        model = FindingMatrix
        fields = (
            'id',
            'projectManMatrix_id',
            'record_id',
            'found',
            'manager',
            'author',
            'created',
            'updated',
            'updatedBy',
            'type',
            'component',
            'seveiry',
            'compelxity',
            'risk',
            'threat',
            'locations',
            'impact',
            'details',
            'example_location',
            'remediation',
            'references',
            'Images',
            'Files'
            )

#############################################################
#############################################################
class apiSerialiser(serializers.ModelSerializer):
    class Meta:
        model = api
        fields = [
            'id',
            'apiproviders_id',
            'dateCreated',
            'lastEgoScan',
            'EgoReconScan',
            'whentouse',
            'apiId',
            'apiKey',
            'passWord',
            'userName',
            'inuse'
            ]

class apiprovidersSerialiser(serializers.ModelSerializer):
    class Meta:
        model = apiproviders
        fields = [
            'id',
            'name'
            ]

#############################################################
#############################################################

class apiProviderApisSerialiser(serializers.ModelSerializer):
    ApiProviders= apiSerialiser(many=True)
    class Meta:
        model = apiproviders
        fields = [
            'id',
            'name',
            'ApiProviders'
            ]

#############################################################
#############################################################
class TemplatesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Template
        fields = (
            'id',
            'record_id',
            'date',
            'md5',
            'template',
            'template_url',
            'template_id',
            'info',
            'host',
            'matched_at',
            'timestamp',
            'extracted_results',
            'curl_command'
            )
#############################################################
#############################################################
class VulnCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnCard
        fields = (
            'id',
            'name',
            'vulnClass',
            'author',
            'severity',
            'cvss_metrics',
            'cvss_score',
            'cwe_id',
            'description',
            'impact',
            'proof_of_concept',
            'remediation',
            'references',
            'pictures'
        )
#############################################################
#############################################################
class FoundVulnDetailSerializers(serializers.ModelSerializer):
    class Meta:
        model = FoundVulnDetails
        fields = (
        'id',
        'FoundVuln_id',
        'DomainName',
        'location',
        'creds',
        'pictures',
        'matchers_status',
        'match_headers',
        'matchedAt_headers',
        'match_bodys',
        'matchedAt_bodys',
        'curl_command',
        )

class FoundVulnSerializer(serializers.ModelSerializer):
    class Meta:
        model = FoundVuln
        fields = (
            'id',
            'vuln_cardId',
            'record_id',
            'severity',
            'date',
            'name',
            'vulnClass',
            'author',
            'cvss_metrics',
            'cvss_score',
            'cwe_id',
            'DomainName',
            'creds',
            'description',
            'location',
            'impact',
            'proof_of_concept',
            'remediation',
            'references',
            'exploitDB',
            'addtional_data',       
            'matchers_status',
            'match_headers',
            'matchedAt_headers',
            'match_bodys',
            'matchedAt_bodys',
            'Submitted'
        )

class TotalFoundVulnSeerializers(serializers.ModelSerializer):
    VulnDetails = FoundVulnDetailSerializers(many=True)
    class Meta:
        model = FoundVuln
        fields = (
            'id',
            'vuln_cardId',
            'record_id',
            'DomainName',
            'name',
            'severity',
            'date',
            'vulnClass',
            'author',
            'cvss_metrics',
            'cvss_score',
            'cwe_id',
            'VulnDetails',
            'description',
            'impact',
            'proof_of_concept',
            'remediation',
            'references',
            'exploitDB',
            'addtional_data',       
            'Submitted'
            )
#############################################################
#############################################################

class PythonMantisSerializer(serializers.ModelSerializer):

    class Meta:
        model = PythonMantis
        fields = (
            'id',
            'vulnCard_id',
            'Elevate_Vuln',
            'name',
            'callbackServer',
            'callbackServerKey',
            'request_method',
            'payloads',
            'headers',
            'postData',
            'ComplexPathPython',
            'ComplexAttackPython',
            'path',
            'creds',
            'pathDeveloper',
            'rawRequest',
            'SSL',
            'timeout_betweenRequest',
            'repeatnumb',
            'redirect',
            'matchers_status',
            'matchers_headers',
            'matchers_bodys',
            'matchers_words',
            'shodan_query',
            'google_dork',
            'tags',
            'tcpversioning'
            )
#############################################################
#############################################################
class ThreatModelingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatModeling
        fields = (
            'id',
            'customer'
            )

#############################################################
#############################################################

class CredentialsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Credential
        fields = (
            'credential',
            'domainname',
            'username',
            'password'
            )
#############################################################
#############################################################
class CertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificate
        fields = (
            'id',
            'record_id',
            'md5',
            'countryName',
            'stateOrProvinceName',
            'organizationName',
            'localityName',
            'subjectAltName',
            'OCSP',
            'caIssuers',
            'crlDistributionPoints',
            'PEM'
            )
#############################################################
#############################################################
class DNSQuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = DNSQuery
        fields = (
            'id',
            'record_id',
            'md5',
            'A',
            'AAAA',  
            'NS',
            'CNAME',
            'r',
            'MX',
            'TXT',
            'ANY'
            )
#############################################################
#############################################################
class DNSAuthoritySerializer(serializers.ModelSerializer):
    class Meta:
        model = DNSAuthority
        fields = (
            'id',
            'record_id',
            'md5',
            'A',
            'AAAA',  
            'NS',
            'CNAME',
            'r',
            'MX',
            'TXT',
            'ANY'
            )
#############################################################
#############################################################
class NmapSerializer(serializers.ModelSerializer):
    class Meta:
        model = Nmap
        fields = (
            'id',
            'record_id',
            #'nmapNistVulns',
            'md5',
            'date',
            'name',
            'port',
            'protocol',
            'service',
            'cpe',
            'scripts',
            'conf',
            'extrainfo',
            'method',
            'ostype',
            'product',
            'version',
            'servicefp',
            'state',
            'hostname',
            'macaddress'
            )

#############################################################
#############################################################
class NucleiSerializer(serializers.ModelSerializer):
    class Meta:
        model = Nuclei
        fields = (
            'id',
            'record_id',
            'md5',
            'date',
            'name',
            'method',
            #'severity',
            'vulnerable'
            )

class TotalRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Record
        fields = (
            'id',
            'customer_id',
            'md5',
            'domainname',
            'subDomain',
            'lastScan',
            'skipScan',
            'dateCreated',
            'alive',
            'nucleiBool',
            'ip',
            'OpenPorts',
            'CertBool',
            'OpenPorts',
            'CMS',
            'ASN',
            'Images',
            )

#############################################################        
class GEOCODESerializer(serializers.ModelSerializer):
    class Meta:
        model = GEOCODES
        fields = (
            'id',
            'record_id',
            'ip_address',
            'city',
            'region',
            'country',
            'latitude',
            'longitude'
            )


#########################
####    Control
#######################
#########################
####    Control
#######################
class DirectoryListingWordListSerializer(serializers.ModelSerializer):
    #WordList = serializers.SlugRelatedField(queryset=WordList.objects.filter(), many=True, slug_field='Value')
    WordList = WordListSerializer(many=True)
    class Meta:
        model = WordListGroup
        fields = [
            'id',
            'groupName',
            'description',
            'count',
            'WordList'
            ]
#############################################################
#############################################################
class Nist_serializers(serializers.ModelSerializer):
    class Meta:
        model = nist_description
        fields = (
            'id',
            'CPEServiceID',
            'csv_version_id',
            'CPE',
            'service',
            'descriptions',
            'references',
            )

#############################################################
#############################################################
class nist_descript_Nist_serializers(serializers.ModelSerializer):
    CPEService = nistCPEID_serializers(many=True)
    CsvVersion = csv_version_version_serializers(many=True)
    class Meta:
        model = nist_description
        fields = (
            'id',
            'CPEServiceID',
            'csv_version_id',
            'CPE',
            'service',
            'descriptions',
            'references',
            'CPEService',
            'CsvVersion'
            )
    def create(self, validated_data):

        _data = validated_data.pop('CsvVersion')
        record = csv_version.objects.create(**validated_data)
        for record in _data:
            csv_version.objects.create(record=record, **record)

        _data = validated_data.pop('CPEService')
        record = CPEID.objects.create(**validated_data)
        for record in _data:
            CPEID.objects.create(record=record, **record)

        for record in _data:
            nist.objects.create(record=record, **record)
        return record

#############################################################
#############################################################
class Totalnist_serializers(serializers.ModelSerializer):
    Nist_records = nist_description_serializers(many=True)
    class Meta:
        model = CPEID
        fields = (
            'id',
            'CPEID_record', 
            'nist_record_id',
            'Nist_records'
            )
    def create(self, validated_data):
        _data = validated_data.pop('Nist_records')
        record = nist_description.objects.create(**validated_data)
        for record in _data:
            nist_description.objects.create(record=record, **record)

        for record in _data:
            CPEID.objects.create(record=record, **record)
        return record

class TotalRecords(serializers.ModelSerializer):
    
    GEOCODES = GEOCODESerializer(many=True)
    foundVuln_record = FoundVulnSerializer(many=True)
    Nmaps_record = NmapSerializer(many=True)
    Templates_record = TemplatesSerializer(many=True)
    DNSQuery_record = DNSQuerySerializer(many=True)
    DNSAuthority_record = DNSAuthoritySerializer(many=True)
    nucleiRecords_record = NucleiSerializer(many=True)
    Certificates_record = CertificateSerializer(many=True)
    RecRequestMetaData = RequestMetaDataSerializer(many=True)
    class Meta: 
        model = Record
        fields = (
            'id',
            'customer_id',
            'md5',
            'domainname',
            'subDomain',
            
            'dateCreated',
            'alive',
            'ip',
            'OpenPorts',
            'GEOCODES',   
            'CMS',
            'Images',
            'RecRequestMetaData',
            'Nmaps_record',
            'nucleiBool',
            'CertBool',
            'Certificates_record',
            'DNSQuery_record',
            'DNSAuthority_record',
            'nucleiRecords_record',
            'Templates_record',
            'foundVuln_record',

        )
      

    def create(self, validated_data):
        
        _data = validated_data.pop('RecRequestMetaData')
        record = RequestMetaData.objects.create(**validated_data)
        for record in _data:
            RequestMetaData.objects.create(record=record, **record)

        _data = validated_data.pop('Certificates_record')
        record = Certificate.objects.create(**validated_data)
        for record in _data:
            Certificate.objects.create(record=record, **record)

        _data = validated_data.pop('DNSQuery_record')
        record = Record.objects.create(**validated_data)
        for record in D_data:
            DNSQuery.objects.create(record=record, **record)

        _data = validated_data.pop('DNSAuthority_record')
        record = Record.objects.create(**validated_data)
        for record in _data:
            DNSAuthority.objects.create(record=record, **record)

        _data = validated_data.pop('nucleiRecords_record')
        record = Record.objects.create(**validated_data)
        for record in _data:
            Nuclei.objects.create(record=record, **record)

        _data = validated_data.pop('Templates_record')
        record = Record.objects.create(**validated_data)
        for record in _data:
            Template.objects.create(record=record, **record)

        _data = validated_data.pop('foundVuln_record')
        record = Record.objects.create(**validated_data)
        for record in _data:
            TotalFoundVuln.objects.create(record=record, **record)

        _data = validated_data.pop('Nmaps_record')
        record = Record.objects.create(**validated_data)
        for record in _data:
            Nmap.objects.create(record=record, **record)
        return record
   
class CustomerRecordSerializer(serializers.ModelSerializer):
    customerrecords = TotalRecords(many=True,required=False, allow_null=True)
    credentials_customers = CredentialsSerializer(many=True,required=False, allow_null=True)
    whois_customers = Whois_serializers(many=True,required=False, allow_null=True)
    record_count = serializers.SerializerMethodField()
    unique_geocodes = serializers.SerializerMethodField()

    class Meta:
        model = Customers
        fields = (
            'id',
            'groupingProject',
            'nameProject',
            'nameCustomer',
            'dateCreated',
            'customDaysUntilNextScan',
            'toScanDate',
            'endToScanDate',
            'URLCustomer',
            'lastEgoScan',
            'EgoReconScan',
            'reconOnly',
            'passiveAttack',
            'agressiveAttack',
            'notes',
            'OutOfScopeString',
            'urlScope',
            'outofscope',
            'domainScope',
            'Ipv4Scope',
            'Ipv6Scope',
            'whois_customers',
            'FoundTLD',
            'FoundASN',
            'skipScan',
            'credentials_customers',
            'record_count',
            'unique_geocodes',
            'customerrecords',
        )

    def get_record_count(self, obj):
        return obj.customerrecords.count()

    def get_unique_geocodes(self, obj):
        geocodes_set = set()
        for record in obj.customerrecords.all():
            for geocodes in record.GEOCODES.all():
                geocode_dict = OrderedDict([
                    ('ip_address', geocodes.ip_address),
                    ('city', geocodes.city),
                    ('country', geocodes.country)
                ])
                geocodes_set.add(frozenset(geocode_dict.items()))  # Convert dictionary to frozenset to add it to the set
        # Convert each frozenset back to dictionary and return as a list
        return [OrderedDict(geocode) for geocode in geocodes_set]

    def create(self, validated_data):
        records_data = validated_data.pop('whois_customers')
        customer = Customers.objects.create(**validated_data)
        for record in records_data:
            whois.objects.create(record=customer, **record)

        records_data = validated_data.pop('customerrecords')
        customer = Customers.objects.create(**validated_data)
        for record in records_data:
            Record.objects.create(record=customer, **record)

        records_data = validated_data.pop('credentials_customers')
        customer = Customers.objects.create(**validated_data)
        for record in records_data:
            Credential.objects.create(credential=customer, **credential)
        return customer

    def update(self, instance, validated_data):
        records_data = validated_data.pop('customerrecords')
        credential_data = validated_data.pop('credentials_customers')
        whois = validated_data.pop('whois_customers')
        records = (instance.customerrecords).all()
        records = list(records)
        instance.nameProject = validated_data.get('nameProject', instance.nameProject)
        instance.nameCustomer = validated_data.get('nameCustomer', instance.nameCustomer)
        instance.dateCreated = validated_data.get('dateCreated', instance.dateCreated)
        instance.customDaysUntilNextScan = validated_data.get('customDaysUntilNextScan', instance.customDaysUntilNextScan)
        instance.toScanDate = validated_data.get('toScanDate', instance.toScanDate)
        instance.endToScanDate = validated_data.get('endToScanDate', instance.endToScanDate)
        instance.lastEgoScan = validated_data.get('lastEgoScan', instance.lastEgoScan)
        instance.EgoReconScan = validated_data.get('EgoReconScan', instance.EgoReconScan)
        instance.egoOnly = validated_data.get('egoOnly', instance.egoOnly)
        instance.passiveAttack = validated_data.get('passiveAttack', instance.passiveAttack)
        instance.agressiveAttack = validated_data.get('agressiveAttack', instance.agressiveAttack)
        instance.URLCustomer = validated_data.get('URLCustomer', instance.URLCustomer)
        instance.notes = validated_data.get('notes', instance.notes)
        instance.notes = validated_data.get('FoundTLD', instance.FoundTLD)
        instance.notes = validated_data.get('FoundASN', instance.FoundASN)
        instance.urlScope = validated_data.get('OutOfScopeString', instance.OutOfScopeString)
        instance.urlScope = validated_data.get('urlScope', instance.urlScope)
        instance.outofscope = validated_data.get('outofscope', instance.outofscope)
        instance.domainScope = validated_data.get('domainScope', instance.domainScope)
        instance.Ipv4Scope = validated_data.get('Ipv4Scope', instance.Ipv4Scope)
        instance.Ipv6Scope = validated_data.get('Ipv6Scope', instance.Ipv6Scope)
        instance.FoundTLD = validated_data.get('FoundTLD', instance.FoundTLD)
        instance.FoundASN = validated_data.get('FoundASN', instance.FoundASN)
        instance.skipScan = validated_data.get('skipScan', instance.skipScan)
        instance.save()

        for record in credential_data:
            record = records.pop(0)
            record.credential = record.get('credential', record.credential)
            record.domainname = record.get('domainname', record.domainname)
            record.username = record.get('username', record.username)
            record.password = record.get('password', record.password)
            record.save()
            record.set()
        return instance

        for record in records_data:
            record = records.pop(0)
            record.domainname = record.get('domainname', record.domainname)
            record.subDomain = record.get('subDomain', record.subDomain)
            record.dateCreated = record.get('dateCreated', record.dateCreated)
            record.alive = record.get('alive', record.alive)
            record.nucleiBool = record.get('nucleiBool', record.nucleiBool)
            record.ip = record.get('ip', record.ip)
            record.CertBool = record.get('CertBool', record.CertBool)
            record.Certificate = record.get('Certificate', record.Certificate)
            record.OpenPorts = record.get('OpenPorts', record.OpenPorts)
            record.CMS = record.get('CMS', record.CMS)
            record.DNSQuery = record.get('DNSQuery', record.DNSQuery)
            record.DNSAuthority= record.get('DNSAuthority', record.DNSAuthority)
            record.nucleiRecords = record.get('nucleiRecords', record.nucleiRecords)
            record.save()
            record.set()
        return instance



class apiprovidersSerialiser(serializers.ModelSerializer):
    apiproviders_id = apiSerialiser(many=True)
    class Meta:
        model = apiproviders
        fields = [
            'id',
            'name',
            'apiproviders_id'
            ]