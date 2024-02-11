# snippets/models.py
from django.db import models
from django.contrib.postgres import fields
from django.contrib.postgres.fields import ArrayField
from django.contrib.auth.models import Group, User, ContentType
from datetime import datetime
import uuid
from django.contrib.postgres.fields import JSONField
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.authtoken.models import Token
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils.translation import gettext as _
from rest_framework.authtoken.models import Token
from django.dispatch import receiver

BaseModel = models.Model

    
Choices_Severity= [
('info, low, medium, high, critical, unknown', 'All'),
 ('info', 'Info'),
 ('low', 'Low'),
 ('medium', 'Medium'),
 ('high', 'High'),
 ('critical', 'Critical'),
 ('unknown', 'Unknown')
 ]

Choices_APIProviders= [
    ('nessus', 'Nessus'),
    ('google', 'Google'),
    ('censys', 'Censys'),
    ('shodan', 'Shodan'),
    ('burp', 'Burp'),
    ('yahoo', 'Yahoo'),
    ('other', 'Other')
    ]

choices_request_methods= [
    ('none', 'None'),
    ('connect', 'CONNECT'),
    ('delete', 'DELETE'),
    ('get', 'GET'),
    ('head', 'HEAD'),
    ('options', 'OPTIONS'),
    ('post', 'POST'), 
    ('put', 'PUT'),
    ('trace', 'TRACE')
    ]

def user_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    return 'ATTACK/{0}'.format(filename)

# When a new User is saved...
@receiver(post_save, sender=User)
def create_user_group(sender, instance, created, **kwargs):
    # If the User was just created...
    if created:
        # Create a new Group with the same name as the username
        group, created = Group.objects.get_or_create(name=instance.username)
        if created:
            # Get the content type for the User model
            content_type = ContentType.objects.get_for_model(instance)
            # Get all permissions for the User model
            permissions = Permission.objects.filter(content_type=content_type)
            # Assign the permissions to the Group
            group.permissions.set(permissions)

# When a User is saved...
@receiver(post_save, sender=User)
def add_user_to_group(sender, instance, **kwargs):
    # Get the Group with the same name as the username, or create it if it doesn't exist
    group, created = Group.objects.get_or_create(name=instance.username)
    # Add the User to the Group
    instance.groups.add(group)

##############################
######## customers
##############################
class Customers(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    groupingProject = models.CharField(max_length=100, default='Ego', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide the groups name example BugCrowd, Hackerone, or WorkPlace</fieldset>') 
    nameProject = models.CharField(unique=True, max_length=100, default='Please name the project.', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide a Covert Name for the project, this will help keep your project a secret from other users.</fieldset>') 
    nameCustomer = models.CharField(unique=True, max_length=100, default='Please the customers name.', help_text='<fieldset style="background-color: lightblue;display: inline-block;">The real name of the customer, this is a secret</fieldset>')
    URLCustomer = models.CharField(max_length = 2048,  default='Please the customers name.', help_text='<fieldset style="background-color: lightblue;display: inline-block;">The main url for the customer, or the BugBounty url to the customer platform. </fieldset>')
    dateCreated = models.DateTimeField(auto_now_add=True, blank=True, editable=False)
    customDaysUntilNextScan = models.IntegerField(default='30')
    toScanDate = models.DateField(blank=True, null=True)
    endToScanDate = models.DateField(blank=True, null=True)
    lastEgoScan = models.DateField(blank=True, null=True)
    EgoReconScan = models.BooleanField(default='False')
    reconOnly = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Will tell all attack engines to skip this customer.</fieldset>')
    passiveAttack = models.BooleanField(default='False')
    agressiveAttack = models.BooleanField(default='False')
    notes = models.TextField(blank=True, default='Nothing to tell here.')
    OutOfScopeString = models.CharField(max_length = 75, blank=True, null=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">This is a list of strings is a negative search for scope, so it will make every domain with the string in it be scanned.</fieldset>')
    urlScope = fields.ArrayField(models.URLField(max_length = 2048), blank=True, default=list, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Must provide a full url example: https://example.com/ </fieldset>')
    outofscope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list, help_text='<fieldset style="background-color: lightblue;display: inline-block;">List of out of scope domains or subdomains not to be included in scans.</fieldset>')
    domainScope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list, help_text='<fieldset style="background-color: lightblue;display: inline-block;">List of in scope domains, example www.example.com, *.example.com, or *.example.*</fieldset>')
    Ipv4Scope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Accepts a list of ip address or cidr examples 127.0.0.1, 192.168.0.0/21</fieldset>') 
    Ipv6Scope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list, help_text='<fieldset style="background-color: lightblue;display: inline-block;">IPV6 example [343f::34::]</fieldset>')
    FoundTLD = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    FoundASN = fields.ArrayField(fields.ArrayField(models.CharField(max_length=256)), blank=True, default=list)
    skipScan = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Default is false, this will tell the engine\'s to skip this target if an <b>All Customer scan</b> is ran.</fieldset>')


    #chart = models.JSONField(blank=True)
    def __unicode__(self):
        return self.nameProject

##############################
######## Records
##############################
class Record(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer_id = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='customerrecords', blank=True)
    md5 = models.CharField(max_length=32, unique=True)
    domainname = models.CharField(max_length=256, blank=True) 
    subDomain = models.CharField(max_length=256, blank=True, unique=True)
    #scanSevirity = models.CharField(max_length=256, blank=True, default='none')
    dateCreated = models.DateTimeField(auto_now_add=True)
    lastScan = models.DateField(auto_now_add=True)
    skipScan = models.BooleanField(default='False')
    alive = models.BooleanField(default='False')
    nucleiBool = models.BooleanField(default='False')
    ip = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    Ipv6Scope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    OpenPorts = models.JSONField(default=list, blank=True)
    CertBool = models.BooleanField(default='False', blank=True)
    CMS = models.CharField(max_length=256, blank=True)
    ASN = ArrayField(ArrayField(models.CharField(max_length=2048), blank=True), default=list)
    Images= models.ImageField(upload_to='RecordPictures', blank=True)
    #whoIs = models.JSONField(default=dict, blank=True)

class GEOCODES(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='GEOCODES')
    ip_address = models.CharField(max_length=256, blank=True)
    city = models.CharField(max_length=256, blank=True)
    region = models.CharField(max_length=256, blank=True)
    country = models.CharField(max_length=256, blank=True)
    latitude = models.CharField(max_length=256, blank=True)
    longitude = models.CharField(max_length=256, blank=True)

##############################
# NMap NIST 
##############################
class CPEID(BaseModel):
    cpeId = models.CharField(max_length=175, primary_key=True)
    CPE = models.CharField(max_length=100)
    service = models.CharField(max_length=75)
    version = models.CharField(max_length=128)

class csv_version(BaseModel):
    vectorString = models.CharField(primary_key=True, max_length=50)
    version = models.CharField(max_length=7)
    accessVector = models.CharField(max_length=50)
    accessComplexity = models.CharField(max_length=9)
    authentication = models.CharField(max_length=256)
    confidentialityImpact = models.CharField(max_length=10)
    integrityImpact = models.CharField(max_length=10)
    availabilityImpact = models.CharField(max_length=10)
    baseScore = models.CharField(max_length=5)
    baseSeverity = models.CharField(max_length=9)

class nist_description(BaseModel):
    nist_record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='Nist_records', blank=True, null=True)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    CPEServiceID = models.ForeignKey(CPEID, on_delete=models.CASCADE, related_name='CPEService')
    csv_version_id = models.ForeignKey(csv_version, on_delete=models.CASCADE, related_name='CsvVersion')
    CPE = models.CharField(max_length=100)
    service = models.CharField(max_length=75)
    descriptions = models.TextField(unique=True)
    references = ArrayField(models.CharField(max_length=2048), blank=True)

class ThreatModeling(BaseModel): 
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='customer_threat_modeling')

class TldIndex(BaseModel):
    tld = models.CharField(unique=True, max_length=256)
    count = models.IntegerField(blank=True)

class Nmap(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='Nmaps_record')
    #nmapNistVulns = models.ForeignKey(nist_description, on_delete=models.CASCADE, related_name='nmapNistVulns', blank=True, default = None)
    md5 = models.CharField(max_length=500, unique=True)
    date = models.DateTimeField(auto_now_add=True, blank=True)
    name = models.CharField(max_length=500, blank=True)
    port = models.CharField(max_length=500, blank=True)
    protocol = models.CharField(max_length=500, blank=True)
    service = models.JSONField(default=dict, blank=True)
    state = models.CharField(max_length=10, blank=True)
    hostname = models.JSONField(default=list, blank=True)
    macaddress = models.CharField(max_length = 50, blank=True)
    reason =models.CharField(max_length = 500, blank=True)
    reason_ttl = models.CharField(max_length = 500, blank=True)
    service=models.CharField(max_length = 500, blank=True)
    cpe= models.CharField(max_length = 500, blank=True)
    scripts= models.JSONField(default=list, blank=True)
    conf = models.CharField(max_length = 500, blank=True)
    extrainfo = models.CharField(max_length = 500, blank=True)
    method = models.CharField(max_length = 500, blank=True)
    ostype = models.CharField(max_length = 500, blank=True)
    product = models.CharField(max_length = 500, blank=True)
    version = models.CharField(max_length = 500, blank=True)
    servicefp = models.TextField(blank=True)

##############################
######## Control
##############################
class EGOAgent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=256, null=True, blank=True)
    hostLocation = models.CharField(max_length=256, blank=True)
    lastConnect = models.DateField(auto_now_add=True)
    callBackTime = models.IntegerField(default='30')
    alive = models.BooleanField(default='False')
    scanning = models.BooleanField(default='False')
    bearer_token = models.CharField(max_length=500, blank=True)

class GnawControl(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    egoAgentID = models.ForeignKey(EGOAgent, on_delete=models.CASCADE, related_name='EGOAgent', null=True, blank=True)
    NucleiScan = models.BooleanField(default='True')
    Ipv_Scan = models.BooleanField(default='False')
    LoopCustomersBool = models.BooleanField(default='False')
## fix in next updatee to support list of strings to ignore
    OutOfScope = models.CharField(max_length = 75, blank=True, null=True)
    ScanProjectByID = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide the groups name example BugCrowd, Hackerone, or WorkPlace</fieldset>')
    ScanGroupingProject = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide a Covert Name for the project, this will help keep your project a secret from other users.</fieldset>')
    ScanProjectByName = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">The real name of the customer, this is a secret</fieldset>')
    Customer_chunk_size = models.IntegerField(default='7', help_text='<fieldset style="background-color: lightblue;display: inline-block;">The main url for the customer, or the BugBounty url to the customer platform. </fieldset>')
    Record_chunk_size = models.IntegerField(default='20', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Default is false, this will tell the engine\'s to skip this target if an <b>All Customer scan</b> is ran.</fieldset>')
    Global_Nuclei_CoolDown= models.IntegerField(default='4', blank=True, null=True)
    Global_Nuclei_RateLimit= models.IntegerField(default='', blank=True, null=True)
    Port = models.IntegerField(default='9000', help_text="<fieldset style=\"background-color: lightblue;display: inline-block;\">The default port number is a dragon ball reference. It is over 9000!</fieldset>")
    HostAddress = models.CharField(max_length=256, default='http://127.0.0.1', help_text="<fieldset style=\"background-color: lightblue;display: inline-block;\">The domain name of the server hosting the API, if the api is ran locally this address would be the default. </fieldset>")
    severity = models.CharField(max_length=256, default='info, low, medium, high, critical, unknown', help_text='<fieldset style="background-color: lightblue;display: inline-block;">please provide, one of the severity options to scan for or use them all. <b>Severity</b>info,</br> low,</br> medium,</br> high,</br> critical,</br> unknown</br></fieldset>')
    Gnaw_Completed = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Used to scan all customers.</fieldset>')
    failed = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">An exception occured.</fieldset>')
    scan_objects = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    SubdomainsSeen = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)


class EgoControl(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ScanProjectByID = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">The uniquic identifier stirng assigned to id Objects.</fieldset>')
    internal_scanner = models.BooleanField(default='False')
    ScanGroupingProject = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Example BugCrowd, HackerOne, or work. </fieldset>')
    ScanProjectByName = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">The projects code, name. </fieldset>')
    OutOfScope = models.CharField(max_length = 75, blank=True, null=True, help_text='')
    chunk_size= models.IntegerField(default='12', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Define the scan chunksize for the records, keep in mind that a high value may lead to getting detected by the wafs. It will perform a scan in breathe but some wafs are smart and will observe slow paralle hits. A high vlaue may also consume your network cards usage, and prevent internet usage on the system.</fieldset>')
    CoolDown= models.IntegerField(default='2', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Accepts a tuple example (1,34), this will define the range for the timeout between customer scans.</fieldset>')
    CoolDown_Between_Queries= models.IntegerField(default='6', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Accepts a tuple example (1,34), this will define the range for the timeout between customer scans. </fieldset>')
    Port = models.IntegerField(default='9000', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Example 5000</fieldset>')
    HostAddress = models.CharField(max_length=256, default='127.0.0.1', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide the full url including protocol schema example https://google.com, for where the api is hsoted</fieldset>')
    passiveAttack = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Passive scans is not active at this time.</fieldset>')
    agressiveAttack = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Passive scans is not active at this time.</fieldset>')
    portscan_bool = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">agressive scan is not active at this time.</fieldset>')
    versionscan_bool = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Tell the engine to perform a port scan, by default EGO uses a predfined list of ports. this feature will be expanded later to allow customer port ranges.</fieldset>')
    Scan_Scope_bool = models.BooleanField(default='False')
    Scan_IPV_Scope_bool = models.BooleanField(default='False')
    Scan_DomainName_Scope_bool = models.BooleanField(default='False')
    scriptscan_bool = models.BooleanField(default='False')
    BruteForce = models.BooleanField(default='False')
    BruteForce_WL = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    scan_records_censys = models.BooleanField(default='False')
    crtshSearch_bool = models.BooleanField(default='False')
    Update_RecordsCheck = models.BooleanField(default='False')
    LoopCustomersBool = models.BooleanField(default='False')
    #Start = models.BooleanField(default='False')
    #StartBy = models.DateTimeField(auto_now_add=True, blank=True)
    #pause = models.BooleanField(default='False')
    #pauseBy = models.DateTimeField(auto_now_add=True, blank=True)
    Completed = models.BooleanField(default='False')
    Gnaw_Completed = models.BooleanField(default='False')
    failed = models.BooleanField(default='False')
    scan_objects = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)

class MantisControls(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    NucleiScan = models.BooleanField(default='True')
    Ipv_Scan = models.BooleanField(default='False')
    LoopCustomersBool = models.BooleanField(default='False')
    OutOfScope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    ScanProjectByID = models.CharField(max_length = 75, blank=True)
    ScanGroupingProject = models.CharField(max_length = 75, blank=True)
    ScanProjectByName = models.CharField(max_length = 75, blank=True)
    Customer_chunk_size = models.IntegerField(default='7')
    Record_chunk_size = models.IntegerField(default='20')
    Global_CoolDown= fields.ArrayField(models.IntegerField(default='2'), blank=True)
    Global_RateLimit= models.IntegerField(default='6')
    Port = models.IntegerField(default='9000')
    HostAddress = models.CharField(max_length=256, default='127.0.0.1')
    severity = models.CharField(max_length=256, default='info, low, medium, high, critical, unknown')
    Elavate =models.CharField(max_length=256, default='127.0.0.1')
    Mantis_Completed = models.BooleanField(default='False')
    failed = models.BooleanField(default='False')
    scan_objects = fields.ArrayField(models.CharField(max_length=256), blank=True)


##############################
##### manager/api/credentials
##############################
class projectManger(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer_id = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='customer_projectManger', blank=True)
    created = models.DateTimeField(auto_now_add=True, blank=True)
    lastupdated = models.DateTimeField(auto_now_add=True, blank=True)
    lastupdatedby = User.objects.filter(id=True)
    comment = models.TextField(unique=True)
    
class DocManger(BaseModel): 
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)    
    projectManDoc_id = models.ForeignKey(projectManger, on_delete=models.CASCADE, related_name='projectManDoc_id')

    created = models.DateTimeField(auto_now_add=True, blank=True)
    lastupdated = models.DateTimeField(auto_now_add=True, blank=True)
    lastupdatedby = User.objects.filter(id=True)
    comment = models.TextField(unique=True)
    Files =  models.FileField(upload_to='Matrix/Files', blank=True)

class FindingMatrix(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    projectManMatrix_id = models.ForeignKey(projectManger, on_delete=models.CASCADE, related_name='projectManMatrix_id')
    found = models.CharField(max_length=500, blank=True)
    created=models.DateTimeField(auto_now_add=True, blank=True)
    updated=models.DateTimeField(auto_now_add=True, blank=True)
    type = models.CharField(max_length = 500, blank=True)
    component = models.CharField(max_length = 500, blank=True)
    seveiry = models.CharField(max_length = 500, blank=True)
    compelxity = models.CharField(max_length = 500, blank=True)
    risk = models.CharField(max_length = 500, blank=True)
    threat = models.CharField(max_length = 500, blank=True)
    locations = models.CharField(max_length = 500, blank=True)
    impact = models.CharField(max_length = 500, blank=True)
    details = models.TextField(blank=True)
    example_location = fields.ArrayField(models.CharField(max_length=1024), blank=True, default=list)
    remediation = models.TextField(blank=True)
    references = fields.ArrayField(models.CharField(max_length=1024), blank=True, default=list)
    Images= models.ImageField(upload_to='RecordPictures/', blank=True)
    Files =  models.FileField(upload_to='Matrix/Files', blank=True)

class apiproviders(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(choices=Choices_APIProviders, max_length=100, default='unknown', unique=True)

class api(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    apiproviders_id = models.ForeignKey(apiproviders, on_delete=models.CASCADE, related_name='ApiProviders', blank=True)
    dateCreated = models.DateTimeField(auto_now_add=True, blank=True, editable=False)
    lastScan = models.DateField(auto_now_add=True)
    whentouse = models.IntegerField(default='30')
    apiId = models.TextField(blank=True)
    apiKey = models.TextField(blank=True)
    passWord = models.CharField(max_length=256, blank=True)
    userName = models.CharField(max_length=256, blank=True)
    inuse = models.BooleanField(default='False')

class Credential(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='credentials_customers', null=True)
    dateCreated = models.DateTimeField(auto_now_add=True, blank=True, editable=False)
    domainname = models.URLField(max_length = 2048)
    username = models.CharField(max_length=256)
    password = models.CharField(max_length=256)


##############################
##### data systems
##############################
class RequestMetaData(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='RecRequestMetaData')
    md5 = models.CharField(max_length=32, unique=True)
    status = models.CharField(max_length = 3)
    redirect = models.BooleanField(default='False')
    paths = fields.ArrayField(models.CharField(max_length = 2048), blank=True )
    cookies = models.JSONField(blank=True)
    headers = models.JSONField(blank=True)
    backend_headers = models.JSONField(default=list, blank=True)
    FoundObjects = models.JSONField(default=list, blank=True)
    headerValues = models.JSONField(default=list, blank=True)
    htmlValues = models.JSONField(default=list, blank=True)
    rawHTML = models.TextField(blank=True)
    
#content_length = models.CharField(max_length=7, unique=True)
#whois model saves an images to  static/images/maps/
class whois(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer_id = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='whois_customers', blank=True)
    domain_name = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    registrar = models.CharField(max_length=254, blank=True, null=True)
    whois_server = models.CharField(max_length=254, blank=True, null=True)
    referral_url = models.CharField(max_length=254, blank=True, null=True)
    updated_date = models.CharField(max_length=254, blank=True)
    creation_date = fields.ArrayField(models.CharField(max_length=30), blank=True, null=True)
    expiration_date = fields.ArrayField(models.CharField(max_length=30), blank=True, null=True)
    name_servers = fields.ArrayField(models.CharField(max_length=256), blank=True, null=True)
    status = fields.ArrayField(models.CharField(max_length=175), blank=True, null=True)
    emails = fields.ArrayField(models.EmailField(max_length=254), blank=True, null=True)
    dnssec = fields.ArrayField(models.CharField(max_length=500), blank=True, null=True)
    name = models.CharField(max_length=254, blank=True, null=True)
    org = models.CharField(max_length=254, blank=True, null=True)
    registrant_postal_code = models.CharField(max_length=254, blank=True, null=True)
    address = models.CharField(max_length=254, blank=True, null=True)
    city = models.CharField(max_length=254, blank=True, null=True)
    state = models.CharField(max_length=254, blank=True, null=True)
    registrant_postal_code = models.CharField(max_length=254, blank=True, null=True)
    country = models.CharField(max_length=4, blank=True, null=True)
    map_image = models.ImageField(upload_to='./recon/static/images/maps/', blank=True)

class Certificate(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='Certificates_record')
    md5 = models.CharField(max_length=32, unique=True)
    countryName = models.TextField(blank=True)
    stateOrProvinceName = models.TextField(blank=True)
    organizationName = models.TextField(blank=True)
    localityName = models.TextField(blank=True)
    subjectAltName = fields.ArrayField(models.CharField(max_length=256), blank=True)
    OCSP = models.URLField(max_length = 2048, blank=True)
    caIssuers = models.URLField(max_length = 2048, blank=True)
    crlDistributionPoints = models.URLField(max_length = 2048, blank=True)
    PEM = models.TextField(blank=True)

class DNSQuery(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='DNSQuery_record')
    md5 = models.CharField( max_length=32, unique=True)
    A = models.GenericIPAddressField(protocol="IPv4", blank=True, null=True)
    AAAA = models.CharField(max_length=500, blank=True)
    #AAAA = models.GenericIPAddressField(protocol="IPv6", blank=True, null=True)
    NS = models.TextField(blank=True)
    CNAME = models.TextField(blank=True)
    r = models.TextField(blank=True)
    MX = models.TextField(blank=True)
    TXT = models.TextField(blank=True)
    ANY = models.TextField(blank=True)

class DNSAuthority(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='DNSAuthority_record')
    md5 = models.CharField( max_length=32, unique=True)
    A = models.GenericIPAddressField(protocol="IPv4", blank=True, null=True)
    #AAAA = models.GenericIPAddressField(protocol="IPv6", blank=True, null=True)
    AAAA = models.CharField(max_length=500, blank=True)
    NS = models.TextField(blank=True)
    CNAME = models.CharField(max_length = 2048, blank=True)
    r = models.CharField(max_length=500, blank=True)
    MX = models.TextField(blank=True)
    TXT = models.TextField(blank=True)
    ANY = models.CharField(max_length=500, blank=True)

class Template(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='Templates_record')
    date = models.DateTimeField(auto_now_add=True, null=True)
    md5 = models.CharField(max_length=32, unique=True)
    template = models.CharField(max_length=2048, null=True)
    template_url = models.URLField(max_length = 2048, null=True)
    template_id = models.CharField(max_length=500, null=True)
    info = models.JSONField(default=list, null=True)
    host = models.CharField(max_length=256, null=True)
    matched_at = models.TextField(blank=True, default='False', null=True)
    matcher_status = models.BooleanField(default='False')
    matched_line = models.BooleanField(default='False')
    matcher_status = models.BooleanField(default='False')
    timestamp = models.DateTimeField(null=True)
    extracted_results = fields.ArrayField(models.CharField(max_length=2048), null=True)
    curl_command = models.TextField(blank=True, null=True)
    Submitted = models.BooleanField(default='False')

class External_Internal_Checklist(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    Grouping = models.CharField(max_length=100, default='Ego') 
    tool = models.DateField(auto_now_add=True)
    tester = models.CharField(max_length=100, default='Ego') 
    date = models.DateTimeField(auto_now_add=True, blank=True, editable=False)
    status = models.BooleanField(default='False')
    notes = models.TextField(blank=True)
    
class WordListGroup(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    groupName = models.CharField( max_length=256 )
    type = models.CharField(max_length=32)
    description = models.TextField(blank=True, default='It may seem dumb but add some context')
    count = models.CharField( max_length=20, blank=True )
    def __unicode__(self):
        return self.groupName

class WordList(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    WordList = models.ForeignKey(WordListGroup, on_delete=models.CASCADE, related_name='WordList')
    type = models.CharField(max_length=32, default="None", blank=True)
    Value = models.CharField(unique=True, max_length=2024)
    Occurance = models.IntegerField(default=0)
    foundAt = fields.ArrayField(models.CharField(max_length=256), blank=True)
##############################
##### vulns
##############################

class Nuclei(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='nucleiRecords_record')
    md5 = models.CharField(max_length=32, unique=True)
    date = models.DateTimeField(auto_now_add=True, blank=True)
    name = models.CharField(max_length=500, blank=True)
    method = models.CharField(max_length=20, blank=True)
    #severity = models.CharField(choices=Choices_Severity, max_length=8, default='unknown')
    vulnerable = models.URLField(max_length = 2048, blank=True)

class VulnCard(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=256, unique=True, blank=True)
    vulnClass = models.CharField(max_length=256, null=True)
    author = fields.ArrayField(models.CharField(max_length = 125, blank=True), null=True)
    severity = models.CharField(choices=Choices_Severity, max_length=120, default='unknown')
    cvss_metrics = models.CharField(max_length=256, blank=True)
    cvss_score = models.CharField(max_length=10, blank=True)
    cwe_id = models.CharField(max_length=256, blank=True)
    description = models.TextField(blank=True)
    impact = models.TextField(blank=True)
    proof_of_concept = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    references = fields.ArrayField(models.URLField(max_length = 2048), blank=True)
    pictures = models.ImageField(upload_to='ProofOfConcept', blank=True)

class FoundVuln(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vuln_cardId = models.ForeignKey(VulnCard, on_delete=models.CASCADE, related_name='vuln_cardId', blank=True, null=True)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='foundVuln_record', blank=True, null=True)
    DomainName = models.CharField(max_length=256, blank=True)
    creds = fields.ArrayField(models.CharField(max_length = 256), blank=True, null=True)
    name = models.CharField(max_length=256, blank=True)
    author = fields.ArrayField(models.CharField(max_length = 125), blank=True)
    severity = models.CharField(choices=Choices_Severity, max_length=120, default='unknown')
    date = models.DateTimeField(auto_now_add=True, blank=True)
    vulnClass = models.CharField(max_length=256, null=True)
    cvss_metrics = models.CharField(max_length=256, blank=True)
    cvss_score = models.CharField(max_length=10, blank=True)
    cwe_id = models.CharField(max_length=256, blank=True)
    description = models.TextField(blank=True)
    impact = models.TextField(blank=True)
    proof_of_concept = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    location = fields.ArrayField(models.URLField(max_length = 2048), blank=True, null=True)
    references = fields.ArrayField(models.URLField(max_length = 2048), blank=True)
    exploitDB = fields.ArrayField(models.URLField(max_length = 2048), blank=True)
    addtional_data = models.FileField(upload_to='ProofOfConcept', blank=True)
    Submitted = models.BooleanField(default='False')
    matchers_status = models.CharField(max_length=2048, blank=True)
    match_headers = models.CharField(max_length=2048, blank=True)
    matchedAt_headers = models.CharField(max_length=2048, blank=True)
    match_bodys = models.CharField(max_length=2048, blank=True)
    matchedAt_bodys = models.CharField(max_length=2048, blank=True)
    curl_command = models.TextField(blank=True)

class FoundVulnDetails(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    FoundVuln_id =  models.ForeignKey(FoundVuln, on_delete=models.CASCADE, related_name='VulnDetails', blank=True, null=True)
    DomainName = models.CharField(max_length=256, blank=True)
    location = models.CharField(max_length=2048, blank=True,unique=True)
    date = models.DateTimeField(auto_now_add=True, blank=True)
    creds = fields.ArrayField(models.CharField(max_length=500), blank=True, null=True)
    pictures = models.ImageField(upload_to='ProofOfConcept', blank=True)
    matchers_status = models.CharField(max_length=2048, blank=True)
    match_headers = models.CharField(max_length=2048, blank=True)
    matchedAt_headers = models.CharField(max_length=2048, blank=True)
    match_bodys = models.CharField(max_length=2048, blank=True)
    matchedAt_bodys = models.CharField(max_length=2048, blank=True)
    curl_command = models.TextField(blank=True)

class PythonMantis(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnCard_id= models.ForeignKey(VulnCard, on_delete=models.CASCADE, related_name='PythonMantis_record')
    Elevate_Vuln = models.CharField(max_length=256, blank=True)
    name = models.CharField(max_length=256, null=True)
    callbackServer =  models.CharField(max_length = 2048, default='http://127.0.0.1')
    callbackServerKey = models.CharField(max_length = 2048, blank=True)
    request_method = models.CharField(max_length=7, blank=True, null=True)
    payloads = models.TextField(blank=True)
    headers = models.JSONField(default=dict, blank=True)
    postData = models.TextField(blank=True)
    ComplexPathPython = models.TextField(blank=True)
    ComplexAttackPython = models.FileField(upload_to=user_directory_path, blank=True)
    path = fields.ArrayField(models.CharField(max_length = 2048), blank=True )
    creds = fields.ArrayField(models.CharField(max_length = 256), blank=True)
    pathDeveloper = models.TextField(blank=True)
    rawRequest = fields.ArrayField(models.CharField(max_length=10240), blank=True)
    SSL = models.BooleanField(default='False')
    timeout_betweenRequest = models.CharField(max_length=10, blank=True)
    repeatnumb = models.CharField(max_length=6, blank=True)
    redirect = models.BooleanField(default='False')
    matchers_status = ArrayField(models.CharField(max_length=2048), blank=True)
    matchers_headers = ArrayField(models.CharField(max_length=2048), blank=True)
    matchers_bodys = ArrayField(models.CharField(max_length=2048), blank=True)
    matchers_words = ArrayField(models.CharField(max_length=2048), blank=True)
    shodan_query = ArrayField(models.CharField(max_length=2048), blank=True)
    google_dork = models.TextField(blank=True, null=True)
    tags = fields.ArrayField(models.CharField(max_length=75))
    tcpversioning = models.CharField(max_length = 2048, blank=True)
    
