from django.shortcuts import render
from rest_framework import status, viewsets, mixins, generics
from rest_framework.exceptions import NotFound
from django.http import Http404
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from django import forms
from django.utils.safestring import mark_safe
from django.contrib.postgres.forms import SimpleArrayField
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
import uuid
from recon.models import * 
from recon.forms import *
from recon.serializers import *



class FormsCustomersCreate(forms.ModelForm):

    class Meta:
        model = Customers
        fields = [
            'user',
            'groupingProject', 
            'nameProject', 
            'nameCustomer', 
            'URLCustomer', 
            'customDaysUntilNextScan', 
            'toScanDate', 
            'endToScanDate', 
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
            'FoundTLD', 
            'FoundASN', 
            'skipScan',
    
        ]

class create_egocontrol(forms.ModelForm):
    internal_scanner = forms.BooleanField(initial=False, required=False, widget=forms.CheckboxInput())
    passiveAttack = forms.BooleanField(initial=False, required=False, widget=forms.CheckboxInput())
    agressiveAttack = forms.BooleanField(initial=True, required=False, widget=forms.CheckboxInput())
    portscan_bool = forms.BooleanField(initial=True, required=False, widget=forms.CheckboxInput())
    versionscan_bool = forms.BooleanField(initial=True, required=False, widget=forms.CheckboxInput())
    Scan_Scope_bool = forms.BooleanField(initial=True, required=False, widget=forms.CheckboxInput())
    Scan_IPV_Scope_bool = forms.BooleanField(initial=False, required=False, widget=forms.CheckboxInput())
    Scan_DomainName_Scope_bool = forms.BooleanField(initial=True, required=False, widget=forms.CheckboxInput())
    scriptscan_bool = forms.BooleanField(initial=True, required=False, widget=forms.CheckboxInput())
    BruteForce = forms.BooleanField(initial=False, required=False, widget=forms.CheckboxInput())
    scan_records_censys = forms.BooleanField(initial=True, required=False, widget=forms.CheckboxInput())
    crtshSearch_bool = forms.BooleanField(initial=True, required=False, widget=forms.CheckboxInput())
    Update_RecordsCheck = forms.BooleanField(initial=False, required=False, widget=forms.CheckboxInput())
    LoopCustomersBool = forms.BooleanField(initial=False, required=False, widget=forms.CheckboxInput())
    Completed = forms.BooleanField(initial=False, required=False, widget=forms.CheckboxInput())
    Gnaw_Completed = forms.BooleanField(initial=False, required=False, widget=forms.CheckboxInput())
    failed = forms.BooleanField(initial=False, required=False, widget=forms.CheckboxInput())  
    class Meta:
        model = EgoControl
        fields = '__all__'

class update_egocontrol(forms.ModelForm):
    class Meta:
        model = EgoControl
        fields = '__all__'
        
## widgets 

class DateInput(forms.DateInput):
    input_type = 'date'

## end widgets
class FoundVulnFormPK(forms.ModelForm):
    class Meta:
        model = FoundVuln
        fields = [
            'Submitted'
        ]
    def clean(self):
        cleaned_data = super().clean()
        known_secret_key = "known_value"
        if self.user.secret_key != known_secret_key:
            raise ValidationError("Invalid secret key.")
            
class VulnSubmittedForm(forms.Form):
    Submitted = forms.BooleanField(widget=forms.CheckboxInput, label="failed", required=False)

severity_CHOICES =(
    ("info", "info"),
    ("low", "low"),
    ("medium", "medium"),
    ("high", "high"),
    ("critical", "critical"),
    ("unknown", "unknown"),
)

class GnawControlBoards_create_Form(forms.ModelForm):
    class Meta:
        model = GnawControl
        fields = '__all__'
        

class customer_Create(forms.Form):
    groupingProject = forms.CharField(max_length=100, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide the groups name example BugCrowd, Hackerone, or WorkPlace</fieldset>')
    nameProject = forms.CharField(max_length=100, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide a Covert Name for the project, this will help keep your project a secret from other users.</fieldset>')
    nameCustomer = forms.CharField(max_length=100, help_text='<fieldset style="background-color: lightblue;display: inline-block;">The real name of the customer, this is a secret</fieldset>')
    URLCustomer = forms.CharField(max_length = 2048, required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">The main url for the customer, or the BugBounty url to the customer platform. </fieldset>')
    customDaysUntilNextScan = forms.IntegerField(initial='30', required=False)
    toScanDate = forms.DateField(widget=DateInput, required=False)
    endToScanDate = forms.DateField(widget=DateInput, required=False)
    skipScan = forms.BooleanField(initial='False', required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Default is false, this will tell the engine\'s to skip this target if an <b>All Customer scan</b> is ran.</fieldset>')
    reconOnly = forms.BooleanField(initial='False', required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Will tell all attack engines to skip this customer.</fieldset>')
    passiveAttack = forms.BooleanField(initial='False', required=False)
    agressiveAttack = forms.BooleanField(initial='False', required=False)
    notes = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False)
    OutOfScopeString = forms.CharField(max_length = 75, required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">This is a list of strings is a negative search for scope, so it will make every domain with the string in it be scanned.</fieldset>')
    urlScope = SimpleArrayField(forms.URLField(max_length = 2048), required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Must provide a full url example: https://example.com/ </fieldset>')
    outofscope = SimpleArrayField(forms.CharField(max_length=256), required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">List of out of scope domains or subdomains not to be included in scans.</fieldset>')
    domainScope = SimpleArrayField(forms.CharField(max_length=256), required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">List of in scope domains, example www.example.com, *.example.com, or *.example.*</fieldset>')
    Ipv4Scope = SimpleArrayField(forms.CharField(max_length=256) , required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Accepts a list of ip address or cidr examples 127.0.0.1, 192.168.0.0/21</fieldset>')
    Ipv6Scope = SimpleArrayField(forms.CharField(max_length=256), required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">IPV6 example [343f::34::]</fieldset>')
    FoundTLD = SimpleArrayField(forms.CharField(max_length=256, initial='[]') , required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Api area</fieldset>')
    FoundASN = SimpleArrayField(forms.CharField(max_length=256, initial='[]'), required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Api area</fieldset>')
    lastEgoScan = forms.DateField(widget=DateInput, required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Api area</fieldset>')
    EgoReconScan = forms.BooleanField(initial='False', required=False, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Api area</fieldset>')


class customer_pk(forms.ModelForm):
    class Meta:
        model = Customers
        fields = [
            'groupingProject',
            'nameProject',
            'nameCustomer',
            'customDaysUntilNextScan',
            'toScanDate',
            'endToScanDate',
            'URLCustomer',
            'skipScan',
            'reconOnly',
            'passiveAttack',
            'agressiveAttack',
            'notes',
            'OutOfScopeString',
            'EgoReconScan',
            'lastEgoScan',
            'urlScope',
            'outofscope',
            'domainScope',
            'Ipv4Scope',
            'Ipv6Scope'
            ]



### MantisData create 
class MantisDataCreate(forms.ModelForm):
    class Meta:
        model = PythonNuclei
        fields = [
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
            ]

class VulnCardData(forms.ModelForm):
    class Meta:
        model = VulnCard
        fields = (

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

class MantisFormCreate(forms.Form):
    vulnCard_id = forms.UUIDField()
    Elevate_Vuln = forms.CharField(max_length=1000, required=False)
    name = forms.CharField(max_length=1000)
    callbackServer = forms.CharField(max_length=1000, required=False)
    callbackServerKey = forms.CharField(max_length=1000, required=False)
    request_method = forms.CharField(max_length=1000)
    payloads = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False)
    headers = SimpleArrayField(forms.CharField(max_length=256), required=False)
    postData = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False)
    ComplexPathPython = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False)
    ComplexAttackPython = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False)
    path = SimpleArrayField(forms.CharField(), required=False)
    creds = SimpleArrayField(forms.CharField(max_length=256), required=False)
    pathDeveloper = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False)
    rawRequest = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False)
    SSL = forms.CharField(max_length = 2048, required=False)
    timeout_betweenRequest = forms.CharField(max_length = 2048, required=False)
    repeatnumb = forms.CharField(max_length = 2048, required=False)
    redirect = forms.CharField(max_length = 2048, required=False)
    matchers_status = SimpleArrayField(forms.CharField(max_length=3))
    matchers_headers = SimpleArrayField(forms.CharField(max_length=256), required=False)
    matchers_bodys = SimpleArrayField(forms.CharField(max_length=256), required=False)
    matchers_words = SimpleArrayField(forms.CharField(max_length=256), required=False)
    shodan_query = SimpleArrayField(forms.CharField(max_length=256), required=False)
    google_dork = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False)
    tags = SimpleArrayField(forms.CharField(max_length=256))
    tcpversioning = SimpleArrayField(forms.CharField(max_length=256), required=False)

class WordListGroupFormCreate(forms.Form):
    groupName = forms.CharField( max_length=256 )
    type = forms.CharField( max_length=32 )
    description = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False, initial="It may seem dumb but add some context")
    count = forms.CharField( max_length=20, required=False)

class WordListGroupFormData(forms.ModelForm):
    class Meta:
        model = WordListGroup
        fields = (
            'groupName',
            'type',
            'description',
            'count'
            )

class CustomUserCreationForm(UserCreationForm):
    signup_key = forms.CharField(max_length=255)

    class Meta(UserCreationForm.Meta):
        fields = UserCreationForm.Meta.fields + ('signup_key',)