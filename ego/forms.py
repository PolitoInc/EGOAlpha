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
from django.contrib.auth import get_user_model
import uuid
from ego.models import * 
from ego.serializers import *


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['user', 'email']

class AdminUserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['user', 'email', 'role']

class GroupInvitationForm(forms.ModelForm):
    class Meta:
        model = GroupInvitation
        fields = ['email', 'role']

class EGOAgentForm(forms.ModelForm):
    class Meta:
        model = EGOAgent
        fields = ['name', 'hostLocation', 'callBackTime', 'alive', 'scanning']

User = get_user_model()

class OTPAuthenticationForm(AuthenticationForm):
    otp_code = forms.CharField(max_length=6, widget=forms.TextInput(attrs={'autocomplete': 'off'}))

class CustomUserCreationForm(UserCreationForm):
    secret_code = forms.CharField(max_length=100, required=False)
    email = forms.EmailField(required=True)
    tenant = forms.CharField(max_length=100)  # Add this line

    class Meta(UserCreationForm.Meta):
        fields = UserCreationForm.Meta.fields + ('email', 'secret_code', 'tenant',)  # Add 'tenant' here

User = get_user_model()


class CustomersFormCreate(forms.ModelForm):
    class Meta:
        model = Customers
        fields = ['user', 'groupingProject', 'nameProject', 'nameCustomer', 'URLCustomer', 'customDaysUntilNextScan', 'toScanDate', 'endToScanDate', 'EgoReconScan', 'reconOnly', 'passiveAttack', 'agressiveAttack', 'notes', 'OutOfScopeString', 'urlScope', 'outofscope', 'domainScope', 'Ipv4Scope', 'Ipv6Scope', 'FoundTLD', 'FoundASN', 'skipScan']
        widgets = {
            'user': forms.Select(attrs={'class': 'form-control', 'style': 'width:300px;'}),
            'groupingProject': forms.TextInput(attrs={'class': 'form-control', 'style': 'width:300px;'}),
            'nameProject': forms.TextInput(attrs={'class': 'form-control', 'style': 'width:300px;', 'font-size': '15'}),
            'nameCustomer': forms.TextInput(attrs={'class': 'form-control', 'style': 'width:300px;'}),
            'URLCustomer': forms.TextInput(attrs={'class': 'form-control', 'style': 'width:400px;'}),
            'customDaysUntilNextScan': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width:200px;'}),
            'toScanDate': forms.DateInput(attrs={'class': 'form-control', 'type': 'date', 'style': 'width:400px;'}),
            'endToScanDate': forms.DateInput(attrs={'class': 'form-control', 'type': 'date', 'style': 'width:400px;'}),
            'EgoReconScan': forms.CheckboxInput(attrs={'class': 'form-check-input', 'value': 'False'}),
            'reconOnly': forms.CheckboxInput(attrs={'class': 'form-check-input', 'value': 'False'}),
            'passiveAttack': forms.CheckboxInput(attrs={'class': 'form-check-input', 'value': 'False'}),
            'agressiveAttack': forms.CheckboxInput(attrs={'class': 'form-check-input', 'value': 'False'}),
            'notes': forms.Textarea(attrs={'class': 'form-control ', 'style': 'width:500px;'}),
            'OutOfScopeString': forms.TextInput(attrs={'class': 'form-control', 'style': 'width:500px;'}),
            'urlScope': forms.Textarea(attrs={'class': 'form-control', 'style': 'width:500px;'}),
            'outofscope': forms.Textarea(attrs={'class': 'form-control', 'style': 'width:500px;'}),
            'domainScope': forms.Textarea(attrs={'class': 'form-control', 'style': 'width:500px;'}),
            'Ipv4Scope': forms.Textarea(attrs={'class': 'form-control', 'style': 'width:500px;'}),
            'Ipv6Scope': forms.Textarea(attrs={'class': 'form-control', 'style': 'width:500px;'}),
            'FoundTLD': forms.Textarea(attrs={'class': 'form-control', 'style': 'width:500px;'}),
            'FoundASN': forms.Textarea(attrs={'class': 'form-control', 'style': 'width:500px;'}),
            'skipScan': forms.CheckboxInput(attrs={'class': 'form-check-input', 'value': 'False'}),
        }
    def __init__(self, *args, **kwargs):
        super(CustomersFormCreate, self).__init__(*args, **kwargs)
        self.fields['groupingProject'].initial = self.instance.groupingProject if self.instance.pk else 'Ego'


class SimpleCustomersFormCreate(forms.ModelForm):
    class Meta:
        model = Customers
        fields = ['user', 'groupingProject', 'nameProject', 'nameCustomer', 'URLCustomer', 'customDaysUntilNextScan', 'toScanDate', 'endToScanDate', 'EgoReconScan',
                  'reconOnly', 'passiveAttack', 'agressiveAttack', 'notes', 'OutOfScopeString', 'urlScope', 'outofscope', 'domainScope', 'Ipv4Scope', 'Ipv6Scope', 'FoundTLD', 'FoundASN', 'skipScan']


class create_egocontrol(forms.ModelForm):
    class Meta:
        model = EgoControl
        fields = [
            'ScanProjectByID', 'internal_scanner', 'ScanGroupingProject', 'ScanProjectByName', 'OutOfScope', 
            'chunk_size', 'CoolDown', 'CoolDown_Between_Queries', 'Port', 'HostAddress', 'passiveAttack', 
            'agressiveAttack', 'portscan_bool', 'versionscan_bool', 'Scan_Scope_bool', 'Scan_IPV_Scope_bool', 
            'Scan_DomainName_Scope_bool', 'scriptscan_bool', 'BruteForce', 'BruteForce_WL', 'scan_records_censys', 
            'crtshSearch_bool', 'Update_RecordsCheck', 'LoopCustomersBool', 'Completed', 'Gnaw_Completed', 'failed', 
            'scan_objects'
        ]
        widgets = {
            'ScanProjectByID': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'ScanGroupingProject': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'ScanProjectByName': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'OutOfScope': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 450px;'}),
            'chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'CoolDown': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'CoolDown_Between_Queries': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'Port': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'HostAddress': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'passiveAttack': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'agressiveAttack': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'portscan_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'versionscan_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Scan_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Scan_IPV_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Scan_DomainName_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scriptscan_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'BruteForce': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'BruteForce_WL': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'scan_records_censys': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'crtshSearch_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Update_RecordsCheck': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'LoopCustomersBool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Gnaw_Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'failed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_objects': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }
    def __init__(self, *args, **kwargs):
        super(create_egocontrol, self).__init__(*args, **kwargs)
        self.fields['ScanProjectByID'].initial = 'Unique Identifier'
        self.fields['internal_scanner'].initial = False
        self.fields['ScanGroupingProject'].initial = 'Group Name'
        self.fields['ScanProjectByName'].initial = 'Project Name'
        self.fields['OutOfScope'].initial = ''
        self.fields['chunk_size'].initial = 12
        self.fields['CoolDown'].initial = 2
        self.fields['CoolDown_Between_Queries'].initial = 6
        self.fields['Port'].initial = 9000
        self.fields['HostAddress'].initial = 'http://127.0.0.1'
        self.fields['passiveAttack'].initial = False
        self.fields['agressiveAttack'].initial = True
        self.fields['portscan_bool'].initial = True
        self.fields['versionscan_bool'].initial = True
        self.fields['Scan_Scope_bool'].initial = True
        self.fields['Scan_IPV_Scope_bool'].initial = False
        self.fields['Scan_DomainName_Scope_bool'].initial = True
        self.fields['scriptscan_bool'].initial = True
        self.fields['BruteForce'].initial = False
        self.fields['BruteForce_WL'].initial = list()
        self.fields['scan_records_censys'].initial = False
        self.fields['crtshSearch_bool'].initial = True
        self.fields['Update_RecordsCheck'].initial = False
        self.fields['LoopCustomersBool'].initial = False
        self.fields['Completed'].initial = False
        self.fields['Gnaw_Completed'].initial = False
        self.fields['failed'].initial = False
        self.fields['scan_objects'].initial = list()
        
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

class create_gnawcontrol(forms.ModelForm):
    class Meta:
        model = GnawControl
        fields = [
            'NucleiScan', 'Ipv_Scan', 'egoAgentID', 'LoopCustomersBool', 'OutOfScope', 'ScanProjectByID', 
            'ScanGroupingProject', 'ScanProjectByName', 'Customer_chunk_size', 'Record_chunk_size', 
            'Global_Nuclei_CoolDown', 'Global_Nuclei_RateLimit', 'Port', 'HostAddress', 'severity', 
            'Gnaw_Completed', 'failed', 'scan_objects'
        ]
        widgets = {
            'NucleiScan': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Ipv_Scan': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'egoAgentID': forms.Select(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'LoopCustomersBool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'OutOfScope': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 450px;'}),
            'ScanProjectByID': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'ScanGroupingProject': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'ScanProjectByName': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'Customer_chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Record_chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Global_Nuclei_CoolDown': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Global_Nuclei_RateLimit': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Port': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'HostAddress': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'severity': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'Gnaw_Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'failed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_objects': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }
    def __init__(self, *args, **kwargs):
        super(create_gnawcontrol, self).__init__(*args, **kwargs)
        self.fields['NucleiScan'].initial = True
        self.fields['Ipv_Scan'].initial = False
        self.fields['Ipv_Scan'].initial = False
        self.fields['LoopCustomersBool'].initial = False       
        self.fields['Gnaw_Completed'].initial = False
        self.fields['failed'].initial = False

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
        model = PythonMantis
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

class create_mantisCardCreate(forms.ModelForm):
    class Meta:
        model = VulnCard
        fields = [
            'name', 'vulnClass', 'author', 'severity', 'cvss_metrics', 'cvss_score', 
            'cwe_id', 'description', 'impact', 'proof_of_concept', 'remediation', 
            'references', 'pictures'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'vulnClass': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'author': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'severity': forms.Select(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'cvss_metrics': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'cvss_score': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'cwe_id': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'impact': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'proof_of_concept': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'remediation': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'references': forms.URLInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'pictures': forms.ClearableFileInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }

class create_mantiscontrol(forms.ModelForm):
    class Meta:
        model = MantisControls
        fields = [
            'NucleiScan', 'Ipv_Scan', 'LoopCustomersBool', 'OutOfScope', 'ScanProjectByID', 
            'ScanGroupingProject', 'ScanProjectByName', 'Customer_chunk_size', 'Record_chunk_size', 
            'Global_CoolDown', 'Global_RateLimit', 'Port', 'HostAddress', 'severity', 
            'Elavate', 'Mantis_Completed', 'failed', 'scan_objects'
        ]
        widgets = {
            'NucleiScan': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Ipv_Scan': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'LoopCustomersBool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'OutOfScope': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 450px;'}),
            'ScanProjectByID': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'ScanGroupingProject': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'ScanProjectByName': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'Customer_chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Record_chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Global_CoolDown': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Global_RateLimit': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Port': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'HostAddress': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'severity': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'Elavate': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'Mantis_Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'failed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_objects': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }

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

