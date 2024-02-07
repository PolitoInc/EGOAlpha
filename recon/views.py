from django.contrib.auth.decorators import login_required, permission_required

from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
import requests, json, re, time
from datetime import datetime
import fuzzywuzzy
import uuid, folium, pycountry
from geopy.geocoders import Nominatim
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import pandas as pd
import numpy as np
import statistics
import tldextract
from statistics import mode
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

from collections import deque
import codecs
from django.views import generic
from rest_framework.response import Response
from django.urls import reverse
from django.shortcuts import render, redirect, get_object_or_404
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from django.urls import reverse_lazy
from django.core.files import File
from rest_framework.authtoken.models import Token
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, timedelta
from recon.models import * 
from recon.forms import *
from recon.serializers import *
from django.template.response import TemplateResponse;
from django.shortcuts import render, redirect, reverse
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.template import loader
from django.db.models import Q

from django.core.files.storage import FileSystemStorage
from django.views import View
from django.utils.decorators import method_decorator
from django.core.paginator import Paginator, EmptyPage
from django.shortcuts import render
from django.contrib.auth.models import Group, User, ContentType
from django.http import HttpResponseForbidden, HttpResponseServerError
from rest_framework.views import APIView

class SignUpView(generic.CreateView):
    form_class = CustomUserCreationForm
    success_url = reverse_lazy('login')
    template_name = './auth/signup.html'
    
    def form_valid(self, form):
        signup_key = form.cleaned_data.get('meow')
        if signup_key == 'string':  # replace 'string' with your actual key
            response = super().form_valid(form)
            # Authenticate the user
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            if user:
                user.is_active = True  # Make the user active
                user.save()  # Save the user
                # Log the user in
                login(self.request, user)
                return response
            else:
                return self.form_invalid(form)
        return super().form_valid(form)

class LoginView(generic.FormView):
    form_class = AuthenticationForm
    success_url = reverse_lazy('ProjectsListView')  # Changed 'projectviewset' to 'project'
    template_name = './auth/login.html'

    def form_valid(self, form):
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password1')  # Changed 'password' to 'password1'
        user = authenticate(self.request, username=username, password=password)
        if user is not None:
            login(self.request, user)
            return super().form_valid(form)
        else:
            return HttpResponseRedirect(reverse('login_fail'))  # Redirect to 'login_fail' if login failed

class LoginApiView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if user:
            # Generate or retrieve a token for the authenticated user
            token, created = Token.objects.get_or_create(user=user)
            return Response({"token": token.key}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid username/password"}, status=status.HTTP_400_BAD_REQUEST)

def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to 'login' after logout

@login_required
def get_domain_values(domain):
    domain = domain['subDomain']
    tldExtracted= tldextract.extract(domain)
    SUFFIX= tldExtracted.suffix
    DOMAIN= tldExtracted.domain
    SUBDOMAIN= tldExtracted.subdomain
    return {"suffix": SUFFIX, "DOMAIN": DOMAIN,"SUBDOMAIN": SUBDOMAIN}

@login_required
def wordCreation(request):
    if request.method == 'GET':
        print('error')
    else:
        name = 'SupremeWordList'
        WordList = DirectoryListingWordListSerializer()
        try:
            WordList = WordList[name]
        except:
            WordList = False
        if WordList:
            Words = WordList['WordList']
            records = RecordSerializer()
        else:
            Subdomains = Record.objects.values_list('subDomain', flat=True)
            print(Subdomains)
            records_stored = {}
            records_stored = {}
            totalCount = count(Subdomains)
            domains = []
            subDomains= []
            Domain_Data_Set = {"subDomainCount": count(subDomains), "domainCount": count(domains), "totalCount": totalCount, "domainData": []}
            dataSet_wordlistgroup = {"groupName": name, "type": "DNS", "description": f"the {name} is the self maintaining growing and learning list of found subdomains that will help with future discoveries.","count": 0}
            for rec in Subdomains:
                records_stored.add(rec['subDomain'])
                domain = rec['subDomain']
                tldExtracted= tldextract.extract(domain)
                SUFFIX= tldExtracted.suffix
                DOMAIN= tldExtracted.domain
                SUBDOMAIN= tldExtracted.subdomain
                dataSet_WordList = {"type": "DNS", "Value": SUBDOMAIN, "Occurance": 1, "foundAt": [DOMAIN.SUFFIX]}
                print(domain)
            return TemplateResponse(requests, 'Vulns/explore.html', {"customers": customers})

@login_required
def fileUpload(request):
    if request.method == 'POST' and request.FILES['uploaded_file']:
        uploaded_file = request.FILES['uploaded_file']
        fs = FileSystemStorage()
        filename = fs.save(uploaded_file.name, uploaded_file)
        filename = fs.url(filename)
        return render(request, 'WordList/WordClass.html', {
            'filename': filename
        })
    else:
        return render(request, 'WordList/WordClass.html', {})

# Views
@login_required
def home(request):
    return render(request, "registration/success.html", {})

@login_required
def CustomerVIEW(request):
    search_query = request.GET.get('search', '')
    customers = Customers.objects.all()
    if search_query:
        customers = customers.filter(
            Q(groupingProject__icontains=search_query) | 
            Q(nameProject__icontains=search_query) | 
            Q(nameCustomer__icontains=search_query) |
            Q(URLCustomer__icontains=search_query) |
            Q(notes__icontains=search_query) |
            Q(OutOfScopeString__icontains=search_query) |
            Q(urlScope__icontains=search_query) |
            Q(outofscope__icontains=search_query) |
            Q(domainScope__icontains=search_query) |
            Q(Ipv4Scope__icontains=search_query) |
            Q(Ipv6Scope__icontains=search_query) |
            Q(FoundTLD__icontains=search_query) |
            Q(FoundASN__icontains=search_query)
        )
    serializer = limitedCustomerSerializer(customers, many=True)
    data = serializer.data
    return TemplateResponse(request, 'Customers/customers.html', {"Customers": data})


@login_required
def CustomersDelete(request, pk):
    Control = Customers.objects.get(pk=pk)
    Control.delete() 
    return HttpResponseRedirect('/Customers/')

@login_required
def VulnSubmitted(request, pk):
    results = FoundVuln.objects.get(pk=pk)
    if request.POST == 'POST':
        form = FoundVulnFormPK(request.POST, instance=results)
        if form.is_valid():
            form.Submitted = True
            form.save()
    
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))



# create a customer record    



# Get country information from 2 character country code EN US FR GR
@login_required
def get_country_location(country_code):
    try:
        country_info = pycountry.countries.get(alpha_2=country_code.upper())
        # You would need to replace this with a method to get the actual latitude and longitude of the country
        return country_info.name
    except AttributeError:
        print(f"Invalid country code: {country_code}")
        return None

#rretrieves latitude and lonogitufe   from country name
@login_required
def get_latitude_location(country_name, city):
    
    if str(country_name) != 'REDACTED FOR PRIVACY' and country_name != None:
        #location = geolocator.geocode(str(country_name))
        geolocator = Nominatim(user_agent="geopy get country")
        location = geolocator.geocode(str(get_country_location(country_name)))
        return [location.latitude, location.longitude]
    elif str(city) != 'REDACTED FOR PRIVACY' and city != None:
        #location = geolocator.geocode(str(country_name))
        geolocator = Nominatim(user_agent="Geopy Library")
        location = geolocator.geocode(str(city))
        return [location.latitude, location.longitude]
    else:
        pass
    return None

@login_required
def CustomersCreate(request, format=None):
    if request.method == 'POST':
        form = CustomersForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('/Customers/customerCreate.html')
    elif request.method == 'GET':
        form = CustomersForm()
    else:
        form = CustomersForm()
    return TemplateResponse(request, 'Customers/customerCreate.html', {'form': form})

#retrieve customer record
@login_required
def CustomerPk(request, pk, format=None):
    if request.method == 'GET':
        customer = get_object_or_404(Customers, pk=pk)
        form = CustomersForm(instance=customer)
        serializer = CustomerRecordSerializer(customer)
        data = serializer.data
        # get longitude and latitude from nested records from GEOCODES
        Map_Generation = request.GET.get('mapcreate', None)
        if Map_Generation:
            whois_customers= whois.objects.filter(customer_id=pk)
            print('whois_customers', whois_customers)
            for x in whois_customers:
                    print(x.map_image)
                    print('map')
                    location = get_latitude_location(x.country, x.city)
                    print(location)
                    if location != None:
                        map = folium.Map(location=location, zoom_start=5)
                        name = f"img{x.id}.html"
                        map.save(name)
                        with open(name, 'rb') as f:
                            file_data = File(f)
                            x.map_image = file_data
                            # Assuming `customer` is a Django model instance
                            x.map_image.save(name, file_data, save=True) 

        # Filter out records where 'alive' is False
        alive_records = [record for record in data['customerrecords'] if record['alive']]
     
     # If search query is provided in GET request, filter the records
        search_query = request.GET.get('search', None)
        if search_query:
            alive_records = [x for x in alive_records if search_query in str(x)]
        # Perform pagination on the nested field value 'customer_records'
        paginator = Paginator(alive_records, 100)  # Show 20 records per page

        # Get the page number from the GET request. If no page number is provided, default to 1
        page_number = request.GET.get('page', 1)

        # Get the data for the requested page
        try:
            page_obj = paginator.page(page_number)
        except EmptyPage:
            # If page is out of range (e.g. 9999), deliver last page of results.
            page_obj = paginator.page(paginator.num_pages)

        # Merge paginated 'customer_records' back into data
        data['customerrecords'] = [record for record in page_obj.object_list]

        return TemplateResponse(request, "Customers/customersPK.html", {"Customer": data, "form": form, 'page_obj': page_obj})

    elif request.method == 'POST':
        customer = get_object_or_404(Customers, pk=pk)
        form = CustomersForm(request.POST, instance=customer)
        if form.is_valid():
            results = form.save()
            return HttpResponseRedirect(f'/Customers/{results.pk}/')
        else:
            return HttpResponse("Form is not valid", status=400)
    else:
        form = CustomersForm(instance=customer)
    return render(request, 'form_template.html', {'form': form})

@login_required

def Interconneciton(request, pk):
    results = get_object_or_404(Customers, pk=pk)
    #record = CustomersViewSet(results)
    queryset = CustomerRecordSerializer(results)

    customers_ = queryset.data['customer_records']
    dic = {}
    for x in customers_:

        ipaddr = x.get('ip', {})
        print(ipaddr)
        if ipaddr == 0:
            pass
        else:
            try:
                if bool(ipaddr) == False:
                       pass
                else:
                    #print('ipaddr',ipaddr)
                    dic.update({ ipaddr : f"{int(dic[ipaddr]) + 1}" })
            except:
                dic.update({ ipaddr : "1" })
    data = []
    labels = []
    for d in dic:
        valuenew = str(dic[d])
        if valuenew == "0":
            pass
        else:
            data.append(valuenew)
            labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"data": data, "labels": labels})

@login_required

def VulnsBoardChartPK(request, pk):
    results = get_object_or_404(Customers, pk=pk)
    #record = CustomersViewSet(results)
    queryset = CustomerRecordSerializer(results)
    customers_ = queryset.data['customer_records']
    sev_score = {"info": "0", "low": "0", "medium": "0", "high": "0" , "critical": "0", "unknown": "0"}
    for x in customers_:
        print('x')
        querysetTemplate = x['Templates_record']
        queryset = x['foundVuln_record']
        count = len(queryset)
        for s in querysetTemplate:
            print('s',s)
            s.items()
            ocr = s['info']
            ocr = ocr['severity']
            value = sev_score[ocr]
            new_value = int(value) + 1
            print(new_value)
            sev_score.update({ocr: new_value})
        for s in queryset:
            s.items()
            ocr = s['severity']
            value = sev_score[ocr]
            new_value = int(value) + 1
            print(new_value)
            sev_score.update({ocr: new_value})
    data = []
    labels = []
    for d in sev_score:
        valuenew = str(sev_score[d])
        data.append(valuenew)
        labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"data": data, "labels": labels})

@login_required

def RecordDelete(request, pk):
    results = get_object_or_404(Record, pk=pk)
    #record = CustomersViewSet(results)
    queryset = TotalRecords(results)
    queryset.delete() 
    return HttpResponseRedirect(f'/Customers/{results.pk}')

## GNAW
@login_required
def GnawControlBoards(request):
    gnaw = GnawControl.objects.all()
    customers = Customers.objects.all()
    form = create_gnawcontrol()
    create = GnawControlCreateViewSet()
    return TemplateResponse(request, 'GnawControl/gnawControlBoards.html', {"gnaw": gnaw, "customers": customers, "create":create, "form": form})

@login_required
def GnawControlBoardsCreate(request):
    if request.method == 'GET':
        form = create_gnawcontrol()
        return TemplateResponse(request, f'GnawControl/gnawControlBoardsCreate.html', {"form": form})
    
    if request.method == 'POST':
        form = create_gnawcontrol(request.POST or None)
        if form.is_valid():
            form.cleaned_data['HostAddress'] = form.cleaned_data['HostAddress'].rstrip('/')  # Remove trailing slash
            form.save()
            return HttpResponseRedirect('/GnawControlBoard/')
        else:
            # Handle the case where the form is not valid
            pass
        
@login_required
def GnawControlBoardsPK(request, pk):
    results = GnawControl.objects.get(pk=pk)
    form = create_mantiscontrol()
    if request.method == 'GET':
        form = create_gnawcontrol(instance=results)

        return TemplateResponse(request, f'GnawControl/gnawControlBoardsPk.html', {"control": results, "form": form})
    if request.method == 'POST':
        form = create_gnawcontrol(request.POST, instance=results or None)
        if form.is_valid():
            form.save()
        return HttpResponseRedirect(f'/GnawControlBoard/{results.pk}')

## EGO
@login_required

def EgoControlBoard(request):
    response = EgoControl.objects.all()
    customers = Customers.objects.all()

    return TemplateResponse(request, 'EgoControl/EgoControlBoard.html', {"controls": response, "customers": customers})

@login_required
def EgoControlCreate(request):
    if request.method == 'POST':
        form = create_egocontrol(request.POST)
        if form.is_valid():
            form.save()
            return redirect('/EgoControlBoard/create')  # replace with your success url
    else:
        form = create_egocontrol()
    return TemplateResponse(request, 'EgoControl/EgoControlBoardCreate.html', {'form': form})  # replace 'template_name.html' with your template name

@login_required
def EgoControlBoardDelete(request, pk):
    Control = get_object_or_404(EgoControl, pk=pk)
    Control.delete() 
    return HttpResponseRedirect('/EgoControlBoard/')

@login_required
def EgoControlBoardpk(request, pk):
    results = EgoControl.objects.get(pk=pk)
    if request.method == 'POST':
        form = create_egocontrol(request.POST, instance=results)
        if form.is_valid():
            results= form.save()
            return HttpResponseRedirect(f'/EgoControlBoard/{results.pk}')
        else:
            return HttpResponse("Form is not valid", status=400)
    else:
        form = create_egocontrol(instance=results)
    return TemplateResponse(request, 'EgoControl/EgoControlBoardpk.html', {"control": results, "form":form})
#VULNS 
# list vulns found
@login_required
def VulnBoards(request):
    query = request.GET.get("q")
    print(query)
    if query:
        querysetTemplate = Template.objects.filter(name__icontains=query)
        querysetFoundVuln = FoundVuln.objects.filter(name__icontains=query)
    else:
        querysetTemplate = Template.objects.all()
        querysetFoundVuln = FoundVuln.objects.all()

    count = len(querysetFoundVuln) + len(querysetTemplate)

    if request.method == 'GET':
        return TemplateResponse(request, "Vulns/VulnBoards.html", {"Vulns": querysetFoundVuln, "Template": querysetTemplate, "count": count})


# create mantis controls
@login_required

def VulnBoardCreate(request):
    context ={}
    mantis = PythonMantis.objects.all()
    cards = VulnCard.objects.all()
    form = create_mantiscontrol()
    formdata = MantisDataCreate()
    if request.method == 'GET':
        form = MantisDataCreate(request.POST or None)
        context['form']=form
        return TemplateResponse(request, f'Vulns/VulnBoardCreate.html', {"mantis": mantis, "cards": cards, "form": form})
    if request.method == 'POST':
        form = MantisDataCreate(request.POST or None)
        dict_ = dict(request.POST)
        json_ = json.dumps(dict_)
        print(json_)
        Name = dict_[('name')]
        print(Name)
        regex = r"(\w+)"
        clean_name = re.findall(regex, str(Name))
        filename = ''.join(clean_name)
        f = open(f"./vulns/{filename}.json", "x")
        f.write(json_)
        f.close()
        if form.is_valid():
            form.save()
        context['form']=form
        return TemplateResponse(request, f'Vulns/VulnBoardCreate.html', {"mantis": mantis, "cards": cards, "form": form})


@login_required

def VulnBoardDeletePK(request, pk):
    Control = PythonMantis.objects.get(pk=pk)
    Control.delete() 
    return HttpResponseRedirect(f'/VulnBoard/create/')

@login_required

def VulnBoardCreatePK(request, pk):
    context ={}
    mantis = PythonMantis.objects.get(pk=pk)
    form = create_mantiscontrol()
    #cards = VulnCard.objects.get(pk=uuid.UUID(mantis.vulnCard_id))
    if request.method == 'GET':
        form = MantisDataCreate(instance=mantis)

        return TemplateResponse(request, f'Vulns/VulnBoardCreatePK.html', {"results": mantis, "form": form})
    if request.method == 'POST':
        form = MantisDataCreate(request.POST  or None, instance=mantis)
        dict_ = dict(request.POST)
        json_ = json.dumps(dict_)
        print(json_)
        Name = dict_[('name')]
        regex = r"(\w+)"
        clean_name = re.findall(regex, str(Name))
        filename = ''.join(clean_name)
        f = open(f"./vulns/{filename}.json", "r+")
        f.write(json_)
        f.truncate()
        f.close()
        if form.is_valid():
            form.save()
        context['form']=form
        return HttpResponseRedirect(f'/VulnBoard/create/{pk}')


## vulncards 
@login_required

def VulnCardCreate(request):
    queryset = VulnCard.objects.all()
    form = create_mantisCardCreate()
    if request.method == 'GET':
        return TemplateResponse(request, "Vulns/vulncards.html", {"results": queryset, "form": form })
    if request.method == 'POST':
        form = create_mantisCardCreate(request.POST  or None)
        if form.is_valid():
            form.save()
        return HttpResponseRedirect(f'/VulnBoard/create/')

@login_required

def VulnCardPK(request, pk):
    queryset = VulnCard.objects.get(pk=pk)
    form = create_mantisCardCreate(instance=queryset)
    if request.method == 'GET':
        return TemplateResponse(request, "Vulns/VulnCard.html", {"results": queryset, "form": form})
    if request.method == 'POST':
        form = create_mantisCardCreate(request.POST  or None, instance=queryset)
        if form.is_valid():
            form.save()
        return HttpResponseRedirect(f'/VulnBoard/create/{pk}')



@login_required

def VulnsBoardChart(request):
    querysetTemplate = Template.objects.all()
    queryset = FoundVuln.objects.all()
    count = len(queryset)
    sev_score = {"info": "0", "low": "0", "medium": "0", "high": "0" , "critical": "0", "unknown": "0"}
    for s in querysetTemplate:
        ###print('s',s)
        ocr = s.info['severity']
        value = sev_score[ocr]
        new_value = int(value) + 1
        ###print(new_value)
        sev_score.update({ocr: new_value})
    for s in queryset:
        ###print(s)
        ocr = s.severity
        value = sev_score[ocr]
        new_value = int(value) + 1
        ###print(new_value)
        sev_score.update({ocr: new_value})
    data = []
    labels = []
    for d in sev_score:
        valuenew = str(sev_score[d])
        data.append(valuenew)
        labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"data": data, "labels": labels})

@login_required

def AliveOrDeadChartPk(request, pk):
    results = get_object_or_404(Customers, pk=pk)
    #record = CustomersViewSet(results)
    queryset = CustomerRecordSerializer(results)

    customers_ = queryset.data['customer_records']
    
    aliveordead = {"dead": "0", "alive": "0"}
    hostalive = [x['alive'] for x in customers_  if x['alive'] == True]
    hostdead = [x['alive'] for x in customers_  if x['alive'] == False]
    count_alive = len(hostalive)
    count_dead = len(hostdead)
    aliveordead.update({"dead": count_dead})
    aliveordead.update({"alive": count_alive})
    data = []
    labels = []
    for d in aliveordead:
        valuenew = str(aliveordead[d])
        data.append(valuenew)
        labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"labels": labels, "data": data})

@login_required

def PortChartPk(request, pk):
    results = get_object_or_404(Customers, pk=pk)
    #record = CustomersViewSet(results)

    queryset = CustomerRecordSerializer(results)
    customers_ = queryset.data['customer_records']
    ports_store = {}
    for x in customers_:
        ports = x.get('OpenPorts',[])
        
        for p in ports:
            try:
                ports_store.update({f"{p}": f"{ int(ports_store[p]) + 1 }"})
            except:
                ports_store.update({f"{p}": "1" })
    data = []
    labels = []
    for d in ports_store:
        valuenew = str(ports_store[d])
        data.append(valuenew)
        labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"data": data, "labels": labels})


    
@login_required

def Vulnerabilty(request):
    Templates = Template.objects.all()
    #convert reponse data into json
    DIC = {}
    out_vulns = []
    for users in Templates:
        #record_id = `s['record_id']
        #rjson = response.json()
        #users['customer'] = rjson.get('customer',{})
        sevrity= users['info']
        if sevrity['severity'] == 'low':
            out_vulns.append(users)
        elif sevrity['severity'] == 'medium':
            out_vulns.append(users)
        elif sevrity['severity'] == 'high':
            out_vulns.append(users)
        elif sevrity['severity'] == 'critical':
            out_vulns.append(users)
    if out_vulns:
        out=[]
        for out_vuln in out_vulns:
            out_vuln_time= out_vuln['date']
            current_date = (out_vuln_time.replace("T", " ").replace(".000Z", "")).split(" ")[0]
            out_vuln.update({'date':current_date})
            out.append(out_vuln)
        return render(request, "Vuln/VulnerabilitiesApp.html", {'out_vuln': out})
    else:
        return render(request, "Vuln/VulnerabilitiesApp.html", {'out_vuln': out})

#def MantisControlsApp(requests):

@login_required

def WordClass(request):
    WordList = WordListGroup.objects.all()
    form = WordListGroupFormCreate()
    return TemplateResponse(request, "WordList/WordClass.html", {"WordList": WordList, "form": form})

@login_required

def WordClassCreate(request):
    WordList = WordListGroup.objects.all()
    if request.method == 'POST':
        form = WordListGroupFormData(request.POST or None)
        if form.is_valid():
            form.save()
    return HttpResponseRedirect(f"/WordList/")

@login_required

def TotalVulnApp(request, pk):
    index = [
        ('info, low, medium, high, critical, unknown'),
     ('info'),
     ('low'),
     ('medium'),
     ('high'),
     ('critical'),
     ('unknown')
     ]  

    response = requests.get(f'http://127.0.0.1:10000/api/customers/{pk}')
    #convert reponse data into json
    rjson = response.json()
    Records_here = rjson['customer_records']
    services_nmap_out = []

    ports_out= []
    set_sorted_ports=[]
    single_ports_out= set()
    newcpeseen=[]
    for n in Records_here:
        domain = n.get('subDomain')
        ###print(domain)
        nmap = n.get('Nmaps_record',[])
        nmap_ports = {"ports" : []} 
        nmap_products = {"products" : [] }
        nmap_services = {"services" : [] }
        nmap_protocols = {"protocols" : [] }
        listed_services = []
        for map in nmap:
            if n['alive'] == False:
                pass
            else:
                ports = map.get('port', {})
                if ports:
                    nmap_ports['ports'].append(ports)
                    ports_out.append(ports)
                    set_sorted_ports.append(ports)
                    single_ports_out.add(ports)
                    
                try:
                    product = map.get('product')
                    nmap_products['products'].append(product)
                    protocol = map.get('protocol')
                    nmap_protocols['protocols'].append(protocol)
                    service = map.get('name')
                    nmap_services['services'].append(service)
                    servicefp = map['servicefp']
                    regex = re.compile("(?<=,\")(.*?)(?=\"\))")
                    print(servicefp['servicefp'])
                    found = re.search(regex, str(servicefp))
                    grouping = found.group(1)
                    spaces = grouping.replace('\\x20' , ' ')
                    macsnewline = spaces.replace('\\r', '')
                    period = macsnewline.replace('\\.', '.')
                    results = period.split('\\n')
                    request_formated_dict = dict.fromkeys(['results'], results)
                    DIC = {}
                    DIC.update(request_formated_dict)
                except:
                    DIC = {}
                    
                    
                record_dict = dict.fromkeys(['record'], n)

                    
                nmap_dict = dict.fromkeys(['map'], map)
                cpe = map.get('cpe')
                nist_dict=[]
                print('service',service)
                if len(cpe)>0:
                    try:
                        if cpe in newcpeseen:
                            pass
                        else:


                            newcpeseen.append(cpe)
                            newcpe=cpe.replace('cpe:/','')
                            print(newcpe)
                            time.sleep(1)
                            nisturl = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:{newcpe}:{service}"
                            print(nisturl)
                            response = requests.get(
                                url=nisturl
                            )
                            print(response.status_code)
                            print('above')
                            nist_rjson = response.json()
                            vulns = (nist_rjson.get('vulnerabilities'))
                                
                            for vuln in vulns:
                                print(vuln)
                                cve=vuln.get('cve')
                                for k in cve:
                                    print(k)
                                    if k == 'descriptions':
                                        DICnist_rjson ={}
                                        descript= cve.get('descriptions')
                                        descout = descript[0]
                                        DESCRIPT= dict.fromkeys(['descriptions'], descout)
                                        DICnist_rjson.update(DESCRIPT)
                                        references=cve.get('references')
                                        refeDict= dict.fromkeys(['references'], references)
                                        DICnist_rjson.update(refeDict)
                                        for d in descript:
                                            print(d)
                                            metrics = (cve.get('metrics'))
                                            print(metrics)
                                            cvs = metrics.get('cvssMetricV2', {})
                                                
                                            print(cvs)
                                            for score in cvs:
                    
                                                s = score.get('cvssData')
                                                DICnist_rjson.update(s)
                                                nist_dict.append(DICnist_rjson)
                    except:
                        pass
                nist_dict = dict.fromkeys(['nist'], nist_dict) 
                dict_cpe = dict.fromkeys(['cpe'], str(cpe))
                print('#')
               # ###print(nist_dict)
                print('#')
                subdomain = dict.fromkeys(['domain'], domain)
                DIC.update(nmap_ports)
                DIC.update(nist_dict)
                DIC.update(subdomain)
                DIC.update(dict_cpe)
                DIC.update(record_dict)
                DIC.update(nmap_dict)
                listed_services.append(DIC)
        listedServices = dict.fromkeys(['listed_services'], listed_services)
        outDIC = {}
        outDIC.update(listedServices)
        outDIC.update(nmap_products)
        outDIC.update(nmap_services)
        outDIC.update(nmap_protocols)
        
        
        services_nmap_out.append(outDIC)
        ###print('#')
        ###print('services_nmap_out', services_nmap_out)
        ###print('#')

    templates = [ n.get('Templates_record', {})[0] for n in Records_here if bool(n.get('Templates_record', {})) != False]
    info = [ t.get('info', {}) for t in templates]
    
    severity = [s['severity'] for s in info ]
    #severity = info.get('severity')
    occurrence = {item: severity.count(item) for item in severity}
    results = {item: 0 for item in index if item not in occurrence}
    occurrence.update(results)

    ###print(occurrence)
    print(np.cumsum(severity))
    #df = pd.DataFrame.from_dict(severity)
    #dfgraph = df.plot.bar()
    #image = dfi.export(df, 'dataframe.png')
    mydict = {
        "dataframe":  occurrence
    }
    
    #fuzz.partial_ratio(str(lowerCustomerValues),str(lowerVendorValues))
    seen=set()
    seen_add = seen.add
    tuple_list = [ t for t in services_nmap_out if  t.get('map') ]
    ###print('#')
    ###print(tuple_list)
    nmap_tup = [ (x.get('map').get('port')) for x in tuple_list  if x.get('map').get('port') ]
    ###print(nmap_tup)
    ###print('#')
    if nmap_tup:
        ignore = list(mode(nmap_tup))
        ###print(ignore)
    flat_list_ports = [s for s in tuple_list if s.get('map').get('port') != ignore]
    #flat_list_ports = [s for s in set_sorted_ports if s.get('OpenPorts', ) in super]
    flat_list_subdomain_alive = [p for p in Records_here if bool(p.get('alive', "")) == True ]
    flat_list_subdomain_dead = [p for p in Records_here if bool(p.get('alive', "")) == False ]
    counter = len(rjson['customer_records'])
    services_nmap = dict.fromkeys(['services_nmap'], services_nmap_out)
    dic_flat_list_subdomain_alive = dict.fromkeys(['alive_host'], flat_list_subdomain_alive)
    dic_flat_list_subdomain_dead = dict.fromkeys(['dead_host'], flat_list_subdomain_dead)
    dic_flat_list_ports = dict.fromkeys(['flat_list_port_tuple'], flat_list_ports)
    dic_ports = dict.fromkeys(['total_ports'], sorted(ports_out))
    dic_single_ports = dict.fromkeys(['single_ports'], sorted(single_ports_out))
    dic_count = dict.fromkeys(['counter'], counter)
    ###print(counter)
    rjson.update(dic_flat_list_subdomain_dead)
    rjson.update(dic_flat_list_subdomain_alive)
    rjson.update(dic_flat_list_ports)
    rjson.update(dic_count)
    rjson.update(dic_ports)
    rjson.update(dic_single_ports)
    rjson.update(mydict)
    rjson.update(services_nmap)
    print(rjson)
    if rjson:
        return render(request, "TotalVulnApp.html", {'rjson': rjson}, )
    else:
        return HttpResponseRedirect('/Web/')


def EgoControlFormViews(request):
    response = EgoControl.objects.all()
    customers = Customers.objects.all()
    return TemplateResponse(request, 'EgoControl/EgoControlBoards.html', {"controls": response, "customers": customers})

class BaseView:
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

class GnawControlCreateViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = GnawControlSerializer
    queryset = GnawControl.objects.all()

class GnawControlViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = GnawControlSerializer
    queryset = GnawControl.objects.all()

class EgoControlListViewSet(BaseView, generics.ListAPIView):
    serializer_class = EgoControlSerializer
    queryset = EgoControl.objects.all()

class EgoControlCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = EgoControlSerializer
    queryset = EgoControl.objects.all()

class EgoControlViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = EgoControlSerializer
    queryset = EgoControl.objects.all()

class nistCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = nistCPEID_serializers
    queryset = CPEID.objects.all()

class nistListViewSet(BaseView, generics.ListAPIView):
    serializer_class = nistCPEID_serializers
    queryset = CPEID.objects.all()

class nistViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = nistCPEID_serializers
    queryset = CPEID.objects.all()
    
class nistdescription_CreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = nist_description_serializers
    queryset = nist_description.objects.all()

class nistdescription_ListViewSet(BaseView, generics.ListAPIView):
    serializer_class = nist_description_serializers
    queryset = nist_description.objects.all()

class nistdescription_ViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = nist_description_serializers
    queryset = nist_description.objects.all()

class Createnist_descript_Nist_serializers_viewset(BaseView, generics.CreateAPIView):
    serializer_class = nist_descript_Nist_serializers
    queryset = nist_description.objects.all()

class Listnist_descript_Nist_serializers_viewset(BaseView, generics.ListAPIView):
    serializer_class = nist_descript_Nist_serializers
    queryset = nist_description.objects.all()

class nist_descript_Nist_serializers_retrieve_ViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = nist_descript_Nist_serializers
    queryset = nist_description.objects.all()

class nistCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = Totalnist_serializers
    queryset = nist_description.objects.all()

class nistListViewSet(BaseView, generics.ListAPIView):
    serializer_class = Totalnist_serializers
    queryset = nist_description.objects.all()
    
class nistViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = Totalnist_serializers
    queryset = nist_description.objects.all()

class csv_versionCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = csv_version_version_serializers
    queryset = csv_version.objects.all()

class csv_versionListViewSet(BaseView, generics.ListAPIView):
    serializer_class = csv_version_version_serializers
    queryset = csv_version.objects.all()

class csv_versionViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = csv_version_version_serializers
    queryset = csv_version.objects.all()

class ThreatModelingCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()

class ThreatModelingListViewSet(BaseView, generics.ListAPIView):
    serializer_class = ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()

class ThreatModelingViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()

class PythonMantisListViewSet(BaseView, generics.ListAPIView):
    serializer_class = PythonMantisSerializer
    queryset = PythonMantis.objects.all()

class PythonMantisCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = PythonMantisSerializer
    queryset = PythonMantis.objects.all()

class PythonMantisViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = PythonMantisSerializer
    queryset = PythonMantis.objects.all()

class VulnCardListViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = VulnCardSerializer
    queryset = VulnCard.objects.all()

class VulnCardViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = VulnCardSerializer
    queryset = VulnCard.objects.all()

class FoundVulnCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = FoundVulnSerializer
    queryset = FoundVuln.objects.all()

class FoundVulnListViewSet(BaseView, generics.ListAPIView):
    serializer_class = FoundVulnSerializer
    queryset = FoundVuln.objects.all()

class FoundVulnViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = FoundVulnSerializer
    queryset = FoundVuln.objects.all()

class FoundVulnDetailCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = FoundVulnDetailSerializers
    queryset = FoundVuln.objects.all()

class FoundVulnDetailListViewSet(BaseView, generics.ListAPIView):
    serializer_class = FoundVulnDetailSerializers
    queryset = FoundVuln.objects.all()

class FoundVulnDetailViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = FoundVulnDetailSerializers
    queryset = FoundVuln.objects.all()

class TotalFoundVulnCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = TotalFoundVulnSeerializers
    queryset = FoundVuln.objects.all()

class TotalFoundVulnListViewSet(BaseView, generics.ListAPIView):
    serializer_class = TotalFoundVulnSeerializers
    queryset = FoundVuln.objects.all()

class TotalFoundVulnViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TotalFoundVulnSeerializers
    queryset = FoundVuln.objects.all()

class ThreatModelingListViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()

class ThreatModelingViewSet(BaseView):
    serializer_class =ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()
    
class TemplatesListViewSet(BaseView, generics.ListAPIView):
    serializer_class = TemplatesSerializer
    queryset = Template.objects.all()

class TemplatesViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TemplatesSerializer
    queryset = Template.objects.all()
    
class TemplatesCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = TemplatesSerializer
    queryset = Template.objects.all()

class csv_versionCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = csv_version_version_serializers
    queryset = csv_version.objects.all()

class csv_versionListViewSet(BaseView, generics.ListAPIView):
    serializer_class = csv_version_version_serializers
    queryset = csv_version.objects.all()

class csv_versionViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = csv_version_version_serializers
    queryset = csv_version.objects.all()

class WordListGroupListViewSet(BaseView, generics.ListAPIView):
    serializer_class = WordListGroupSerializer
    queryset = WordListGroup.objects.all()
    
class WordListGroupCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = WordListGroupSerializer
    queryset = WordListGroup.objects.all()

class WordListGroupUpdateViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WordListGroupSerializer
    queryset = WordListGroup.objects.all()

class WordListListViewSet(BaseView, generics.ListAPIView):
    serializer_class = WordListSerializer
    queryset = WordList.objects.all()
    
class WordListCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = WordListSerializer
    queryset = WordList.objects.all()

class WordListUpdateViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WordListSerializer
    queryset = WordList.objects.all()

class DirectoryListViewSet(BaseView, generics.ListAPIView):
    serializer_class = DirectoryListingWordListSerializer
    queryset = WordListGroup.objects.all()

class DirectoryViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DirectoryListingWordListSerializer
    queryset = WordListGroup.objects.all()

class NmapListViewSet(BaseView, generics.ListAPIView):
    serializer_class = NmapSerializer
    queryset = Nmap.objects.all()

class NmapCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = NmapSerializer
    queryset = Nmap.objects.all()

class NmapViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = NmapSerializer
    queryset = Nmap.objects.all()

class CredentialsListViewSet(BaseView, generics.ListAPIView):
    serializer_class = CredentialsSerializer
    queryset = Credential.objects.all()

class CredentialsCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = CredentialsSerializer
    queryset = Credential.objects.all()

class CredentialsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CredentialsSerializer
    queryset = Credential.objects.all()

class RequestMetaDataListViewSet(BaseView, generics.ListAPIView):
    serializer_class = RequestMetaDataSerializer
    queryset = RequestMetaData.objects.all()

class RequestMetaDataCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = RequestMetaDataSerializer
    queryset = RequestMetaData.objects.all()

class RequestMetaDataViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = RequestMetaDataSerializer
    queryset = RequestMetaData.objects.all()

class CertificateRecordsListViewSet(BaseView, generics.ListAPIView):
    serializer_class = CertificateSerializer
    queryset = Certificate.objects.all()

class CertificateRecordsCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = CertificateSerializer
    queryset = Certificate.objects.all()

class CertificateRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CertificateSerializer
    queryset = Certificate.objects.all()

class DNSQueryRecordsListViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = DNSQuerySerializer
    queryset = DNSQuery.objects.all()

class DNSQueryRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DNSQuerySerializer
    queryset = DNSQuery.objects.all()

class DNSAuthRecordsListViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = DNSAuthoritySerializer
    queryset = DNSAuthority.objects.all()

class DNSAuthRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DNSAuthoritySerializer
    queryset = DNSAuthority.objects.all()

class NucleiRecordsListViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = NucleiSerializer
    queryset = Nuclei.objects.all()

class NucleiRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = NucleiSerializer
    queryset = Nuclei.objects.all()

class RecordsCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = RecordSerializer
    queryset = Record.objects.all()

class RecordsListViewSet(BaseView, generics.ListAPIView):
    serializer_class = RecordSerializer
    queryset = Record.objects.all()

class RecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = RecordSerializer
    queryset = Record.objects.all()

class TotalRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TotalRecords
    queryset = Record.objects.all()

class CustomersCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = CustomerSerializer
    queryset = Customers.objects.all()

class CustomersRetrieveLimitedViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = limitedCustomerSerializer
    queryset = Customers.objects.all()

class CustomersListViewSet(BaseView, generics.ListAPIView):
    serializer_class = limitedCustomerSerializer
    queryset = Customers.objects.all()

class vulncardListCreateViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = VulnCardSerializer
    queryset = VulnCard.objects.all()
    
class vulncardRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = VulnCardSerializer
    queryset = VulnCard.objects.all()

class CustomersViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CustomerRecordSerializer
    queryset = Customers.objects.all()

class apiCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = apiSerialiser
    queryset = api.objects.all()

class apiListViewSet(BaseView, generics.ListAPIView):
    serializer_class = apiSerialiser
    queryset = api.objects.all()

class apiRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = apiSerialiser
    queryset = api.objects.all()

class apiproviderCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = apiprovidersSerialiser
    queryset = apiproviders.objects.all()

class apiproviderListViewSet(BaseView, generics.ListAPIView):
    serializer_class = apiprovidersSerialiser
    queryset = apiproviders.objects.all()

class apiproviderRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = apiprovidersSerialiser
    queryset = apiproviders.objects.all()

class projectDocMangerRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = projectDocMangerSerializer
    queryset = projectManger.objects.all()

class projectMangerCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = projectMangerSerializer
    queryset = projectManger.objects.all()

class projectMangerListViewSet(BaseView, generics.ListAPIView):
    serializer_class = projectMangerSerializer
    queryset = projectManger.objects.all()
    
class apiprovidersRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = apiProviderApisSerialiser
    queryset = apiproviders.objects.all()

class apiprovidersCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = apiProviderApisSerialiser
    queryset = apiproviders.objects.all()

class apiprovidersListViewSet(BaseView, generics.ListAPIView):
    serializer_class = apiProviderApisSerialiser
    queryset = apiproviders.objects.all()

class DocMangerCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = DocMangerSerializer
    queryset = DocManger.objects.all()

class DocMangerListViewSet(BaseView, generics.ListAPIView):
    serializer_class = DocMangerSerializer
    queryset = DocManger.objects.all()

class DocMangerRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DocMangerSerializer
    queryset = DocManger.objects.all()

class FindingMatrixCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = FindingMatrixSerializer
    queryset = FindingMatrix.objects.all()

class FindingMatrixListViewSet(BaseView, generics.ListAPIView):
    serializer_class = FindingMatrixSerializer
    queryset = FindingMatrix.objects.all()

class FindingMatrixRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = FindingMatrixSerializer
    queryset = FindingMatrix.objects.all()

class GEOCODESCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = GEOCODESerializer
    queryset = GEOCODES.objects.all()

class GEOCODESListViewSet(BaseView, generics.ListAPIView):
    serializer_class = GEOCODESerializer
    queryset = GEOCODES.objects.all()

class GEOCODESRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = GEOCODESerializer
    queryset = GEOCODES.objects.all()


class whoisCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = Whois_serializers
    queryset = whois.objects.all()

class whoisListViewSet(BaseView, generics.ListAPIView):
    serializer_class = Whois_serializers
    queryset = whois.objects.all()

class whoisRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = Whois_serializers
    queryset = whois.objects.all()

class EGOAgentListCreateView(generics.ListCreateAPIView):
    queryset = EGOAgent.objects.all()
    serializer_class = EGOAgentSerializer

class EGOAgentRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = EGOAgent.objects.all()
    serializer_class = EGOAgentSerializer