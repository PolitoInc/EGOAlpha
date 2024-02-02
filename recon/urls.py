# recon/urls.py
from django.urls import path, re_path, include
from django.conf.urls.static import static
from django.contrib import admin 
from rest_framework.urlpatterns import format_suffix_patterns
from recon.forms import *
from recon.views import *
from django.contrib.auth import views as auth_views
from rest_framework.routers import DefaultRouter



app_name = 'web'
urlpatterns = [
    path('', auth_views.LoginView.as_view(), name='login'),
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('admin/', admin.site.urls),
    path('Customers/', CustomerVIEW, name='CustomerVIEW'),
    path('Customers/Create',CustomersCreate, name='CustomersCreate'),
    path('Customers/<pk>/', CustomerPk, name='CustomerPk'),
    path('Customers/<pk>/delete', CustomersDelete, name='CustomersDelete'),
    path('Record/<pk>/delete', RecordDelete, name='RecordDelete'),
    path('EgoControlBoard/', EgoControlBoard, name='EgoControlBoard'),
    path('EgoControlBoard/<pk>/', EgoControlBoardpk, name='EgoControlBoardpk'),
    path('EgoControlBoard/<uuid:pk>/delete/', EgoControlBoardDelete, name='EgoControlBoardDelete'),
    path('EgoControlBoard/create', EgoControlCreate, name='EgoControlCreate'),
    path('GnawControlBoard/', GnawControlBoards, name='GnawControlBoards'),
    path('GnawControlBoard/create', GnawControlBoardsCreate, name='GnawControlBoardsCreate'),
    path('GnawControlBoard/<pk>', GnawControlBoardsPK, name='GnawControlBoardsPK'),
    path('VulnBoards/', VulnBoards, name='VulnBoards'),
    path('VulnBoards/search/', VulnBoards, name='VulnBoards'),
    path('VulnsBoardChart/', VulnsBoardChart, name='VulnsBoardChart'),
    path('VulnsBoardChartPK/<pk>', VulnsBoardChartPK, name='VulnsBoardChartPK'),
    path('AliveOrDeadChartPk/<pk>', AliveOrDeadChartPk, name='AliveOrDeadChartPk'),
    path('PortChartPk/<pk>', PortChartPk, name='PortChartPk'),
    path('Interconneciton/<pk>', Interconneciton, name='Interconneciton'),
    path('VulnBoard/create/', VulnBoardCreate, name='VulnBoardCreate'),
    path('VulnBoard/create/<pk>', VulnBoardCreatePK, name='VulnBoardCreatePK'),
    path('VulnBoard/create/delete/<pk>', VulnBoardDeletePK, name='VulnBoardDeletePK'),
    path('VulnBoard/VulnCard/create', VulnCardCreate, name='VulnCardCreate'),
    path('VulnBoard/VulnCard/<pk>', VulnCardPK, name='VulnCardPK'),
    path('WordList/', WordClass, name='WordClass'),
    path('WordList/fileUpload', fileUpload, name='fileUpload'),
    path('WordList/create', WordClassCreate, name='WordClassCreate'),
    path('VulnBoard/submited/<pk>', VulnSubmitted, name='VulnSubmitted'),

    path('api/login', LoginApiView.as_view()),

    path('api/csv_version/', csv_versionListViewSet.as_view()),
    path('api/csv_version/<pk>/', csv_versionViewSet.as_view()),
    path('api/csv_version/create/', csv_versionCreateViewSet.as_view()),
    path('api/GnawControl/', GnawControlCreateViewSet.as_view()),
    path('api/GnawControl/<pk>', GnawControlViewSet.as_view()),
    path('api/EgoControls/', EgoControlListViewSet.as_view()),
    path('api/EgoControls/create', EgoControlCreateViewSet.as_view(), name='egocreate'),
    path('api/EgoControls/<pk>', EgoControlViewSet.as_view()),
    path('api/records/', RecordsListViewSet.as_view()),
    path('api/records/<pk>', RecordsViewSet.as_view()),
    path('api/TotalRecords/<pk>', TotalRecordsViewSet.as_view()),
    path('api/records/create/', RecordsCreateViewSet.as_view()),
    path('api/DNS/', DNSQueryRecordsListViewSet.as_view()),
    path('api/DNS/<pk>', DNSQueryRecordsViewSet.as_view()),
    path('api/DNSAuth/', DNSAuthRecordsListViewSet.as_view()),
    path('api/DNSAuth/<pk>', DNSAuthRecordsViewSet.as_view()),
    path('api/Nuclei/', NucleiRecordsListViewSet.as_view()),
    path('api/Nuclei/<pk>', NucleiRecordsViewSet.as_view()),
    path('api/Certificate/', CertificateRecordsListViewSet.as_view()),
    path('api/Certificate/create/', CertificateRecordsCreateViewSet.as_view()),
    path('api/Certificate/<pk>', CertificateRecordsViewSet.as_view()),
    path('api/create/', CustomersCreateViewSet.as_view()),
    path('api/create/<pk>', CustomersRetrieveLimitedViewSet.as_view()),
    path('api/customers/', CustomersListViewSet.as_view()),
    path('api/customers/<pk>', CustomersViewSet.as_view()),
    path('api/customers/Credentials', CredentialsListViewSet.as_view()),
    path('api/customers/Credentials/<credential_pk>', CredentialsViewSet.as_view()),
    path('api/WordList/', WordListListViewSet.as_view()),
    path('api/WordList/create', WordListCreateViewSet.as_view()),
    path('api/WordList/createSuperList', wordCreation, name='createSuperList'),
    path('api/WordList/<pk>', WordListUpdateViewSet.as_view()),
    path('api/WordClass/', WordListGroupListViewSet.as_view()),
    path('api/WordClass/create/', WordListGroupCreateViewSet.as_view()),
    path('api/WordClass/<pk>', WordListGroupUpdateViewSet.as_view()),
    path('api/DirectoryWords/', DirectoryListViewSet.as_view()),
    path('api/DirectoryWords/<pk>', DirectoryViewSet.as_view()),
    path('api/Key/create/', apiCreateViewSet.as_view()),
    path('api/Key/List', apiListViewSet.as_view()),
    path('api/Key/Retrieve/<pk>', apiRetrieveViewSet.as_view()),
    path('api/Provider/create/', apiproviderCreateViewSet.as_view()),
    path('api/Provider/List', apiproviderListViewSet.as_view()),
    path('api/Provider/Retrieve/<pk>', apiproviderRetrieveViewSet.as_view()),
    path('api/Templates/', TemplatesListViewSet.as_view()),
    path('api/Templates/<pk>', TemplatesViewSet.as_view()),    
    path('api/Templates/create/', TemplatesCreateViewSet.as_view()),
    path('api/Nmap/', NmapListViewSet.as_view()),
    path('api/Nmap/create', NmapCreateViewSet.as_view()),
    path('api/Nmap/<pk>', NmapViewSet.as_view()),
    path('api/PythonNuclei/', PythonNucleiListViewSet.as_view()),
    path('api/PythonNuclei/<pk>', PythonNucleiViewSet.as_view()),
    path('api/VulnCard/', vulncardListCreateViewSet.as_view()),
    path('api/VulnCard/<pk>', vulncardRetrieveViewSet.as_view()),
    path('api/TotalFoundVuln/create/', TotalFoundVulnCreateViewSet.as_view()),
    path('api/TotalFoundVuln/', TotalFoundVulnListViewSet.as_view()),
    path('api/TotalFoundVuln/<pk>', TotalFoundVulnViewSet.as_view()),
    path('api/FoundVuln/create/', FoundVulnCreateViewSet.as_view()),
    path('api/FoundVuln/', FoundVulnListViewSet.as_view()),
    path('api/FoundVuln/<pk>', FoundVulnViewSet.as_view()),
    path('api/FoundVulnDetail/create/', FoundVulnDetailCreateViewSet.as_view()),
    path('api/FoundVulnDetail/', FoundVulnDetailListViewSet.as_view()),
    path('api/FoundVulnDetail/<pk>', FoundVulnDetailViewSet.as_view()),
    path('api/RequestMetaData/create/', RequestMetaDataCreateViewSet.as_view()),
    path('api/RequestMetaData/', RequestMetaDataListViewSet.as_view()),
    path('api/RequestMetaData/<pk>', RequestMetaDataViewSet.as_view()),
    path('api/GEOCODES/create/', GEOCODESCreateViewSet.as_view()),
    path('api/GEOCODES/', GEOCODESListViewSet.as_view()),
    path('api/GEOCODES/<pk>', GEOCODESRetrieveViewSet.as_view()),
    path('api/whois/create', whoisCreateViewSet.as_view()),
    path('api/whois/', whoisListViewSet.as_view()),
    path('api/whois/<pk>', whoisRetrieveViewSet.as_view()),
    ]


urlpatterns = format_suffix_patterns(urlpatterns)
 