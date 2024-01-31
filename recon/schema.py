from django_elasticsearch_dsl import Document , Index, fields
from elasticsearch_dsl import analyzer

from recon.models import CustomerRecords

# Name of the Elasticsearch index
Customer_Index = Index('CustomerRecords')
# See Elasticsearch Indices API reference for available settings
Customer_Index.settings(
    number_of_shards=1,
    number_of_replicas=1
)

@Customer_Index.doc_type
class CustomerDocument(Document):
    """Customer Elasticsearch document."""

    domain = fields.TextField(
        fields={
            'raw': fields.TextField(
                analyzer='keyword'
            )
        }
    )
    subDomain = fields.TextField(
        attr='id',
        fields={
            'raw': fields.TextField(
                analyzer='keyword'
            )
        }
    )
    alive = fields.TextField(
        fields={
            'raw': fields.TextField(
                analyzer='keyword'
            )
        }
    )
    dateCreated = fields.TextField(
        fields={
            'raw': fields.TextField(
                analyzer='keyword'
            )
        }
    )
    CertBool = fields.TextField(
        fields={
            'raw': fields.TextField(
                analyzer='keyword'
            )
        }
    )
    Certificate = fields.TextField(
        fields={
            'raw': fields.TextField(
                analyzer='keyword'
            )
        }
    )
    OpenPorts = fields.TextField(
        fields={
            'raw': fields.TextField(
                analyzer='keyword'
            )
        }
    )
    DNSQuery = fields.TextField(
            fields={
            'raw': fields.TextField(
                analyzer='keyword'
            )
        }
    )
    DNSAuthority = fields.TextField(
            fields={
            'raw': fields.TextField(
                analyzer='keyword'
            )
        }
    )

    class Meta(object):
        """Meta options."""

        model = CustomerRecords  # The model associate with this DocType

from django_elasticsearch_dsl_drf.filter_backends import (
    FilteringFilterBackend,
    OrderingFilterBackend,
    SearchFilterBackend,
)
from django_elasticsearch_dsl_drf.viewsets import BaseDocumentViewSet
# Example app models
from recon.schema.schema import CustomerDocument
from recon.serializers import UpdateCustomerSerializer

class PublisherDocumentView(BaseDocumentViewSet):
    """The PublisherDocument view."""

    document = PublisherDocument
    serializer_class = PublisherDocumentSerializer
    lookup_field = 'id'
    filter_backends = [
        FilteringFilterBackend,
        OrderingFilterBackend,
        SearchFilterBackend,
    ]
    # Define search fields
    search_fields = (
        'domain',
        'subDomain',
        'alive',
        'dateCreated',
        'CertBool',
        'Certificate',
        'OpenPorts',
        'DNSQuery',
        'DNSAuthority'
    )
    # Define filtering fields
    filter_fields = {
        'domain': 'domain.raw',
        'subDomain': 'subDomain.raw',
        'Certificate': 'Certificate.raw',
        'OpenPorts': 'OpenPorts.raw',
        'DNSQuery': 'DNSQuery.raw',
        'DNSAuthority': 'DNSAuthority.raw'
    }
    # Define ordering fields
    ordering_fields = {
        'domain': None,
        'subDomain': None,
        'alive': None,
        'dateCreated': None,
        'CertBool': None,
    }
    # Specify default ordering
    ordering = ('id', 'name',)