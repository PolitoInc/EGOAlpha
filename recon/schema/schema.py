from django_elasticsearch_dsl import DocType, Index, fields
from elasticsearch_dsl import analyzer

from recon.models import CustomerRecords

# Name of the Elasticsearch index
PUBLISHER_INDEX = Index('CustomerRecords')
# See Elasticsearch Indices API reference for available settings
PUBLISHER_INDEX.settings(
    number_of_shards=1,
    number_of_replicas=1
)


@PUBLISHER_INDEX.doc_type
class PublisherDocument(DocType):
    """Publisher Elasticsearch document."""

    domain = fields.StringField(
        fields={
            'raw': fields.StringField(
                analyzer='keyword'
            )
        }
    )
    subDomain = fields.StringField(
        attr='id',
        fields={
            'raw': fields.StringField(
                analyzer='keyword'
            )
        }
    )
    alive = fields.StringField(
        fields={
            'raw': fields.StringField(
                analyzer='keyword'
            )
        }
    )
    dateCreated = fields.StringField(
        fields={
            'raw': fields.StringField(
                analyzer='keyword'
            )
        }
    )
    CertBool = fields.StringField(
        fields={
            'raw': fields.StringField(
                analyzer='keyword'
            )
        }
    )
    Certificate = fields.StringField(
        fields={
            'raw': fields.StringField(
                analyzer='keyword'
            )
        }
    )
    OpenPorts = fields.StringField(
        fields={
            'raw': fields.StringField(
                analyzer='keyword'
            )
        }
    )
    DNSQuery = fields.StringField(
            fields={
            'raw': fields.StringField(
                analyzer='keyword'
            )
        }
    )
    DNSAuthority = fields.StringField(
            fields={
            'raw': fields.StringField(
                analyzer='keyword'
            )
        }
    )

    class Meta(object):
        """Meta options."""

        model = CustomerRecords  # The model associate with this DocType