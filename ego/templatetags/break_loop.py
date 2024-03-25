from django import template

register = template.Library()

@register.filter
def get_first(value):
    for sub_value in value:
        for sub_keys, sub_values in sub_value.items():
            if sub_keys in ["Nmaps_record", "GEOCODES", "Certificates_record", "Templates_record", "DNSQuery_record", "DNSAuthority_record"] and sub_values:
                if isinstance(sub_values, list) and sub_values and isinstance(sub_values[0], dict):
                    return sub_values[0].keys()
    return []
