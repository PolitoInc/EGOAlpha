from django import template

register = template.Library()

@register.filter
def get_type(value):
    return type(value).__name__

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

@register.filter
def in_list(value, list_string):
    return str(value) in list_string.split(',')


