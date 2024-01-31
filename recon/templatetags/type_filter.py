from django import template

register = template.Library()

@register.filter
def get_type(value):
    return type(value).__name__

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)