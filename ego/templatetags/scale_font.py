# your_app/templatetags/scale_font.py

from django import template
import math

register = template.Library()

@register.filter
def scale_font(value):
    scaled_value = 16 + math.log(value + 1) * 10  # Adjust the base and multiplier as needed
    return min(max(scaled_value, 12), 20)
