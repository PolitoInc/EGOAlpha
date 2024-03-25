from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, UserProfile, UserGroup
from django.db import IntegrityError

@receiver(post_save, sender=User)
def create_user_group(sender, instance, created, **kwargs):
    if created:
        try:
            user_profile, created = UserProfile.objects.get_or_create(user=instance, email=instance.email)
            user_group = UserGroup.objects.create()
            user_group.users.add(user_profile)
        except IntegrityError:
            pass  # UserProfile with this email already exists, no need to create a new one
