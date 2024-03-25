from django.apps import AppConfig


class EgoConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ego'
    
    def ready(self):
        import ego.signals  # noqa