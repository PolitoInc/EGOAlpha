from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import EGOAgent

class BearerTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        bearer_token = auth_header[7:]  # Extract the token part
        ego_agents = EGOAgent.objects.filter(bearer_token=bearer_token)
        if not ego_agents.exists():
            raise AuthenticationFailed('No such agent')

        ego_agent = ego_agents.first() # Get the first matching agent
        return (ego_agent, None)