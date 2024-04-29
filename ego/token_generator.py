from django.contrib.auth.tokens import PasswordResetTokenGenerator

class InvitationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, invitation, timestamp):
        return str(invitation.pk) + str(timestamp) + str(invitation.last_login)

invitation_token_generator = InvitationTokenGenerator()
