import secrets
from django.core.mail import send_mail
from django.conf import settings

def generate_confirmation_token():
    return secrets.token_urlsafe(32)  # Génère un token sécurisé de 32 bytes

def send_confirmation_email(user, request):
    subject = "Confirmez votre email"
    message = f"""
    Bonjour {user.username},
    
    Cliquez sur ce lien pour confirmer votre email:
    {request.build_absolute_uri(f'/accounts/confirm-email/{user.confirmation_token}/')}
    
    Ce lien expire dans 48 heures.
    """
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )