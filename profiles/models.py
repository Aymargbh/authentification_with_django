from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import secrets

class CustomUser(AbstractUser):
    phone = models.CharField(max_length=20, blank=True)
    bio = models.TextField(blank=True)
    profile_picture = models.ImageField(
        upload_to='profile_pics/',  # Dossier où les images seront stockées
        blank=True,                 # Optionnel (l'utilisateur peut ne pas uploader de photo)
        null=True,                  # Permet NULL en base de données
        default='profile_pics/default.png',  # Image par défaut (optionnel)
    )
    email_confirmed = models.BooleanField(default=False)
    confirmation_token = models.CharField(max_length=64, blank=True, null=True, unique=True)
    confirmation_token_created_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def generate_new_confirmation_token(self):
        self.confirmation_token = secrets.token_urlsafe(32)
        self.confirmation_token_created_at = timezone.now()
        self.save()
        return self.confirmation_token

    def is_confirmation_token_expired(self):
        if not self.confirmation_token_created_at:
            return True
        expire_days = getattr(settings, 'ACCOUNT_CONFIRMATION_EXPIRE_DAYS', 2)
        return timezone.now() > self.confirmation_token_created_at + timedelta(days=expire_days)
    
    def send_confirmation_email(self, request):
        token = self.generate_new_confirmation_token()
        confirmation_url = request.build_absolute_uri(
            f'/accounts/confirm-email/{token}/'
        )
        
        subject = "Confirmation de votre compte"
        html_message = render_to_string('accounts/email_confirmation.txt', {
            'user': self,
            'confirmation_url': confirmation_url,
        })
        
        send_mail(
            subject,
            strip_tags(html_message),
            settings.DEFAULT_FROM_EMAIL,
            [self.email],
            html_message=html_message
        )