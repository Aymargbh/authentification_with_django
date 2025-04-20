from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings

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
    confirmation_token = models.CharField(max_length=64, blank=True)

    def __str__(self):
        return f"{self.email} ({self.first_name})"
    
    def send_confirmation_email(self, request):
        self.confirmation_token = get_random_string(64)
        self.save()
        
        # Utilisez request.build_absolute_uri pour générer l'URL complète
        confirmation_url = request.build_absolute_uri(
            f'/accounts/confirm-email/{self.confirmation_token}/'
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