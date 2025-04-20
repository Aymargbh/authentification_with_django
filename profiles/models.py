from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    phone = models.CharField(max_length=20, blank=True)
    bio = models.TextField(blank=True)
    profile_picture = models.ImageField(
        upload_to='profile_pics/',  # Dossier où les images seront stockées
        blank=True,                 # Optionnel (l'utilisateur peut ne pas uploader de photo)
        null=True,                  # Permet NULL en base de données
        default='profile_pics/default.png',  # Image par défaut (optionnel)
    )

    def __str__(self):
        return f"{self.email} ({self.first_name})"