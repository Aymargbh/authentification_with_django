from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import CreateView, FormView
from django.contrib.auth.views import LoginView, LogoutView as AuthLogoutView
from .forms import *
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.views.generic import TemplateView
from django.contrib import messages
from django.views import View
from django.core.mail import send_mail
from django.conf import settings
import secrets

User = get_user_model()

class SignUpView(CreateView):
    model = CustomUser
    form_class = CustomUserCreationForm
    template_name = 'accounts/registration/signup.html'
    success_url = reverse_lazy('confirmation_sent')

    def form_valid(self, form):
        response = super().form_valid(form)
        # Passez la request à la méthode
        self.object.send_confirmation_email(self.request) 
        return response

class CustomLoginView(LoginView):
    form_class = CustomUserLoginForm
    template_name = 'accounts/registration/login.html'
    
    def get_success_url(self):
        return reverse_lazy('acceuil')

class CustomLogoutView(AuthLogoutView):
    next_page = reverse_lazy('acceuil')

class PasswordChangeView(FormView):
    template_name = 'accounts/registration/password_change.html'
    form_class = CustomPasswordChangeForm
    success_url = reverse_lazy('password_change_done')

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)

class PasswordResetView(FormView):
    template_name = 'accounts/registration/password_reset.html'
    form_class = CustomPasswordResetForm
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        email = form.cleaned_data['email']
        users = User.objects.filter(email__iexact=email)
        for user in users:
            context = {
                'email': user.email,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
                'protocol': 'https' if self.request.is_secure() else 'http',
                'domain': self.request.get_host()
            }
            send_mail(
                "Réinitialisation de mot de passe",
                f"Utilisez ce lien pour reset: {context['protocol']}://{context['domain']}/reset/{context['uid']}/{context['token']}/",
                None,  # Utilisera DEFAULT_FROM_EMAIL
                [user.email]
            )
        return super().form_valid(form)

class PasswordResetConfirmView(FormView):
    """
    Vue personnalisée pour la confirmation de réinitialisation du mot de passe
    """
    template_name = 'accounts/registration/password_reset_confirm.html'
    form_class = CustomSetPasswordForm
    success_url = reverse_lazy('password_reset_complete')

    def dispatch(self, request, *args, **kwargs):
        """
        Vérifie la validité du token avant toute action
        """
        # Récupération de l'utilisateur
        self.user = self.get_user(kwargs['uidb64'])
        
        # Vérification du token
        if not self.valid_link():
            return redirect('password_reset_invalid')
            
        return super().dispatch(request, *args, **kwargs)

    def get_user(self, uidb64):
        """
        Décode l'UID et retourne l'utilisateur correspondant
        """
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            return User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return None

    def valid_link(self):
        """
        Vérifie que le lien est valide
        """
        return (self.user is not None and 
                self.user.is_active and
                default_token_generator.check_token(self.user, self.kwargs['token']))

    def get_form_kwargs(self):
        """
        Injecte l'utilisateur dans le formulaire
        """
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def form_valid(self, form):
        """
        Traitement après validation du formulaire
        """
        form.save()
        
        # Optionnel : Ajouter un message de succès
        from django.contrib import messages
        messages.success(self.request, 'Votre mot de passe a été modifié avec succès.')
        
        return super().form_valid(form)

def password_change_done(request):
    return render(request, 'accounts/registration/password_change_done.html')

def password_reset_done(request):
    return render(request, 'accounts/registration/password_reset_done.html')

def password_reset_complete(request):
    return render(request, 'accounts/registration/password_reset_complete.html')

class CustomPasswordResetConfirmView(FormView):
    template_name = 'accounts/registration/password_reset_confirm.html'
    form_class = CustomSetPasswordForm
    success_url = reverse_lazy('password_reset_complete')

    def dispatch(self, request, *args, **kwargs):
        """
        Vérifie le token et stocke l'utilisateur avant toute autre méthode
        """
        # Décode l'UID
        try:
            uid = urlsafe_base64_decode(kwargs['uidb64']).decode()
            self.user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            self.user = None

        # Vérifie le token
        if not self.is_valid_token(kwargs['token']):
            return render(request, 'accounts/registration/password_reset_invalid.html')

        return super().dispatch(request, *args, **kwargs)

    def is_valid_token(self, token):
        """
        Vérifie que l'utilisateur existe et que le token est valide
        """
        return (self.user is not None and 
                self.user.is_active and
                default_token_generator.check_token(self.user, token))

    def get_form_kwargs(self):
        """
        Injecte l'utilisateur dans le formulaire
        """
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.user  # self.user est maintenant toujours défini
        return kwargs

    def form_valid(self, form):
        """
        Traitement après validation réussie
        """
        form.save()
        return super().form_valid(form)

class ConfirmEmailView(View):
    def get(self, request, token):
        try:
            user = get_object_or_404(CustomUser, confirmation_token=token)
            
            if user.email_confirmed:
                messages.info(request, "Votre email a déjà été confirmé.")
                return render(request, 'accounts/email_already_confirmed.html')
                
            user.email_confirmed = True
            user.confirmation_token = ""
            user.save()
            
            # On utilise render au lieu de redirect pour afficher une page dédiée
            return render(request, 'accounts/email_confirmation_success.html')
            
        except Exception as e:
            return render(request, 'accounts/email_confirmation_invalid.html', 
                         {'token': token})

class ConfirmationSentView(TemplateView):
    template_name = 'accounts/confirmation_sent.html'


class ConfirmEmailView(View):
    def get(self, request, token):
        try:
            user = get_object_or_404(CustomUser, confirmation_token=token)
            user.email_confirmed = True
            user.confirmation_token = ""
            user.save()
            return render(request, 'accounts/confirmation_success.html')
        except Exception as e:
            return render(request, 'accounts/confirmation_invalid.html', {'token': token})

class ResendConfirmationEmailView(View):
    def get(self, request):
        return render(request, 'accounts/resend_confirmation.html')
    
    def post(self, request):
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email, email_confirmed=False)
            token = secrets.token_urlsafe(32)
            user.confirmation_token = token
            user.save()
            
            # Envoyer l'email
            confirmation_link = request.build_absolute_uri(
                f'/confirm-email/{token}/'
            )
            send_mail(
                'Confirmation de votre email',
                f'Cliquez sur ce lien pour confirmer votre email: {confirmation_link}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            
            messages.success(request, "Un nouveau lien de confirmation a été envoyé à votre adresse email.")
            return redirect('resend_confirmation')
            
        except CustomUser.DoesNotExist:
            messages.error(request, "Aucun compte non confirmé trouvé avec cette adresse email.")
            return redirect('resend_confirmation')