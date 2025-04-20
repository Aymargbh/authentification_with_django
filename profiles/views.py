from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView, FormView
from django.contrib.auth.views import LoginView, LogoutView as AuthLogoutView
from .forms import *
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model

User = get_user_model()

class SignUpView(CreateView):
    form_class = CustomUserCreationForm
    template_name = "accounts/registration/signup.html"
    success_url = reverse_lazy("login")

    def form_valid(self, form):
        user = form.save(commit=False)
        user.save()
        return redirect(self.success_url)

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