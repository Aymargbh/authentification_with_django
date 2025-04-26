from django.urls import path
from .views import *
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('confirmation-sent/',
         ConfirmationSentView.as_view(), 
         name='confirmation_sent'),
    path('resend-confirmation/', ResendConfirmationEmailView.as_view(), name='resend_confirmation'),
    path('confirm-email/<str:token>/', ConfirmEmailView.as_view(), name='confirm_email'),
    path('reactivate-account/<str:token>/', ReactivateAccountView.as_view(), name='reactivate_account'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    path('password_change/', PasswordChangeView.as_view(), name='password_change'),
    path('password_change/done/', password_change_done, name='password_change_done'),
    path('password_reset/',
        auth_views.PasswordResetView.as_view(
            template_name='accounts/registration/password_reset.html',
            email_template_name='accounts/registration/password_reset_email.txt',
        ),
        name='password_reset'),
    
    path('password_reset/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name='accounts/registration/password_reset_done.html'
        ),
        name='password_reset_done'),
    
    path('reset/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    
    path('reset/done/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='accounts/registration/password_reset_complete.html'
        ),
        name='password_reset_complete'),
]
