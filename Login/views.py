
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from Authentication import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_str, force_bytes
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode 
from . tokens import generate_token
from django.core.mail import EmailMessage


# Create your views here.
def home(request):
    return render(request, 'home.html')
def signup(request):
    if request.method ==  'POST':
        username = request.POST['username']
        password = request.POST['pass1']
        email = request.POST['email']
        password2 = request.POST['pass2']
        if password != password2:
            messages.error(request, 'Passwords do not match')
            return redirect('signup')
        if User.objects.filter(username=username, email=email).exists():
            messages.error(request, 'User already exists')
            return redirect('signup')
        user = User.objects.create_user(username, email, password)
        subject = 'Django Authentication'
        message = 'Welcome to Django Authentication'
        from_email = settings.EMAIL_HOST_USER
        to_list = [user.email]
        send_mail(subject, message, from_email, to_list, fail_silently=False)
        messages.success(request, 'Check your email for activation link')
        user.is_active = False
        user.save()

        #Email Confirmation
        current_site = get_current_site(request)
        subject2 = "Confirm your account and get activated"
        message2 = render_to_string('confirmation.html', {   'name': user.username,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })
        email = EmailMessage(
            subject2, message2, settings.EMAIL_HOST_USER, [user.email],
        )
        email.fail_silently = False
        email.send()
        return redirect('signin')



    return render(request,'signup.html')
def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']
        user = authenticate(username=username, password=pass1)
        if user is not None:
            login(request, user)
            fname = user.username
            return render(request, 'home.html', {"fname":fname})
        else:
            messages.error(request, 'Invalid username or password')
            return redirect('signin')
    return render(request,'signin.html')

def signout(request):
    # Without this function the user.is_authenticated will malfunction to always have a valid state = "True"
    messages.success(request, 'You have logged out successfully')
    logout(request)
    return redirect('home')

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()
        fname=user.username
        login(request, user)
        messages.success(request, 'Account activated successfully')
        return render(request, 'home.html', {"fname":fname})
    else:
        messages.error(request, 'Activation link is invalid or has expired')
        return redirect('home')
