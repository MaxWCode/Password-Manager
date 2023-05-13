from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from datetime import datetime
from . import forms
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from cryptography.fernet import Fernet
from .models import Info
import pyperclip
import os


# ENCRYPTION FUNCTIONS
key = os.environ.get('ENCRYPTION_KEY').encode()
if not key:
    raise ValueError("Encryption key is not set or is invalid")
FERNET = Fernet(key)
# ENCRYPTION FUNCTIONS

# Create your views here.
def index(request):
    return render(request, "vault/index.html")

@login_required(login_url='/login')
def vault(request):
    passwords = Info.objects.filter(user_account=request.user.id)
    if request.method == 'POST':
        form = forms.InfoForm(request.POST)
        if form.is_valid():
            website_name = form.cleaned_data['website_name']
            username = form.cleaned_data['username']
            password = form.cleaned_data['website_password']
            encrypted_password = FERNET.encrypt(password.encode())
            info = Info(user_account=request.user, website_name=website_name, username=username, website_password=encrypted_password)
            info.save()
            return HttpResponseRedirect(reverse('vault'))
    else:
        form = forms.InfoForm()
    return render(request, "vault/vault.html", {
        "passwords": passwords,
        "infoForm": form,
    })

    


def login_view(request):
    if request.method == "POST":
        form = forms.LoginForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            user = authenticate(request, username=username, password=password)

            if user is not None:
                # Authenticate the user and log them in
                login(request, user)
                return HttpResponseRedirect(reverse('home'))
            else:
                # Display an error message if authentication fails
                messages.error(request, "Incorrect username or password", extra_tags='login_error')
        
    else:
        form = forms.LoginForm()

    return render(request, "vault/login.html", {'form': form})


def signup(request):
    if request.method == "POST":
        form = forms.SignupForm(request.POST)

        if form.is_valid():
            username=form.cleaned_data['username']
            password=form.cleaned_data['password']
            user = User.objects.create_user(username=username, password=password)
            user.save()
            messages.success(request, "Account Successfully Created!", extra_tags='login_error')
            return HttpResponseRedirect(reverse('login'))
        
    else:
        form = forms.SignupForm()

    return render(request, "vault/signup.html", {
        'form': form
    })

def logout_view(request):
    logout(request)
    messages.success(request, "Successfully Logged Out")
    return redirect(reverse('home') + '?messages=' + messages.get_messages(request).as_json())

@login_required(login_url='/login')
def copy_password(request, password_id):
    decrypted_password = ''
    #Get Specific User
    try:
        password = Info.objects.get(pk=password_id, user_account=request.user)
        print(password)
        print(key)
        print(password.website_password, "<---<---<")
    except Info.DoesNotExist:
        messages.error(request, 'Password not found.')
        return redirect('vault')
        
    try:
        decrypted_password = FERNET.decrypt(password.website_password.encode()).decode()
        print(" L "+decrypted_password + "L", "THIS IS THE DECRUPTED PASSWORD")
    except Exception as error:
        messages.error(request, 'Invalid Token', extra_tags="vault")
        print(messages.error(request, 'Invalid Token', extra_tags="vault"))
        print(" L "+decrypted_password + "L", "THIS IS THE DECRUPTED PASSWORD")
        return redirect('vault')

    # pyperclip.copy(decrypted_password)
    print(decrypted_password)
    messages.success(request, 'Password copied to clipboard.')
    return redirect('vault')
