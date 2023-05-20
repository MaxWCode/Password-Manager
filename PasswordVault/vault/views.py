from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from datetime import datetime
from . import forms
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Info, Profile
import pyperclip
import os



# ENCRYPTION FUNCTIONS
key = settings.ENCRYPTION_KEY.encode('utf-8')
if not key:
    raise ValueError("Encryption key is not set or is invalid")
FERNET = Fernet(key)

# Create your views here.
def index(request):
    return render(request, "vault/index.html")

@login_required(login_url='/login')
def account(request):
    if request.method == 'POST':
        master_password = request.POST.get('master_password')
        re_master_password = request.POST.get('re_master_password')
        if master_password == re_master_password:
            profile = Profile.objects.get(user=request.user)

            #Encrypt Password
            encrypted_masterPassword = FERNET.encrypt(master_password.encode('utf-8'))
            profile.master_password = encrypted_masterPassword
            profile.master_password_set = True
            profile.save()
            messages.success(request, "Master Password Successfully Created!", extra_tags='account_message')
            return redirect('account')
        else:
            messages.error(request, "Passwords Don't Match", extra_tags='account_message')
            return redirect('account')
    return render(request, "vault/account.html")

@login_required(login_url='/login')
def vault_unlock(request):
    passwords = Info.objects.filter(user_account=request.user.id)
    if request.method == 'POST':
        master_password = request.POST.get('master_password')
        print(master_password)
        decrypted_password = ''
        
        #Get Specific User
        try:
            profile = Profile.objects.get(user=request.user)
            profile_master_password = profile.master_password
            print(profile_master_password)
        except Profile.DoesNotExist:
            messages.error(request, 'Profile not found')
            return redirect('vault')
        try:
            decrypted_password = FERNET.decrypt(eval(profile_master_password)).decode()
            print(decrypted_password)
        except InvalidToken as error:
            messages.error(request, "Invalid Token", extra_tags='vault')
            return redirect('vault')

    if decrypted_password == master_password:
        #display the graph
        messages.success(request, "Unlocked", extra_tags='vault')
        form = forms.InfoForm()
        context = {
        'passwords': passwords,
        'infoForm' : form
        }
        return render(request, 'vault/vault.html', context)
    else:
        messages.error(request, "Password doesn't match", extra_tags='vault')
                    
    return redirect('vault')
        
        



@login_required(login_url='/login')
def vault(request):
    if request.method == 'POST':
        form = forms.InfoForm(request.POST)
        if form.is_valid():
            website_name = form.cleaned_data['website_name']
            username = form.cleaned_data['username']
            password = form.cleaned_data['website_password']
            encrypted_password = FERNET.encrypt(password.encode('utf-8'))
            info = Info(user_account=request.user, website_name=website_name, username=username, website_password=encrypted_password)
            info.save()
            messages.success(request, "Added to the vault", extra_tags='vault')
            return HttpResponseRedirect(reverse('vault'))
    else:
        form = forms.InfoForm()
    return render(request, "vault/vault.html", {
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
            profile = Profile(user=user)
            profile.save()
            messages.success(request, "Account Successfully Created!", extra_tags='login_error')
            return HttpResponseRedirect(reverse('login'))
        
    else:
        form = forms.SignupForm()

    return render(request, "vault/signup.html", {
        'form': form
    })

def logout_view(request):
    logout(request)
    messages.success(request, "Successfully Logged Out", )
    return redirect('home')

@login_required(login_url='/login')
def copy_password(request, password_id):
    decrypted_password = ''
    #Get Specific User
    try:
        user = Info.objects.get(pk=password_id, user_account=request.user)
    except Info.DoesNotExist:
        messages.error(request, 'Password not found')
        return redirect('vault')
        
    try:
        decrypted_password = FERNET.decrypt(eval(user.website_password))
        pyperclip.copy(decrypted_password.decode())
        messages.success(request, 'Password copied to clipboard')
    except InvalidToken as error:
        messages.error(request, 'Invalid Token', extra_tags="vault")
        return redirect('vault')
        
    return redirect('vault')


@login_required(login_url='/login')
def delete_password(request, password_id):
    try:
        user = get_object_or_404(Info, pk=password_id, user_account=request.user)
        user.delete()
        messages.success(request, 'Password deleted successfully')
    except Info.DoesNotExist:
        messages.error(request, 'Password not found.')
    return redirect('vault')
