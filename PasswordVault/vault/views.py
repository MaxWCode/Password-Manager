from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from datetime import datetime
from . import forms
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Info, Profile
import pyperclip
import os
import re

#add status codes gto

# ENCRYPTION FUNCTIONS
key = settings.ENCRYPTION_KEY.encode('utf-8')
if not key:
    raise ValueError("Encryption key is not set or is invalid")
FERNET = Fernet(key)

# Create your views here.
def index(request):
    return render(request, "vault/index.html")


# ...
def reset_master_password(request):
    if request.method == 'POST':
        resetMasterPasswordForm = forms.ResetMasterPasswordForm(request.POST)
        if resetMasterPasswordForm.is_valid():
            password = resetMasterPasswordForm.cleaned_data.get('password')
            new_password = resetMasterPasswordForm.cleaned_data.get('new_password')
            re_new_password = resetMasterPasswordForm.cleaned_data.get('re_new_password')

            profile = Profile.objects.get(user=request.user)
            decrypted_master_password = FERNET.decrypt(eval(profile.master_password)).decode()

            if str(password) != str(decrypted_master_password):
                messages.error(request, "Invalid Original Password", extra_tags='account_message')
                return redirect('account')
            else:
                # Check if passwords match
                if new_password == re_new_password:
                    # Password validations in the view
                    if len(new_password) < 8:
                        messages.error(request, "Password should be at least 8 characters long", extra_tags='account_message')
                    elif not re.search(r'\d', new_password):
                        messages.error(request, "Password should contain at least one digit", extra_tags='account_message')
                    elif not re.search(r'[A-Z]', new_password):
                        messages.error(request, "Password should contain at least one uppercase letter", extra_tags='account_message')
                    elif not re.search(r'[a-z]', new_password):
                        messages.error(request, "Password should contain at least one lowercase letter", extra_tags='account_message')
                    elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
                        messages.error(request, "Password should contain at least one special character", extra_tags='account_message')
                    else:
                        # Encrypt Password
                        encrypted_masterPassword = FERNET.encrypt(new_password.encode('utf-8'))
                        profile.master_password = encrypted_masterPassword
                        profile.save()

                        messages.success(request, "Master Password Successfully Reset!", extra_tags='account_message')
                        return redirect('account')
                else:
                    messages.error(request, "Passwords Don't Match", extra_tags='account_message')
                    return redirect('account')
        else:
            messages.error(request, "Invalid Form", extra_tags='account_message')
            return redirect('account')
    else:
        resetMasterPasswordForm = forms.ResetMasterPasswordForm()
        MasterPasswordForm = forms.MasterPasswordForm()  

    MasterPasswordForm = forms.MasterPasswordForm() 
    resetMasterPasswordForm = forms.ResetMasterPasswordForm() 

    return render(request, 'vault/account.html', {
        'MasterPasswordForm': MasterPasswordForm,
        'ResetMasterPwForm': resetMasterPasswordForm,
    })


@login_required(login_url='/login')
def edit_user_password(request):
    resetMasterPasswordForm = None  # Initialize with a default value
    if request.method == 'POST':
        resetPasswordForm = forms.ResetPasswordForm(request.POST)
        if resetPasswordForm.is_valid():
            password = resetPasswordForm.cleaned_data.get('password')
            new_password = resetPasswordForm.cleaned_data.get('new_password')
            re_new_password = resetPasswordForm.cleaned_data.get('re_new_password')

            user = request.user

            if not user.check_password(password):
                messages.error(request, "Invalid Original Password", extra_tags='account_message')
                return redirect('account')

            if new_password != re_new_password:
                messages.error(request, "Passwords Don't Match", extra_tags='account_message')
                return redirect('account')

            if len(new_password) < 8:
                messages.error(request, "Password should be at least 8 characters long", extra_tags='account_message')
            elif not re.search(r'\d', new_password):
                messages.error(request, "Password should contain at least one digit", extra_tags='account_message')
            elif not re.search(r'[A-Z]', new_password):
                messages.error(request, "Password should contain at least one uppercase letter", extra_tags='account_message')
            elif not re.search(r'[a-z]', new_password):
                messages.error(request, "Password should contain at least one lowercase letter", extra_tags='account_message')
            elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
                messages.error(request, "Password should contain at least one special character", extra_tags='account_message')
            else:
                user.set_password(new_password)
                user.save()

                messages.success(request, "Password Successfully Reset!", extra_tags='account_message')
                return redirect('account')

        else:
            messages.error(request, "Invalid Form", extra_tags='account_message')
            return redirect('account')
    else:
        resetPasswordForm = forms.ResetPasswordForm()

    return render(request, "vault/account.html", {
        'resetPasswordForm': resetPasswordForm,
        'resetMasterPasswordForm': resetMasterPasswordForm,
        "time": time_string,
        "date": date_string
    })



@login_required(login_url='/login')
def account(request):
    if request.method == 'POST':
        form = forms.MasterPasswordForm(request.POST)
        if form.is_valid():
            master_password = form.cleaned_data.get('password')
            re_master_password = form.cleaned_data.get('re_password')
            
            # Check if passwords match
            if master_password == re_master_password:
                # Password validations in view this time
                if len(master_password) < 8:
                    messages.error(request, "Password should be at least 8 characters long", extra_tags='account_message')
                elif not re.search(r'\d', master_password):
                    messages.error(request, "Password should contain at least one digit", extra_tags='account_message')
                elif not re.search(r'[A-Z]', master_password):
                    messages.error(request, "Password should contain at least one uppercase letter", extra_tags='account_message')
                elif not re.search(r'[a-z]', master_password):
                    messages.error(request, "Password should contain at least one lowercase letter", extra_tags='account_message')
                elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', master_password):
                    messages.error(request, "Password should contain at least one special character", extra_tags='account_message')
                else:
                    profile = Profile.objects.get(user=request.user)
                    
                    # Encrypt Password
                    encrypted_masterPassword = FERNET.encrypt(master_password.encode('utf-8'))
                    profile.master_password = encrypted_masterPassword
                    profile.master_password_set = True
                    profile.save()
                    
                    messages.success(request, "Master Password Successfully Created!", extra_tags='account_message')
                    return redirect('account')
            else:
                messages.error(request, "Passwords Don't Match", extra_tags='account_message')
        else:
            messages.error(request, "Invalid Form", extra_tags='account_message')
    else:
        form = forms.MasterPasswordForm()
        resetMasterPasswordForm = forms.ResetMasterPasswordForm()
        resetPasswordForm = forms.ResetPasswordForm()

    current_time = datetime.now()
    time_string = current_time.strftime('%H:%M')
    date_string = current_time.strftime('%d/%m')

    form = forms.MasterPasswordForm()
    resetMasterPasswordForm = forms.ResetMasterPasswordForm()
    resetPasswordForm = forms.ResetPasswordForm()

    return render(request, "vault/account.html", {
        "MasterPasswordForm": form,
        'ResetMasterPwForm': resetMasterPasswordForm,
        'resetPasswordForm': resetPasswordForm,
        "time": time_string,
        "date": date_string
    })



@login_required(login_url='/login')
def vault_unlock(request):
    #Get Specific User
    try:
        profile = Profile.objects.get(user=request.user)
        profile_master_password = profile.master_password
    except Profile.DoesNotExist:
        messages.error(request, 'Profile not found')
        return redirect('vault')
    if request.method == 'POST':
        if profile_master_password:
            master_password = request.POST.get('master_password')
            decrypted_password = ''
        
            try:
                decrypted_password = FERNET.decrypt(eval(profile_master_password)).decode()
            except InvalidToken as error:
                messages.error(request, "Invalid Token", extra_tags='vault')
                return redirect('vault')
        else:
            messages.error(request, "Make a Master Password", extra_tags='vault')
            return redirect('vault')

    if profile_master_password:
        if decrypted_password == master_password:
            profile.vault_locked = False
            profile.save()
            messages.success(request, "Vault Unlocked", extra_tags='vault')
        else:
            messages.error(request, "Password doesn't match", extra_tags='vault')
    else:
        messages.error(request, "Make a Master Password", extra_tags='vault')
        return redirect('vault')
    return redirect('vault')

@login_required(login_url='/login')
def vault_lock(request):
    profile = Profile.objects.get(user=request.user)
    if request.method == 'POST':
        if not profile.vault_locked:
                profile.vault_locked = True
                profile.save()
                messages.success(request, "Vault Locked", extra_tags='vault')
        else:
            messages.error(request, "Vault Already Locked", extra_tags='vault')
    return redirect('vault')
        

@login_required(login_url='/login')
def vault(request):
    profile = Profile.objects.get(user=request.user)
    passwords = None  # Initialize passwords as None

    if not profile.vault_locked:
        passwords = Info.objects.filter(user_account=request.user.id)

    if request.method == 'POST':
        form = forms.InfoForm(request.POST)
        if not profile.vault_locked:
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
            messages.error(request, "Unlock The Vault", extra_tags='vault')
    else:
        form = forms.InfoForm()
    return render(request, "vault/vault.html", {
        "passwords": passwords,
        "infoForm": form
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
def edit_password(request, password_id):
    #Get Specific User
    try:
        userInfo = Info.objects.get(pk=password_id, user_account=request.user)
    except Info.DoesNotExist:
        messages.error(request, 'Password not found')
        return redirect('vault')

    #Render form
    if request.method == 'POST':
        form = forms.InfoForm(request.POST)
        if form.is_valid():
            website_name = form.cleaned_data['website_name']
            username = form.cleaned_data['username']
            password = form.cleaned_data['website_password']
            encrypted_password = FERNET.encrypt(password.encode('utf-8'))

            userInfo.website_name = website_name
            userInfo.username = username
            userInfo.website_password = encrypted_password
            userInfo.save()

            messages.success(request, "Edited The Vault", extra_tags='vault')
            return HttpResponseRedirect(reverse('vault'))
    else:
        form = forms.InfoForm()
    return render(request, "vault/vault.html", {
        "infoForm": form
    })

@login_required(login_url='/login')
def delete_password(request, password_id):
    try:
        user = get_object_or_404(Info, pk=password_id, user_account=request.user)
        user.delete()
        messages.success(request, 'Password deleted successfully')
    except Info.DoesNotExist:
        messages.error(request, 'Password not found.')
    return redirect('vault')
