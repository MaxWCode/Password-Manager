from django.shortcuts import render
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


# ENCRYPTION FUNCTIONS
key = Fernet.generate_key()
def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data
#{{ decrypt_data(password.website_password, key) }}
# ENCRYPTION FUNCTIONS

# Create your views here.
def index(request):
    return render(request, "vault/index.html")

@login_required(login_url='/login')
def vault(request):
    passwords = Info.objects.filter(user_account=request.user.id)
    form = forms.InfoForm(request.POST)
    if form.is_valid():
        website_name = form.cleaned_data['website_name']
        username = form.cleaned_data['username']
        password = form.cleaned_data['website_password']
        encrypted_password = encrypt_data(password, key)
        info = Info(user_account=request.user, website_name=website_name, username=username, website_password=encrypted_password)
        info.save()
        return HttpResponseRedirect(reverse('vault'))

    
    infoForm = forms.InfoForm()
    return render(request, "vault/vault.html", {
        "passwords": passwords,
        "infoForm": infoForm,
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
    return HttpResponseRedirect('/', {"messages": messages.get_messages(request)})

def copy_password(request):
    if request.method == 'POST':
        key = Fernet.generate_key()
        fernet = Fernet(key)
        password_id = request.POST.get('password_id')
        password = Info.objects.get(pk=password_id)
        decrypted_password = fernet.decrypt(password.website_password).decode()
        pyperclip.copy(decrypted_password)
        messages.success(request, 'Password copied to clipboard.')
    return redirect('vault')