from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from datetime import datetime
from . import forms
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Info

# Create your views here.
def index(request):
    return render(request, "vault/index.html")

@login_required
def vault(request):
    passwords = Info.objects.filter(user_account=request.user.id)

    return render(request, "vault/vault.html", {
        "passwords": passwords
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
                return HttpResponseRedirect("/home", {"messages": messages.get_messages(request), "username": username})
            else:
                # Display an error message if authentication fails
                messages.error(request, "Incorrect username or password")
        
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
            messages.success(request, "Account Successfully Created!")
            return HttpResponseRedirect("/login", {"messages": messages.get_messages(request)})
        
    else:
        form = forms.SignupForm()

    return render(request, "vault/signup.html", {
        'form': form
    })

def logout_view(request):
    logout(request)
    messages.success(request, "Successfully Logged Out")
    return HttpResponseRedirect('/home', {"messages": messages.get_messages(request)})