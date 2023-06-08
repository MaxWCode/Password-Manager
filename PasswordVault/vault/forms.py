from django import forms
from django.core.exceptions import ValidationError
from .models import Info
from django.contrib import messages
from django.contrib.auth.models import User

class SignupForm(forms.Form):
    username = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={
            'id': 'username',
            'class': 'txt_field',
            'type': 'text'

        }),
        error_messages={
            "required": "Enter A Username",
            "max_length": "Use Under 30 Characters"
        }
    )
    
    password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'password',
            'class': 'txt_field',
            'type': 'password'
        }),
        error_messages={
            "required": "Enter A Password"
        }
    )

    def clean_password(self):
        password = self.cleaned_data['password']
        if not any(char.isdigit() for char in password):
            raise ValidationError('Password must contain at least one digit')
        if not any(char.isupper() for char in password):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in password):
            raise ValidationError('Password must contain at least one lowercase letter')
        if len(password) < 8:
            raise ValidationError('Password must be at least 8 characters long')
        return password
    
class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={
            'id': 'username',
            'class': 'txt_field',
            'type': 'text'

        }),
        error_messages={
            "required": "Enter A Username",
            "max_length": "Use Under 30 Characters"
        }
    )
    
    password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'password',
            'class': 'txt_field',
            'type': 'password'
        }),
        error_messages={
            "required": "Enter A Password"
        }
    )

class InfoForm(forms.ModelForm):
    website_name = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'id': 'id_website_name',
        'name': 'website_name',
        'maxlength': '100',
        'required': 'true',
        'placeholder': 'Website name'
    }))
    username = forms.CharField(max_length=50, widget=forms.TextInput(attrs={
        'id': 'id_username',
        'name': 'username',
        'maxlength': '50',
        'required': 'true',
        'placeholder': 'Username'
    }))
    website_password = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'id': 'id_website_password',
        'name': 'website_password',
        'type': 'password',
        'maxlength': '50',
        'required': 'true',
        'placeholder': 'Password'
    }))

    class Meta:
        model = Info
        fields = ['website_name', 'username', 'website_password']


class EditForm(forms.Form):
    choose_website = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'editInput',
        'name': 'choose_website',
        'maxlength': '100',
        'required': 'true',
        'placeholder': 'Choose Website'
    }))
    new_username = forms.CharField(max_length=50, widget=forms.TextInput(attrs={
        'class': 'editInput',
        'name': 'new_username',
        'maxlength': '50',
        'required': 'true',
        'placeholder': 'New Username'
    }))
    new_website_password = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'editInput',
        'name': 'new_website_password',
        'type': 'password',
        'maxlength': '50',
        'required': 'true',
        'placeholder': 'New Website Password'
    }))

class MasterPasswordForm(forms.Form):
    password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'masterPasswordInput',
            'type': 'password',
            'placeholder': 'Enter Master Password',
            'text-align': 'center',
            'name': 'password'
        }),
        error_messages={
            "required": "Enter Master Password"
        }
    )
    
    re_password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'masterPasswordInput',
            'type': 'password',
            'placeholder': 'Re-Enter Master Password',
            'text-align': 'center',
            'name': 're_password'
        }),
        error_messages={
            "required": "Re-Enter Master Password"
        }
    )

class ResetMasterPasswordForm(forms.Form):
    password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'resetMasterPasswordInput',
            'type': 'password',
            'placeholder': 'Enter Master Password',
            'text-align': 'center',
            'name': 'password'
        }),
        error_messages={
            "required": "Enter Password"
        }
    )

    new_password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'resetMasterPasswordInput',
            'type': 'password',
            'placeholder': 'Enter New Password',
            'text-align': 'center',
            'name': 'new_password'
        }),
        error_messages={
            "required": "Enter Master Password"
        }
    )
    
    re_new_password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'resetMasterPasswordInput',
            'type': 'password',
            'placeholder': 'Re-Enter Your New Password',
            'text-align': 'center',
            'name': 're_new_password'
        }),
        error_messages={
            "required": "Re-Enter Master Password"
        }
    )

class ResetPasswordForm(forms.Form):
    password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'resetMasterPasswordInput',
            'type': 'password',
            'placeholder': 'Enter Password',
            'text-align': 'center',
            'name': 'password'
        }),
        error_messages={
            "required": "Enter Password"
        }
    )

    new_password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'resetMasterPasswordInput',
            'type': 'password',
            'placeholder': 'Enter New Password',
            'text-align': 'center',
            'name': 'new_password'
        }),
        error_messages={
            "required": "Enter Master Password"
        }
    )
    
    re_new_password = forms.CharField(
        max_length=30,
        widget=forms.PasswordInput(attrs={
            'id': 'resetMasterPasswordInput',
            'type': 'password',
            'placeholder': 'Re-Enter Your New Password',
            'text-align': 'center',
            'name': 're_new_password'
        }),
        error_messages={
            "required": "Re-Enter Master Password"
        }
    )



