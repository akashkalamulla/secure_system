from django import forms
from django.contrib.auth.forms import AuthenticationForm
from accounts.models import CustomUser
from django.contrib.auth.password_validation import validate_password

class LoginForm(AuthenticationForm):
    username = forms.CharField(max_length=150, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))


class RegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput,
        label="Password",
        help_text="Your password must be at least 12 characters long and meet security requirements.",
        validators=[validate_password],  # Apply Django's standard password validation
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput,
        label="Confirm Password"
    )

    class Meta:
        model = CustomUser  # ✅ Use CustomUser instead of User
        fields = ["username", "email", "password"]

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")

        # Check if passwords match
        if password and password_confirm and password != password_confirm:
            self.add_error("password_confirm", "Passwords do not match.")

        # Validate password using Django's built-in security checks
        if password:
            validate_password(password)

        return cleaned_data
class EditUserForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'role', 'is_active']
        labels = {
            'username': 'Username',
            'email': 'Email',
            'role': 'User Role',
            'is_active': 'Active Status',
        }
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'role': forms.Select(attrs={'class': 'form-control'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }