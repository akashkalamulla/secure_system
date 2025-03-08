import os

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth.models import User

from accounts.models import CustomUser, Task, Notification
from django.contrib.auth.password_validation import validate_password

class LoginForm(AuthenticationForm):
    username = forms.CharField(max_length=150, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

User = get_user_model()

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
class UserForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'role', 'password']

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if CustomUser.objects.filter(username=username).exists():
            raise forms.ValidationError("Username is already taken.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError("Email is already registered.")
        return email

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if len(password) < 12:
            raise forms.ValidationError("Password must be at least 12 characters long.")
        return password

class EmployeePasswordChangeForm(PasswordChangeForm):
    class Meta:
        model = User
        fields = ['password']

class FileUploadForm(forms.Form):
    file = forms.FileField()

    def clean_file(self):
        uploaded_file = self.cleaned_data['file']
        # Limit file size (e.g., 5MB)
        if uploaded_file.size > 5 * 1024 * 1024:
            raise forms.ValidationError("File size should be less than 5MB.")
        # Only allow certain file types (PDF, JPG, PNG)
        allowed_extensions = ['.pdf', '.jpg', '.jpeg', '.png']
        extension = os.path.splitext(uploaded_file.name)[1]
        if extension.lower() not in allowed_extensions:
            raise forms.ValidationError("Only PDF, JPG, and PNG files are allowed.")
        return uploaded_file

class TaskForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['user', 'name', 'description', 'due_date', 'status']  # Include name and description

    # Custom validation (e.g., ensure the user is an employee)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user'].queryset = User.objects.filter(role='employee')  # Only show employees in the dropdown

class NotificationForm(forms.ModelForm):
    class Meta:
        model = Notification
        fields = ['user', 'message']

    # Custom validation (e.g., ensure the user is an employee)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user'].queryset = User.objects.filter(role='employee')  # Only show employees in the dropdown