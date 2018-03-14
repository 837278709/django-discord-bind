
from django import forms
from django.utils.translation import ugettext_lazy as _
from account.models import EmailAddress


class EmailVerifyForm(forms.Form):

    email = forms.EmailField(label=_("Email"), required=True)

    def clean_email(self):
        value = self.cleaned_data["email"]
        if EmailAddress.objects.filter(email__iexact=value).exists():
            raise forms.ValidationError(_("Email already exist."))
        return value
