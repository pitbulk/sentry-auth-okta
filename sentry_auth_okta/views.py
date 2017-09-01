from __future__ import absolute_import, print_function

from django import forms
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django.core.validators import URLValidator
from django.utils.translation import ugettext_lazy as _

from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from sentry.auth.view import AuthView
from sentry.auth.providers.saml2 import SAML2Provider, SAML2ConfigureView, NAMEID_FORMAT_CHOICES, AUTHNCONTEXT_CHOICES
from sentry.utils.http import absolute_uri


class OktaSAMLForm(forms.Form):
    idp_entityid = forms.CharField(label='Okta Entity ID')
    idp_sso_url = forms.URLField(label='Okta Single Sign On URL')
    idp_slo_url = forms.URLField(label='Okta Single Log Out URL', required=False)
    idp_x509cert = forms.CharField(label='Okta x509 public certificate', widget=forms.Textarea)


class OktaAdvancedForm(forms.Form):
    advanced_spentityid = forms.CharField(label='SP EntityID', required=False, help_text=_('Service Provider EntityID, if not provided, the URL where Sentry publish the SP metadata will be used as its value'))
    advanced_nameidformat = forms.ChoiceField(label='NameID Format', required=False, choices=NAMEID_FORMAT_CHOICES, help_text=_('Specifies constraints on the name identifier to be used to represent the requested subject. Review IdP metadata to see the supported NameID formats'))
    advanced_requestedauthncontext = forms.MultipleChoiceField(label='Requested Authn Context', required=False, choices=AUTHNCONTEXT_CHOICES, help_text=_('AuthContext sent in the AuthNRequest. You can select none (any authn source will be accepted), one or multiple values'))
    advanced_sp_x509cert = forms.CharField(label='SP X.509 Certificate', widget=forms.Textarea, required=False, help_text=_('Public x509 certificate of the Service Provider'))
    advanced_sp_privatekey = forms.CharField(label='SP Private Key', widget=forms.Textarea, required=False, help_text=_('Private Key of the Service Provider'))

    def clean(self):
        super(OktaAdvancedForm, self).clean()

        requires_sp_cert_data_due_sign = self.data.get('options_slo', False)
        has_sp_cert_data = self.data.get('advanced_sp_x509cert', None) and self.data.get('advanced_sp_privatekey', None)

        if requires_sp_cert_data_due_sign:
            if not has_sp_cert_data:
                self._errors["advanced_sp_x509cert"] = [_("Required in order to be provided to Okta to validate signature of SP's SAML Logout messages")]
                self._errors["advanced_sp_privatekey"] = [_("Required since SP needs to sign Logout SAML Messages")]
                del self.cleaned_data["advanced_sp_x509cert"]
                del self.cleaned_data["advanced_sp_privatekey"]
        return self.cleaned_data

class OktaForm(forms.Form):
    metadata_url = forms.URLField(label='Metadata URL')
    provider = forms.CharField(widget=forms.HiddenInput, initial='okta', required=False)


class OktaSAML2ConfigureView(SAML2ConfigureView):
    saml_form_cls = OktaSAMLForm
    advanced_form_cls = OktaAdvancedForm

    def display_configure_view(self, organization, saml_form, options_form, attr_mapping_form, advanced_form):

        sp_metadata_url = absolute_uri(reverse('sentry-auth-organization-saml-metadata', args=[organization.slug]))

        return self.render('sentry_auth_okta/configure.html', {
            'sp_metadata_url': sp_metadata_url,
            'saml_form': saml_form,
            'options_form': options_form,
            'attr_mapping_form': attr_mapping_form,
            'advanced_form': advanced_form
        })


class OktaSelectIdP(AuthView):
    def handle(self, request, helper):
        missing_values = error_url = False
        if 'action_save' in request.POST:
            form = OktaForm(request.POST)
            if form.is_valid():
                metadata_url = form.cleaned_data['metadata_url']

                if metadata_url:
                    validate_url = URLValidator()
                    try:
                        validate_url(metadata_url)
                        try:
                            data = OneLogin_Saml2_IdPMetadataParser.parse_remote(metadata_url)

                            if data and 'idp' in data:    
                                idp_data = SAML2Provider.extract_idp_data_from_parsed_data(data)
                                form2 = OktaSAMLForm(idp_data)
                                if form2.is_valid():
                                    helper.bind_state('idp', idp_data)
                                    helper.bind_state('contact', request.user.email)
                                    return helper.next_step()
                                else:
                                    missing_values = form2.errors.keys
                        except Exception:
                            pass
                    except ValidationError:
                        error_url = True                    
        else:
            form = OktaForm()

        return self.respond('sentry_auth_okta/select-idp.html', {
            'form': form,
            'error_url': error_url,
            'missing_values': missing_values
        })
