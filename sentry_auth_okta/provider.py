from __future__ import absolute_import, print_function

from sentry.auth.providers.saml2 import SAML2Provider

from .views import (
    OktaSAML2ConfigureView, OktaSelectIdP
)

from .constants import OKTA_EMAIL, OKTA_USERNAME, OKTA_DISPLAYNAME


class OktaSAML2Provider(SAML2Provider):
    name = 'Okta'

    def get_configure_view(self):
        return OktaSAML2ConfigureView.as_view()

    def get_setup_pipeline(self):
        return [
            OktaSelectIdP()
        ]

    def build_config(self, state):
        data = super(OktaSAML2Provider, self).build_config(state)

        if data:
            data['attribute_mapping'] = {
                'attribute_mapping_email': OKTA_EMAIL,
                'attribute_mapping_username': OKTA_USERNAME,
                'attribute_mapping_displayname': OKTA_DISPLAYNAME
            }
        return data
