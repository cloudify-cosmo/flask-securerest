#########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

import ldap

from flask.ext.securest.models import User
from flask.ext.securest.userstores.abstract_userstore import AbstractUserstore


class LDAPUserstore(AbstractUserstore):
    """
    This class is an example of a concrete implementation of a user store.
    It implements an LDAP user store.
    """

    def __init__(self,
                 identifying_attribute,
                 directory_url,
                 admin_dn,
                 admin_password,
                 root_dn,
                 username_attribute,
                 user_password_attribute,
                 user_email_attribute=None,
                 is_active_attribute=None):
        # initialize ldap with url, admin and password
        self._identifying_attribute = identifying_attribute
        self.root_dn = root_dn
        self.ldapObject = ldap.initialize(directory_url)
        self.ldapObject.bind(admin_dn, admin_password, ldap.AUTH_SIMPLE)
        self.username_attribute = username_attribute
        self.user_password_attribute = user_password_attribute
        self.user_email_attribute = user_email_attribute
        self.is_active_attribute = is_active_attribute

    def __del__(self):
        self.ldapObject.unbind()

    def get_user(self, user_identifier):
        if not user_identifier:
            raise ValueError('user identifier is missing or empty')

        return self._get_user_object(user_identifier)

    def _get_user_object(self, user_identifier):
        search_result = self.ldapObject.search_s(
            '{0}'.format(self.root_dn),
            ldap.SCOPE_SUBTREE,
            '({0}={1})'.format(self._identifying_attribute, user_identifier))
        if not search_result:
            return None
        user_entry = search_result[0][1]

        user_email = LDAPUserstore.get_attribute_if_exists(
            self.user_email_attribute, user_entry, None)
        is_active = LDAPUserstore.get_attribute_if_exists(
            self.is_active_attribute, user_entry, True)

        return User(user_entry[self.username_attribute][0],
                    user_entry[self.user_password_attribute][0],
                    user_email,
                    active=is_active)

    @staticmethod
    def get_attribute_if_exists(attr_name, user_entry, default_value=None):
        value = default_value
        if attr_name:
            attr_list = user_entry.get(attr_name)
            if attr_list:
                value = attr_list[0]
        return value
