"""DNS Authenticator for Strato."""
import logging
import sys
import re
import sys
import time
import pyotp
import requests

from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Strato

    This Authenticator uses webscraping of Strato.de to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using Strato for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="Strato credentials INI file")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge on a Strato hosted domain."

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "Strato credentials INI file",
            {
                "username": "Username for Strato API.",
                "password": "Password for Strato API."
            },
        )

    def _perform(self, domain, validation_name, validation):
        strato = self._get_configured_strato_client()
        strato.set_domain_name(domain)
        # Requests package id which package contains domain to be verified
        strato.get_package_id()
        # Requests all current TXT/CNAME/SPF/DKIM records from Strato
        strato.get_txt_records()
        # Add verification token record
        strato.set_amce_record(validation_name, validation)
        # Sets all TXT/CNAME/SPF/DKIM records with AMCE record in dns server
        strato.push_txt_records()


    def _cleanup(self, domain, validation_name, validation):
        strato = self._get_configured_strato_client()
        strato.set_domain_name(domain)
        # Requests package id which package contains domain to be verified
        strato.get_package_id()
        # Requests all current TXT/CNAME/SPF/DKIM records from Strato
        strato.get_txt_records()
        # Remove verification token record
        strato.reset_amce_record(validation_name)
        # Sets all TXT/CNAME/SPF/DKIM records without AMCE record in dns server
        strato.push_txt_records()

    def _get_configured_strato_client(self):
        strato = _StratoApi(self.credentials.conf('domain_display_name'))
        if not strato.login(self.credentials.conf('username'), self.credentials.conf('password'), self.credentials.conf('totp_secret'), self.credentials.conf('totp_devicename')):
            print('ERROR: Strato login not accepted.')
            sys.exit(1)
        
        return strato



class _StratoApi:
    """Class to validate domains with dns-01 challange"""

    def __init__(self, domain_display_name=None):
        """ Initializes the data structure """
        self.api_url = 'https://www.strato.de/apps/CustomerService'
        self.domain_display_name = domain_display_name
        self.domain_name = None
        self.second_level_domain_name = None
        

        # setup session for cookie sharing
        self.http_session = requests.session()

        # Set later
        self.session_id = ''
        self.package_id = 0
        self.records = []


    def login_2fa(
            self,
            response: requests.Response,
            username: str,
            totp_secret: str,
            totp_devicename: str,
            ) -> requests.Response:
        """Login with Two-factor authentication by TOTP on Strato website.

        :param str totp_secret: 2FA TOTP secret hash
        :param str totp_devicename: 2FA TOTP device name

        :returns: Original response or 2FA response
        :rtype: requests.Response

        """
        # Is 2FA used
        if (not response.text.__contains__(
            '<h1>Zwei-Faktor-Authentifizierung</h1>')
            ):
            print('INFO: 2FA is not used.')
            return response
        if (not totp_secret) or (not totp_devicename):
            print('ERROR: 2FA parameter is not completely set.')
            return response

        param = {'identifier': username}

        # Set parameter 'totp_token'
        result = re.search(
            r'<input type="hidden" name="totp_token" '
            r'value="(?P<totp_token>\w+)">',
            response.text)
        if result:
            param['totp_token'] = result.group('totp_token')
        else:
            print('ERROR: Parsing error on 2FA site by totp_token.')
            return response

        # Set parameter 'action_customer_login.x'
        param['action_customer_login.x'] = 1

        # Set parameter pw_id
        for device in re.finditer(
            rf'<option value="(?P<value>(S\.{username}\.\w*))"'
            r'( selected(="selected")?)?\s*>(?P<name>(.+?))</option>',
            response.text):
            if totp_devicename.strip() == device.group('name').strip():
                param['pw_id'] = device.group('value')
                break
        if param.get('pw_id') is None:
            print('ERROR: Parsing error on 2FA site by device name.')
            return response

        # Set parameter 'totp'
        param['totp'] = pyotp.TOTP(totp_secret).now()
        print(f'DEBUG: totp: {param.get("totp")}')

        request = self.http_session.post(self.api_url, param)
        return request


    def login(
            self,
            username: str,
            password: str,
            totp_secret: str = None,
            totp_devicename: str = None,
        ) -> bool:
        """Login to Strato website. Requests session ID.

        :param str username: Username or customer number of
                'STRATO Customer Login'
        :param str password: Password of 'STRATO Customer Login'
        :param str totp-secret: 2FA TOTP secret hash
        :param str totp-devicename: 2FA TOTP device name

        :returns: Successful login
        :rtype: bool

        """
        # request session id
        self.http_session.get(self.api_url)
        request = self.http_session.post(self.api_url, {
            'identifier': username,
            'passwd': password,
            'action_customer_login.x': 'Login'
        })

        # Check 2FA Login
        request = self.login_2fa(request, username,
            totp_secret, totp_devicename)

        # Check successful login
        result = re.search(r'sessionID=(\w+)', request.url)
        if not result:
            return False
        self.session_id = result.group(1)
        print(f'DEBUG: session_id: {self.session_id}')
        return True


    def set_domain_name(self, domain_name):
        self.domain_name = domain_name
        self.second_level_domain_name = self.domain_display_name or re.search(r'([\w-]+\.[\w-]+)$',
            self.domain_name).group(1)
        
        print(f'INFO: second_level_domain_name: {self.second_level_domain_name}')
        print(f'INFO: domain_name: {self.domain_name}')

    def get_package_id(self) -> None:
        """Requests package ID for the selected domain."""
        # request strato packages
        request = self.http_session.get(self.api_url, params={
            'sessionID': self.session_id,
            'cID': 0,
            'node': 'kds_CustomerEntryPage',
        })
        result = re.search(
            r'<div class="package-information">.+?<span\s+class="domains_\d+_long[^>]*>.+?'
            + self.second_level_domain_name.replace('.', r'\.')
            + r'.+?cID=(?P<cID>\d+)',
            request.text.replace('\n', ' ')
            )

        if result is None:
            print(f'ERROR: Domain {self.second_level_domain_name} not '
                'found in strato packages')
            sys.exit(1)
        self.package_id = result.group('cID')
        print(f'INFO: strato package id (cID): {self.package_id}')


    def get_txt_records(self) -> None:
        """Requests all txt and cname records related to domain."""
        request = self.http_session.get(self.api_url, params={
            'sessionID': self.session_id,
            'cID': self.package_id,
            'node': 'ManageDomains',
            'action_show_txt_records': '',
            'vhost': self.domain_name
        })
        for record in re.finditer(
                r'<select [^>]*name="type"[^>]*>.*?'
                r'<option[^>]*value="(?P<type>[^"]*)"[^>]*selected[^>]*>'
                r'.*?</select>.*?'
                r'<input [^>]*value="(?P<prefix>[^"]*)"[^>]*name="prefix"[^>]*>'
                r'.*?<textarea [^>]*name="value"[^>]*>(?P<value>.*?)</textarea>',
                request.text):
            self.records.append({
                'prefix': record.group('prefix'),
                'type': record.group('type'),
                'value': record.group('value')
            })

        print('INFO: Current cname/txt records:')
        list(print(f'INFO: - {item["prefix"]} {item["type"]}: {item["value"]}')
            for item in self.records)


    def add_txt_record(self, prefix: str, record_type: str, value: str) -> None:
        """Add a txt/cname record.

        :param prefix str: Prefix of record
        :param record_type str: Type of record ('TXT' or 'CNAME')
        :param value str: Value of record

        """
        self.records.append({
            'prefix': prefix,
            'type': record_type,
            'value': value,
        })


    def remove_txt_record(self, prefix: str, record_type: str) -> None:
        """Remove a txt/cname record.

        :param prefix str: Prefix of record
        :param record_type str: Type of record ('TXT' or 'CNAME')

        """
        for i in reversed(range(len(self.records))):
            if (self.records[i]['prefix'] == prefix
                and self.records[i]['type'] == record_type):
                self.records.pop(i)


    def set_amce_record(self, txt_key, txt_value) -> None:
        """Set or replace AMCE txt record on domain."""
        self.add_txt_record(txt_key.replace('.' + self.domain_name, ''), 'TXT', txt_value)


    def reset_amce_record(self, txt_key) -> None:
        """Reset AMCE txt record on domain."""
        self.remove_txt_record(txt_key.replace('.' + self.domain_name, ''), 'TXT')


    def push_txt_records(self) -> None:
        """Push modified txt records to Strato."""
        print('INFO: New cname/txt records:')
        list(print(f'INFO: - {item["prefix"]} {item["type"]}: {item["value"]}')
            for item in self.records)

        payload = {
            'sessionID': self.session_id,
            'cID': self.package_id,
            'node': 'ManageDomains',
            'vhost': self.domain_name,
            'spf_type': 'NONE',
            'prefix': [r['prefix'] for r in self.records],
            'type': [r['type'] for r in self.records],
            'value': [r['value'] for r in self.records],
            'action_change_txt_records': 'Einstellung+übernehmen',
        }
        print(payload)
        result = self.http_session.post(self.api_url, payload)
        print(result)
