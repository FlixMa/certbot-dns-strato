"""DNS Authenticator for Strato."""
import logging
import sys
import re
import sys
import time
import pyotp
import requests
import urllib
from bs4 import BeautifulSoup

from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Strato

    This Authenticator uses webscraping of Strato.de to fulfill a dns-01 challenge.
    Accessing different hosts like Strato.nl can be configured using the custom_api_host setting in your credentials INI.
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
        
        if strato.package_id is None:
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
        
        if strato.package_id is None:
            # Requests package id which package contains domain to be verified
            strato.get_package_id()

        # Requests all current TXT/CNAME/SPF/DKIM records from Strato
        strato.get_txt_records()

        # Remove verification token record
        strato.reset_amce_record(validation_name)
        
        # Sets all TXT/CNAME/SPF/DKIM records without AMCE record in dns server
        strato.push_txt_records()

    def _get_configured_strato_client(self):
        strato = _StratoApi(
            domain_display_name=self.credentials.conf('domain_display_name'),
            custom_api_scheme=self.credentials.conf('custom_api_scheme'),
            custom_api_host=self.credentials.conf('custom_api_host'), 
            custom_api_port=self.credentials.conf('custom_api_port'), 
            custom_api_path=self.credentials.conf('custom_api_path'),
            custom_package_id=self.credentials.conf('custom_package_id')
        )
        if not strato.login(self.credentials.conf('username'), self.credentials.conf('password'), self.credentials.conf('totp_secret'), self.credentials.conf('totp_devicename')):
            print('ERROR: Strato login not accepted.')
            sys.exit(1)
        
        return strato



class _StratoApi:
    """Class to validate domains with dns-01 challange"""

    def __init__(self, domain_display_name=None, custom_api_scheme=None, custom_api_host=None, custom_api_port=None, custom_api_path=None, custom_package_id=None):
        """ Initializes the data structure """
        api_scheme = 'https' if custom_api_scheme is None else custom_api_scheme
        api_host = 'www.strato.de' if custom_api_host is None else custom_api_host
        api_port = '' if custom_api_port is None else (':' + custom_api_port)
        api_path = '/apps/CustomerService' if custom_api_path is None else custom_api_path

        self.api_url = f"{api_scheme}://{api_host}{api_port}{api_path}"
        self.domain_display_name = domain_display_name
        self.domain_name = None
        self.second_level_domain_name = None
        

        # setup session for cookie sharing
        self.http_session = requests.session()
        self.http_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0'
        })

        # Set later
        self.session_id = ''
        self.package_id = custom_package_id
        self.records = []

        self.action_change_txt_records = None


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
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find('h1', string=re.compile('Zwei\\-Faktor\\-Authentifizierung')) is None:
            print('INFO: 2FA is not used.')
            return response
        if (not totp_secret) or (not totp_devicename):
            print('ERROR: 2FA parameter is not completely set.')
            return response

        param = {'identifier': username}

        # Set parameter 'totp_token'
        totp_input = soup.find('input', attrs={'type': 'hidden', 'name': 'totp_token'})
        if totp_input is not None:
            param['totp_token'] = totp_input['value']
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
        data={'identifier': username, 'passwd': password, 'action_customer_login.x': 'Login'}
        
        
        response1 = self.http_session.get(self.api_url)
        print(response1.url)
        response2 = self.http_session.post(self.api_url, data=data, allow_redirects=True)
        print(response2.url)
        
        # Check 2FA Login
        response3 = self.login_2fa(response2, username, totp_secret, totp_devicename)
        print(response3.url)

        # Check successful login
        parsed_url = urllib.parse.urlparse(response3.url)
        query_parameters = urllib.parse.parse_qs(parsed_url.query)
        if 'sessionID' not in query_parameters:
            return False
        self.session_id = query_parameters['sessionID'][0]
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
        soup = BeautifulSoup(request.text, 'html.parser')
        package_anchor = soup.select_one(
            '#package_list > tbody >'
            f' tr:has(.package-information:-soup-contains("{self.second_level_domain_name}"))'
            ' .jss_with_own_packagename a'
        )
        if package_anchor:
            if package_anchor.has_attr('href'):
                link_target = urllib.parse.urlparse(package_anchor["href"])
                self.package_id = urllib.parse.parse_qs(link_target.query)["cID"][0]
                print(f'INFO: strato package id (cID): {self.package_id}')
                return
        
        print(f'ERROR: Domain {self.second_level_domain_name} not '
            'found in strato packages. Using fallback cID=1')
        self.package_id = 1


    def get_txt_records(self) -> None:
        """Requests all txt and cname records related to domain."""
        request = self.http_session.get(self.api_url, params={
            'sessionID': self.session_id,
            'cID': self.package_id,
            'node': 'ManageDomains',
            'action_show_txt_records': '',
            'vhost': self.domain_name
        })

        #print('txt_record_response:\n', request.text)
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

        submit_button_match = next(re.finditer(r'<input [^>]*?name="action_change_txt_records"[^>]*value="(.+?)"[^>]*?>', request.text), None)
        self.action_change_txt_records = submit_button_match.group(1) if submit_button_match is not None else 'Einstellung+übernehmen'

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
            'action_change_txt_records': self.action_change_txt_records,
        }
        print(payload)
        result = self.http_session.post(self.api_url, payload)
        print(result)
