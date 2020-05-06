# Copyright (c) 2014 VMware, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Common classes that provide access to vSphere services.
"""

import logging
import os

import netaddr
from oslo_utils import uuidutils
import requests
import six
import six.moves.http_client as httplib

from lxml import etree
import zeep
from zeep.cache import InMemoryCache

from oslo_vmware._i18n import _
from oslo_vmware import exceptions
from oslo_vmware import vim_util

CACHE_TIMEOUT = 60 * 60  # One hour cache timeout
ADDRESS_IN_USE_ERROR = 'Address already in use'
CONN_ABORT_ERROR = 'Software caused connection abort'
RESP_NOT_XML_ERROR = 'Response is "text/html", not "text/xml"'

SERVICE_INSTANCE = 'ServiceInstance'

LOG = logging.getLogger(__name__)


class PruneEmptyNodesPlugin(zeep.Plugin):

    # list of XML elements which are allowed to be empty
    EMPTY_ELEMENTS = ["VirtualMachineEmptyProfileSpec"]

    def _isempty(self, el):
        """Same implementation suds used to have"""
        return el.text is None and not el.keys() and not len(el.getchildren())

    def _prune(self, el):
        pruned = []
        for child in el:
            self._prune(child)
            if self._isempty(child):
                tag_name = etree.QName(child.tag).localname
                if tag_name not in self.EMPTY_ELEMENTS:
                    pruned.append(child)
        for p in pruned:
            el.remove(p)

    def egress(self, envelope, http_headers, operation, binding_options):
        """Prune empty nodes before sending the XML

        According to previous documentation here, the VI SDK throws server
        errors if optional SOAP nodes are sent without values; e.g. <test/> as
        opposed to <test>test</test>. Seeing that `zeep` can create such nodes
        if optional elements in a sequence are not specified, we try to find
        them and remove them.
        """
        self._prune(envelope)
        return envelope, http_headers


class AddAnyTypeTypeAttributePlugin(zeep.Plugin):

    def _add_attribute_for_value(self, el):
        tag_name = etree.QName(el.tag).localname
        xsi_ns = zeep.xsd.const.xsi_ns
        if tag_name in ('value', 'val'):
            el.set(xsi_ns('type'), 'xsd:string')
        elif tag_name == 'removeKey':
            try:
                int(el.text)
                el.set(xsi_ns('type'), 'xsd:int')
            except (ValueError, TypeError):
                el.set(xsi_ns('type'), 'xsd:string')

        for child in el:
            self._add_attribute_for_value(child)

    def egress(self, envelope, http_headers, operation, binding_options):
        """Add an `xsi:type` attribute to value nodes

        The VI SDK requires a type attribute to be set when AnyType is used,
        but `zeep` only does it when explicitly provided with a special object,
        we don't want to leak through the abstraction.
        """
        # TODO(jkulik): Once we're on a zeep version containing
        # https://github.com/mvantellingen/python-zeep/pull/1079 we should be
        # able to remove this plugin.
        self._add_attribute_for_value(envelope)
        return envelope, http_headers


class Response(six.BytesIO):
    """Response with an input stream as source."""

    def __init__(self, stream, status=200, headers=None):
        self.status = status
        self.headers = headers or {}
        self.reason = requests.status_codes._codes.get(
            status, [''])[0].upper().replace('_', ' ')
        six.BytesIO.__init__(self, stream)

    @property
    def _original_response(self):
        return self

    @property
    def msg(self):
        return self

    def read(self, chunk_size, **kwargs):
        return six.BytesIO.read(self, chunk_size)

    def info(self):
        return self

    def get_all(self, name, default):
        result = self.headers.get(name)
        if not result:
            return default
        return [result]

    def getheaders(self, name):
        return self.get_all(name, [])

    def release_conn(self):
        self.close()


class LocalFileAdapter(requests.adapters.HTTPAdapter):
    """Transport adapter for local files.

    See http://stackoverflow.com/a/22989322
    """
    def __init__(self, pool_maxsize=10):
        super(LocalFileAdapter, self).__init__(pool_connections=pool_maxsize,
                                               pool_maxsize=pool_maxsize)

    def _build_response_from_file(self, request):
        file_path = request.url[7:]
        with open(file_path, 'r') as f:
            buff = bytearray(os.path.getsize(file_path))
            f.readinto(buff)
            resp = Response(buff)
            return self.build_response(request, resp)

    def send(self, request, stream=False, timeout=None,
             verify=True, cert=None, proxies=None):
        return self._build_response_from_file(request)


class FactoryCompatibilityProxy(object):

    def __init__(self, _client):
        self._client = _client
        self._factory_cache = {}

    def create(self, obj, *args, **kwargs):
        ns, obj = obj.split(':', 1)
        if ns not in self._factory_cache:
            self._factory_cache[ns] = self._client.type_factory(ns)
        factory = self._factory_cache[ns]
        return getattr(factory, obj)(*args, **kwargs)


class CompatibilityZeepClient(zeep.client.Client):
    """zeep Client with added `factory` attribute

    The `factory` attribute is necessary for compatibility with the older suds
    version of oslo.vmware. There's a lot of code using it, which would have to
    be changed to use `Client.type_factory` instead.

    We also support setting the soap_url to something else than what the WSDL
    ports return, which zeep otherwise doesn't support.

    This class also creates a backend-independent interface for accessing the
    cookiejar.
    """

    def __init__(self, *args, **kwargs):
        soap_url = kwargs.pop('soap_url', None)

        super(CompatibilityZeepClient, self).__init__(*args, **kwargs)

        self.factory = FactoryCompatibilityProxy(self)

        # we cannot set this otherwise. it's parsed from the WSDL. we might
        # need to reconfigure our vcenters to send proper WSDL service and
        # ports
        if soap_url is not None:
            self.service._binding_options['address'] = soap_url

    @property
    def cookiejar(self):
        return self.transport.session.cookies

    @cookiejar.setter
    def cookiejar(self, cookies):
        self.transport.session.cookies = cookies


class Service(object):
    """Base class containing common functionality for invoking vSphere
    services
    """

    def __init__(self, wsdl_url=None, soap_url=None,
                 cacert=None, insecure=True, pool_maxsize=10,
                 connection_timeout=None, op_id_prefix='oslo.vmware',
                 pool_block=False):
        self.wsdl_url = wsdl_url
        self.soap_url = soap_url
        self.op_id_prefix = op_id_prefix

        LOG.debug("Creating zeep client with soap_url='%s' and wsdl_url='%s'",
                  self.soap_url, self.wsdl_url)
        session = requests.Session()
        session.mount('https://', requests.adapters.HTTPAdapter(
            pool_connections=pool_maxsize, pool_maxsize=pool_maxsize,
            pool_block=pool_block))
        session.mount('file:///', LocalFileAdapter(pool_maxsize=pool_maxsize))
        session.verify = cacert if cacert else not insecure

        cache = InMemoryCache(CACHE_TIMEOUT)

        transport = \
            zeep.transports.Transport(session=session,
                                      operation_timeout=connection_timeout,
                                      cache=cache)

        plugins = [PruneEmptyNodesPlugin(), AddAnyTypeTypeAttributePlugin()]

        self.client = CompatibilityZeepClient(self.wsdl_url,
                                              transport=transport,
                                              soap_url=self.soap_url,
                                              plugins=plugins)

        self._service_content = None
        self._vc_session_cookie = None

    @staticmethod
    def build_base_url(protocol, host, port):
        proto_str = '%s://' % protocol
        host_str = '[%s]' % host if netaddr.valid_ipv6(host) else host
        port_str = '' if port is None else ':%d' % port
        return proto_str + host_str + port_str

    @staticmethod
    def _retrieve_properties_ex_fault_checker(response):
        """Checks the RetrievePropertiesEx API response for errors.

        Certain faults are sent in the SOAP body as a property of missingSet.
        This method raises VimFaultException when a fault is found in the
        response.

        :param response: response from RetrievePropertiesEx API call
        :raises: VimFaultException
        """
        fault_list = []
        details = {}
        if not response:
            # This is the case when the session has timed out. ESX SOAP
            # server sends an empty RetrievePropertiesExResponse. Normally
            # missingSet in the response objects has the specifics about
            # the error, but that's not the case with a timed out idle
            # session. It is as bad as a terminated session for we cannot
            # use the session. Therefore setting fault to NotAuthenticated
            # fault.
            LOG.debug("RetrievePropertiesEx API response is empty; setting "
                      "fault to %s.",
                      exceptions.NOT_AUTHENTICATED)
            fault_list = [exceptions.NOT_AUTHENTICATED]
        else:
            for obj_cont in response.objects:
                if hasattr(obj_cont, 'missingSet'):
                    for missing_elem in obj_cont.missingSet:
                        f_type = missing_elem.fault.fault
                        f_name = f_type.__class__.__name__
                        fault_list.append(f_name)
                        if f_name == exceptions.NO_PERMISSION:
                            details['object'] = \
                                vim_util.get_moref_value(f_type.object)
                            details['privilegeId'] = f_type.privilegeId

        if fault_list:
            fault_string = _("Error occurred while calling "
                             "RetrievePropertiesEx.")
            raise exceptions.VimFaultException(fault_list,
                                               fault_string,
                                               details=details)

    def _set_soap_headers(self, op_id):
        """Set SOAP headers for the next remote call to vCenter.

        SOAP headers may include operation ID and vcSessionCookie.
        The operation ID is a random string which allows to correlate log
        messages across different systems (OpenStack, vCenter, ESX).
        vcSessionCookie is needed when making PBM calls.
        """
        headers = []
        if self._vc_session_cookie:
            elem = etree.Element('vcSessionCookie')
            elem.text = self._vc_session_cookie
            headers.append(elem)
        if op_id:
            elem = etree.Element('operationID')
            elem.text = op_id
            headers.append(elem)
        return headers

    @property
    def service_content(self):
        if self._service_content is None:
            self._service_content = self.retrieve_service_content()
        return self._service_content

    def get_http_cookie(self):
        """Return the vCenter session cookie."""
        cookies = self.client.cookiejar
        for cookie in cookies:
            if cookie.name.lower() == 'vmware_soap_session':
                return cookie.value

    def __getattr__(self, attr_name):
        """Returns the method to invoke API identified by param attr_name."""

        def request_handler(managed_object, **kwargs):
            """Handler for vSphere API calls.

            Invokes the API and parses the response for fault checking and
            other errors.

            :param managed_object: managed object reference argument of the
                                   API call
            :param kwargs: keyword arguments of the API call
            :returns: response of the API call
            :raises: VimException, VimFaultException, VimAttributeException,
                     VimSessionOverLoadException, VimConnectionException
            """
            try:
                if isinstance(managed_object, str):
                    # For strings, use string value for value and type
                    # of the managed object.
                    managed_object = vim_util.get_moref(managed_object,
                                                        managed_object)
                if managed_object is None:
                    return

                skip_op_id = kwargs.pop('skip_op_id', False)
                op_id = None
                if not skip_op_id:
                    # Generate opID. It will appear in vCenter and ESX logs for
                    # this particular remote call.
                    op_id = '%s-%s' % (self.op_id_prefix,
                                       uuidutils.generate_uuid())
                    LOG.debug('Invoking %s.%s with opID=%s',
                              vim_util.get_moref_type(managed_object),
                              attr_name,
                              op_id)
                headers = self._set_soap_headers(op_id)
                if headers:
                    kwargs['_soapheaders'] = headers
                request = getattr(self.client.service, attr_name)
                response = request(managed_object, **kwargs)
                if (attr_name.lower() == 'retrievepropertiesex'):
                    Service._retrieve_properties_ex_fault_checker(response)
                return response
            except exceptions.VimFaultException:
                # Catch the VimFaultException that is raised by the fault
                # check of the SOAP response.
                raise

            except zeep.exceptions.Fault as excep:
                fault_string = None
                if excep.message:
                    fault_string = excep.message

                fault_list = []
                details = {}
                if excep.detail:
                    for fault in excep.detail.getchildren():
                        type_ns = '{' + fault.nsmap['xsi'] + '}'
                        fault_type = fault.get('{}type'.format(type_ns))
                        if fault_type.endswith(exceptions.SECURITY_ERROR):
                            fault_type = exceptions.NOT_AUTHENTICATED
                        fault_list.append(fault_type)
                        for child in fault.getchildren():
                            name = etree.QName(child.tag).localname
                            details[name] = child.text

                raise exceptions.VimFaultException(fault_list, fault_string,
                                                   excep, details)

            except AttributeError as excep:
                raise exceptions.VimAttributeException(
                    _("No such SOAP method %s.") % attr_name, excep)

            except (httplib.CannotSendRequest,
                    httplib.ResponseNotReady,
                    httplib.CannotSendHeader) as excep:
                raise exceptions.VimSessionOverLoadException(
                    _("httplib error in %s.") % attr_name, excep)

            except requests.RequestException as excep:
                raise exceptions.VimConnectionException(
                    _("requests error in %s.") % attr_name, excep)

            except Exception as excep:
                # TODO(vbala) should catch specific exceptions and raise
                # appropriate VimExceptions.

                # Socket errors which need special handling; some of these
                # might be caused by server API call overload.
                if (six.text_type(excep).find(ADDRESS_IN_USE_ERROR) != -1 or
                        six.text_type(excep).find(CONN_ABORT_ERROR)) != -1:
                    raise exceptions.VimSessionOverLoadException(
                        _("Socket error in %s.") % attr_name, excep)
                # Type error which needs special handling; it might be caused
                # by server API call overload.
                elif six.text_type(excep).find(RESP_NOT_XML_ERROR) != -1:
                    raise exceptions.VimSessionOverLoadException(
                        _("Type error in %s.") % attr_name, excep)
                else:
                    raise exceptions.VimException(
                        _("Exception in %s.") % attr_name, excep)
        return request_handler

    def __repr__(self):
        return "vSphere object"

    def __str__(self):
        return "vSphere object"
