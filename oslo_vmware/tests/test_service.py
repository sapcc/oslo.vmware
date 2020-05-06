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

import mock
import requests
import six
import six.moves.http_client as httplib
import zeep

import ddt
from lxml import etree
from oslo_vmware import exceptions
from oslo_vmware import service
from oslo_vmware.tests import base
from oslo_vmware import vim_util


def load_xml(xml):
    parser = etree.XMLParser(
        remove_blank_text=True, remove_comments=True, resolve_entities=False
    )
    return etree.fromstring(xml.strip(), parser=parser)


@ddt.ddt
class AddAnyTypeTypeAttributePluginTest(base.TestCase):
    """Test class for AddAnyTypeTypeAttributePlugin."""

    def setUp(self):
        super(AddAnyTypeTypeAttributePluginTest, self).setUp()
        self.plugin = service.AddAnyTypeTypeAttributePlugin()

    @ddt.data(('value', 'foo', 'string'),
              ('removeKey', 1, 'int'),
              ('removeKey', 'foo', 'string'),
              ('flavor', 'foo', None))
    @ddt.unpack
    def test_add_attribute_for_value(self, name, value, xsd_type):
        xml_str = '''
            <document xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <ns0:container xmlns:ns0="http://tests.python-zeep.org/">
                    <ns0:{} {}>{}</ns0:{}>
                </ns0:container>
            </document>
            '''
        xml = load_xml(xml_str.format(name, '', value, name))
        attr = 'xsi:type="xsd:{}"'.format(xsd_type) \
               if xsd_type is not None else ''
        xml_expected = load_xml(xml_str.format(name, attr, value, name))

        self.plugin._add_attribute_for_value(xml)
        self.assertEqual(etree.tostring(xml), etree.tostring(xml_expected))


@ddt.ddt
class PruneEmptyNodesPluginTest(base.TestCase):
    """Test class for PruneEmptyNodesPlugin."""

    def setUp(self):
        super(PruneEmptyNodesPluginTest, self).setUp()
        self.plugin = service.PruneEmptyNodesPlugin()

    @ddt.data(('<document></document>', True),
              ('<document path="foo"></document>', False),
              ('<document>foo</document>', False),
              ('<document><child /></document>', False),
              ('<document />', True),
              ('<document foo="bar" />', False))
    @ddt.unpack
    def test_isempty(self, xml_str, should_be_empty):
        xml = load_xml(xml_str)
        self.assertEqual(self.plugin._isempty(xml), should_be_empty, xml_str)

    @ddt.data(('<document><parent><child>foo</child><child2 />'
               '</parent></document>',
               '<document><parent><child>foo</child></parent></document>'),
              ('<document>text<parent><child /></parent></document>',
               '<document>text</document>'),
              ('<envelope><child /></envelope>',
               '<envelope/>'),
              ('<envelope><parent><VirtualMachineEmptyProfileSpec /></parent>'
               '<parent2 foo="bla"><child /></parent2></envelope>',
               '<envelope><parent><VirtualMachineEmptyProfileSpec/></parent>'
               '<parent2 foo="bla"/></envelope>'))
    @ddt.unpack
    def test_prune(self, xml_str, xml_str_expected):
        xml = load_xml(xml_str)
        self.plugin._prune(xml)
        self.assertEqual(etree.tostring(xml), xml_str_expected)


class ServiceTest(base.TestCase):

    def setUp(self):
        super(ServiceTest, self).setUp()
        patcher = mock.patch('oslo_vmware.service.CompatibilityZeepClient')
        self.addCleanup(patcher.stop)
        self.SudsClientMock = patcher.start()

    def test_retrieve_properties_ex_fault_checker_with_empty_response(self):
        ex = self.assertRaises(
            exceptions.VimFaultException,
            service.Service._retrieve_properties_ex_fault_checker,
            None)
        self.assertEqual([exceptions.NOT_AUTHENTICATED],
                         ex.fault_list)

    def test_retrieve_properties_ex_fault_checker(self):
        fault_list = ['FileFault', 'VimFault']
        missing_set = []
        for fault in fault_list:
            missing_elem = mock.Mock()
            missing_elem.fault.fault.__class__.__name__ = fault
            missing_set.append(missing_elem)
        obj_cont = mock.Mock()
        obj_cont.missingSet = missing_set
        response = mock.Mock()
        response.objects = [obj_cont]

        ex = self.assertRaises(
            exceptions.VimFaultException,
            service.Service._retrieve_properties_ex_fault_checker,
            response)
        self.assertEqual(fault_list, ex.fault_list)

    def test_request_handler(self):
        managed_object = 'VirtualMachine'
        resp = mock.Mock()

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))
            return resp

        svc_obj = service.Service()
        attr_name = 'powerOn'
        service_mock = svc_obj.client.service
        setattr(service_mock, attr_name, side_effect)
        ret = svc_obj.powerOn(managed_object)
        self.assertEqual(resp, ret)

    def test_request_handler_with_retrieve_properties_ex_fault(self):
        managed_object = 'Datacenter'

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))
            return None

        svc_obj = service.Service()
        attr_name = 'retrievePropertiesEx'
        service_mock = svc_obj.client.service
        setattr(service_mock, attr_name, side_effect)
        self.assertRaises(exceptions.VimFaultException,
                          svc_obj.retrievePropertiesEx,
                          managed_object)

    def test_request_handler_with_web_fault(self):
        managed_object = 'VirtualMachine'
        fault_list = ['Fault']

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))

            fault_children = mock.Mock()
            fault_children.tag = "name"
            fault_children.text = "value"
            child = mock.Mock()
            child.get.return_value = fault_list[0]
            child.nsmap = {'xsi': ''}
            child.getchildren.return_value = [fault_children]
            detail = mock.Mock()
            detail.getchildren.return_value = [child]
            raise zeep.exceptions.Fault(message="MyFault", detail=detail)

        svc_obj = service.Service()
        service_mock = svc_obj.client.service
        setattr(service_mock, 'powerOn', side_effect)

        ex = self.assertRaises(exceptions.VimFaultException, svc_obj.powerOn,
                               managed_object)

        self.assertEqual(fault_list, ex.fault_list)
        self.assertEqual({'name': 'value'}, ex.details)
        self.assertEqual("MyFault", ex.msg)

    def test_request_handler_with_empty_web_fault_doc(self):

        def side_effect(mo, **kwargs):
            raise zeep.exceptions.Fault(message="MyFault")

        svc_obj = service.Service()
        service_mock = svc_obj.client.service
        setattr(service_mock, 'powerOn', side_effect)

        ex = self.assertRaises(exceptions.VimFaultException,
                               svc_obj.powerOn,
                               'VirtualMachine')
        self.assertEqual([], ex.fault_list)
        self.assertEqual({}, ex.details)
        self.assertEqual("MyFault", ex.msg)

    def test_request_handler_with_vc51_web_fault(self):
        managed_object = 'VirtualMachine'
        fault_list = ['Fault']

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))

            fault_children = mock.Mock()
            fault_children.tag = "name"
            fault_children.text = "value"
            child = mock.Mock()
            child.get.return_value = fault_list[0]
            child.nsmap = {'xsi': ''}
            child.getchildren.return_value = [fault_children]
            detail = mock.Mock()
            detail.getchildren.return_value = [child]
            raise zeep.exceptions.Fault(message="MyFault", detail=detail)

        svc_obj = service.Service()
        service_mock = svc_obj.client.service
        setattr(service_mock, 'powerOn', side_effect)

        ex = self.assertRaises(exceptions.VimFaultException, svc_obj.powerOn,
                               managed_object)

        self.assertEqual(fault_list, ex.fault_list)
        self.assertEqual({'name': 'value'}, ex.details)
        self.assertEqual("MyFault", ex.msg)

    def test_request_handler_with_security_error(self):
        managed_object = 'VirtualMachine'

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))

            fault_children = mock.Mock()
            fault_children.tag = "name"
            fault_children.text = "value"
            child = mock.Mock()
            child.get.return_value = 'vim25:SecurityError'
            child.nsmap = {'xsi': ''}
            child.getchildren.return_value = [fault_children]
            detail = mock.Mock()
            detail.getchildren.return_value = [child]
            raise zeep.exceptions.Fault(message="MyFault", detail=detail)

        svc_obj = service.Service()
        service_mock = svc_obj.client.service
        setattr(service_mock, 'powerOn', side_effect)

        ex = self.assertRaises(exceptions.VimFaultException, svc_obj.powerOn,
                               managed_object)

        self.assertEqual([exceptions.NOT_AUTHENTICATED], ex.fault_list)
        self.assertEqual({'name': 'value'}, ex.details)
        self.assertEqual("MyFault", ex.msg)

    def test_request_handler_with_attribute_error(self):
        managed_object = 'VirtualMachine'
        svc_obj = service.Service()
        # no powerOn method in Service
        service_mock = mock.Mock(spec=service.Service)
        svc_obj.client.service = service_mock
        self.assertRaises(exceptions.VimAttributeException,
                          svc_obj.powerOn,
                          managed_object)

    def test_request_handler_with_http_cannot_send_error(self):
        managed_object = 'VirtualMachine'

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))
            raise httplib.CannotSendRequest()

        svc_obj = service.Service()
        attr_name = 'powerOn'
        service_mock = svc_obj.client.service
        setattr(service_mock, attr_name, side_effect)
        self.assertRaises(exceptions.VimSessionOverLoadException,
                          svc_obj.powerOn,
                          managed_object)

    def test_request_handler_with_http_response_not_ready_error(self):
        managed_object = 'VirtualMachine'

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))
            raise httplib.ResponseNotReady()

        svc_obj = service.Service()
        attr_name = 'powerOn'
        service_mock = svc_obj.client.service
        setattr(service_mock, attr_name, side_effect)
        self.assertRaises(exceptions.VimSessionOverLoadException,
                          svc_obj.powerOn,
                          managed_object)

    def test_request_handler_with_http_cannot_send_header_error(self):
        managed_object = 'VirtualMachine'

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))
            raise httplib.CannotSendHeader()

        svc_obj = service.Service()
        attr_name = 'powerOn'
        service_mock = svc_obj.client.service
        setattr(service_mock, attr_name, side_effect)
        self.assertRaises(exceptions.VimSessionOverLoadException,
                          svc_obj.powerOn,
                          managed_object)

    def test_request_handler_with_connection_error(self):
        managed_object = 'VirtualMachine'

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))
            raise requests.ConnectionError()

        svc_obj = service.Service()
        attr_name = 'powerOn'
        service_mock = svc_obj.client.service
        setattr(service_mock, attr_name, side_effect)
        self.assertRaises(exceptions.VimConnectionException,
                          svc_obj.powerOn,
                          managed_object)

    def test_request_handler_with_http_error(self):
        managed_object = 'VirtualMachine'

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))
            raise requests.HTTPError()

        svc_obj = service.Service()
        attr_name = 'powerOn'
        service_mock = svc_obj.client.service
        setattr(service_mock, attr_name, side_effect)
        self.assertRaises(exceptions.VimConnectionException,
                          svc_obj.powerOn,
                          managed_object)

    @mock.patch.object(vim_util, 'get_moref', return_value=None)
    def test_request_handler_no_value(self, mock_moref):
        managed_object = 'VirtualMachine'
        svc_obj = service.Service()
        ret = svc_obj.UnregisterVM(managed_object)
        self.assertIsNone(ret)

    def _test_request_handler_with_exception(self, message, exception):
        managed_object = 'VirtualMachine'

        def side_effect(mo, **kwargs):
            self.assertEqual(managed_object, vim_util.get_moref_type(mo))
            self.assertEqual(managed_object, vim_util.get_moref_value(mo))
            raise Exception(message)

        svc_obj = service.Service()
        attr_name = 'powerOn'
        service_mock = svc_obj.client.service
        setattr(service_mock, attr_name, side_effect)
        self.assertRaises(exception, svc_obj.powerOn, managed_object)

    def test_request_handler_with_address_in_use_error(self):
        self._test_request_handler_with_exception(
            service.ADDRESS_IN_USE_ERROR,
            exceptions.VimSessionOverLoadException)

    def test_request_handler_with_conn_abort_error(self):
        self._test_request_handler_with_exception(
            service.CONN_ABORT_ERROR, exceptions.VimSessionOverLoadException)

    def test_request_handler_with_resp_not_xml_error(self):
        self._test_request_handler_with_exception(
            service.RESP_NOT_XML_ERROR, exceptions.VimSessionOverLoadException)

    def test_request_handler_with_generic_error(self):
        self._test_request_handler_with_exception(
            'GENERIC_ERROR', exceptions.VimException)

    def test_get_session_cookie(self):
        svc_obj = service.Service()
        cookie_value = 'xyz'
        cookie = mock.Mock()
        cookie.name = 'vmware_soap_session'
        cookie.value = cookie_value
        svc_obj.client.cookiejar = [cookie]
        self.assertEqual(cookie_value, svc_obj.get_http_cookie())

    def test_get_session_cookie_with_no_cookie(self):
        svc_obj = service.Service()
        cookie = mock.Mock()
        cookie.name = 'cookie'
        cookie.value = 'xyz'
        svc_obj.client.cookiejar = [cookie]
        self.assertIsNone(svc_obj.get_http_cookie())

    def test_set_soap_headers(self):
        def fake_set_options(*args, **kwargs):
            headers = kwargs['soapheaders']
            self.assertEqual(1, len(headers))
            txt = headers[0].getText()
            self.assertEqual('fira-12345', txt)

        svc_obj = service.Service()
        svc_obj.client.options.soapheaders = None
        setattr(svc_obj.client, 'set_options', fake_set_options)
        svc_obj._set_soap_headers('fira-12345')

    def test_soap_headers_pbm(self):
        def fake_set_options(*args, **kwargs):
            headers = kwargs['soapheaders']
            self.assertEqual(2, len(headers))
            self.assertEqual('vc-session-cookie', headers[0].getText())
            self.assertEqual('fira-12345', headers[1].getText())

        svc_obj = service.Service()
        svc_obj._vc_session_cookie = 'vc-session-cookie'
        setattr(svc_obj.client, 'set_options', fake_set_options)
        svc_obj._set_soap_headers('fira-12345')


class TransportTest(base.TestCase):
    """Tests for LocalFileAdapter and Transport parameters."""
    def setUp(self):
        super(TransportTest, self).setUp()

        def new_client_init(self, url, **kwargs):
            self.transport = kwargs['transport']
            return

        mock.patch.object(service.CompatibilityZeepClient,
                          '__init__', new=new_client_init).start()
        self.addCleanup(mock.patch.stopall)

    def test_set_conn_pool_size(self):
        transport = service.Service(pool_maxsize=100).client.transport

        local_file_adapter = transport.session.adapters['file:///']
        self.assertEqual(100, local_file_adapter._pool_connections)
        self.assertEqual(100, local_file_adapter._pool_maxsize)
        https_adapter = transport.session.adapters['https://']
        self.assertEqual(100, https_adapter._pool_connections)
        self.assertEqual(100, https_adapter._pool_maxsize)

    @mock.patch('os.path.getsize')
    def test_send_with_local_file_url(self, get_size_mock):
        transport = service.Service(pool_maxsize=100).client.transport

        url = 'file:///foo'
        request = requests.PreparedRequest()
        request.url = url

        data = b"Hello World"
        get_size_mock.return_value = len(data)

        def readinto_mock(buf):
            buf[0:] = data

        if six.PY3:
            builtin_open = 'builtins.open'
            open_mock = mock.MagicMock(name='file_handle',
                                       spec=open)
            import _io
            file_spec = list(set(dir(_io.TextIOWrapper)).union(
                set(dir(_io.BytesIO))))
        else:
            builtin_open = '__builtin__.open'
            open_mock = mock.MagicMock(name='file_handle',
                                       spec=file)
            file_spec = file

        file_handle = mock.MagicMock(spec=file_spec)
        file_handle.write.return_value = None
        file_handle.__enter__.return_value = file_handle
        file_handle.readinto.side_effect = readinto_mock
        open_mock.return_value = file_handle

        with mock.patch(builtin_open, open_mock, create=True):
            resp = transport.session.send(request)
            self.assertEqual(data, resp.content)

    def test_send_with_connection_timeout(self):
        transport = service.Service(connection_timeout=120).client.transport

        with mock.patch.object(transport.session, "post") as mock_post:
            transport.post(mock.sentinel.url, mock.sentinel.message,
                           mock.sentinel.req_headers)
            mock_post.assert_called_once_with(
                mock.sentinel.url,
                data=mock.sentinel.message,
                headers=mock.sentinel.req_headers,
                timeout=120)
