# coding=utf-8
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

"""Unit tests for session management and API invocation classes."""

from concurrent import futures
from datetime import datetime
import gc
from unittest import mock
import weakref

from eventlet import greenthread
from oslo_context import context
import suds

from oslo_vmware import api
from oslo_vmware import exceptions
from oslo_vmware import pbm
from oslo_vmware.tests import base
from oslo_vmware import vim_util


class RetryDecoratorTest(base.TestCase):
    """Tests for retry decorator class."""

    def test_retry(self):
        result = "RESULT"

        @api.RetryDecorator()
        def func(*args, **kwargs):
            return result

        self.assertEqual(result, func())

        def func2(*args, **kwargs):
            return result

        retry = api.RetryDecorator()
        self.assertEqual(result, retry(func2)())
        self.assertTrue(retry._retry_count == 0)

    def test_retry_with_expected_exceptions(self):
        result = "RESULT"
        responses = [exceptions.VimSessionOverLoadException(None),
                     exceptions.VimSessionOverLoadException(None),
                     result]

        def func(*args, **kwargs):
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        sleep_time_incr = 0.01
        retry_count = 2
        retry = api.RetryDecorator(10, sleep_time_incr, 10,
                                   (exceptions.VimSessionOverLoadException,))
        self.assertEqual(result, retry(func)())
        self.assertTrue(retry._retry_count == retry_count)
        self.assertEqual(retry_count * sleep_time_incr, retry._sleep_time)

    def test_retry_with_max_retries(self):
        responses = [exceptions.VimSessionOverLoadException(None),
                     exceptions.VimSessionOverLoadException(None),
                     exceptions.VimSessionOverLoadException(None)]

        def func(*args, **kwargs):
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        retry = api.RetryDecorator(2, 0, 0,
                                   (exceptions.VimSessionOverLoadException,))
        self.assertRaises(exceptions.VimSessionOverLoadException, retry(func))
        self.assertTrue(retry._retry_count == 2)

    def test_retry_with_unexpected_exception(self):

        def func(*args, **kwargs):
            raise exceptions.VimException(None)

        retry = api.RetryDecorator()
        self.assertRaises(exceptions.VimException, retry(func))
        self.assertTrue(retry._retry_count == 0)


class VMwareAPISessionTest(base.TestCase):
    """Tests for VMwareAPISession."""

    SERVER_IP = '10.1.2.3'
    PORT = 443
    USERNAME = 'admin'
    PASSWORD = 'password'  # nosec
    POOL_SIZE = 15

    def setUp(self):
        super(VMwareAPISessionTest, self).setUp()
        patcher = mock.patch('oslo_vmware.vim.Vim')
        self.addCleanup(patcher.stop)
        self.VimMock = patcher.start()
        self.VimMock.side_effect = lambda *args, **kw: mock.MagicMock()
        self.cert_mock = mock.Mock()

    def _create_api_session(self, _create_session, retry_count=10,
                            task_poll_interval=1, **kwargs):
        return api.VMwareAPISession(VMwareAPISessionTest.SERVER_IP,
                                    VMwareAPISessionTest.USERNAME,
                                    VMwareAPISessionTest.PASSWORD,
                                    retry_count,
                                    task_poll_interval,
                                    'https',
                                    _create_session,
                                    port=VMwareAPISessionTest.PORT,
                                    cacert=self.cert_mock,
                                    insecure=False,
                                    pool_size=VMwareAPISessionTest.POOL_SIZE,
                                    **kwargs)

    def test_vim(self):
        api_session = self._create_api_session(False)
        api_session.vim
        self.VimMock.assert_called_with(
            protocol=api_session._scheme,
            host=VMwareAPISessionTest.SERVER_IP,
            port=VMwareAPISessionTest.PORT,
            wsdl_url=api_session._vim_wsdl_loc,
            cacert=self.cert_mock,
            insecure=False,
            pool_maxsize=VMwareAPISessionTest.POOL_SIZE,
            connection_timeout=None,
            op_id_prefix='oslo.vmware')

    @mock.patch.object(pbm, 'Pbm')
    def test_pbm(self, pbm_mock):
        api_session = self._create_api_session(True)
        vim_obj = api_session.vim
        cookie = mock.Mock()
        vim_obj.get_http_cookie.return_value = cookie
        api_session._pbm_wsdl_loc = mock.Mock()

        pbm = mock.Mock()
        pbm_mock.return_value = pbm
        api_session._get_session_cookie = mock.Mock(return_value=cookie)

        self.assertEqual(pbm, api_session.pbm)
        pbm.set_soap_cookie.assert_called_once_with(cookie)

    def test_create_session(self):
        session = mock.Mock()
        session.key = "12345"
        api_session = self._create_api_session(False)
        cookie = mock.Mock()
        vim_obj = api_session.vim
        vim_obj.Login.return_value = session
        vim_obj.get_http_cookie.return_value = cookie

        pbm = mock.Mock()
        api_session._pbm = pbm

        api_session._create_session()
        session_manager = vim_obj.service_content.sessionManager
        vim_obj.Login.assert_called_once_with(
            session_manager, userName=VMwareAPISessionTest.USERNAME,
            password=VMwareAPISessionTest.PASSWORD, locale='en')
        self.assertFalse(vim_obj.TerminateSession.called)
        self.assertEqual(session.key, api_session._session_id)
        pbm.set_soap_cookie.assert_called_once_with(cookie)

    def test_create_session_with_existing_inactive_session(self):
        old_session_key = '12345'
        new_session_key = '67890'
        session = mock.Mock()
        session.key = new_session_key
        api_session = self._create_api_session(False)
        api_session._session_id = old_session_key
        api_session._session_username = api_session._server_username
        vim_obj = api_session.vim
        vim_obj.Login.return_value = session
        vim_obj.SessionIsActive.return_value = False

        api_session._create_session()
        session_manager = vim_obj.service_content.sessionManager
        vim_obj.SessionIsActive.assert_called_once_with(
            session_manager, sessionID=old_session_key,
            userName=VMwareAPISessionTest.USERNAME)
        vim_obj.Login.assert_called_once_with(
            session_manager, userName=VMwareAPISessionTest.USERNAME,
            password=VMwareAPISessionTest.PASSWORD, locale='en')
        self.assertEqual(new_session_key, api_session._session_id)

    def test_create_session_with_existing_active_session(self):
        old_session_key = '12345'
        api_session = self._create_api_session(False)
        api_session._session_id = old_session_key
        api_session._session_username = api_session._server_username
        vim_obj = api_session.vim
        vim_obj.SessionIsActive.return_value = True

        api_session._create_session()
        session_manager = vim_obj.service_content.sessionManager
        vim_obj.SessionIsActive.assert_called_once_with(
            session_manager, sessionID=old_session_key,
            userName=VMwareAPISessionTest.USERNAME)
        self.assertFalse(vim_obj.Login.called)
        self.assertEqual(old_session_key, api_session._session_id)

    def test_invoke_api(self):
        api_session = self._create_api_session(True)
        response = mock.Mock()

        def api(*args, **kwargs):
            return response

        module = mock.Mock()
        module.api = api
        ret = api_session.invoke_api(module, 'api')
        self.assertEqual(response, ret)

    def test_logout_with_exception(self):
        session = mock.Mock()
        session.key = "12345"
        api_session = self._create_api_session(False)
        vim_obj = api_session.vim
        vim_obj.Login.return_value = session
        vim_obj.Logout.side_effect = exceptions.VimFaultException([], None)
        api_session._create_session()
        api_session.logout()
        self.assertEqual("12345", api_session._session_id)

    def test_logout_no_session(self):
        api_session = self._create_api_session(False)
        vim_obj = api_session.vim
        api_session.logout()
        self.assertEqual(0, vim_obj.Logout.call_count)

    def test_logout_calls_vim_logout(self):
        session = mock.Mock()
        session.key = "12345"
        api_session = self._create_api_session(False)
        vim_obj = api_session.vim
        vim_obj.Login.return_value = session
        vim_obj.Logout.return_value = None

        api_session._create_session()
        session_manager = vim_obj.service_content.sessionManager
        vim_obj.Login.assert_called_once_with(
            session_manager, userName=VMwareAPISessionTest.USERNAME,
            password=VMwareAPISessionTest.PASSWORD, locale='en')
        api_session.logout()
        vim_obj.Logout.assert_called_once_with(
            session_manager)
        self.assertIsNone(api_session._session_id)

    def test_invoke_api_with_expected_exception(self):
        api_session = self._create_api_session(True)
        api_session._create_session = mock.Mock()
        vim_obj = api_session.vim
        vim_obj.SessionIsActive.return_value = False
        ret = mock.Mock()
        responses = [exceptions.VimConnectionException(None), ret]

        def api(*args, **kwargs):
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        module = mock.Mock()
        module.api = api
        with mock.patch.object(greenthread, 'sleep'):
            self.assertEqual(ret, api_session.invoke_api(module, 'api'))
        api_session._create_session.assert_called_once_with()

    def test_invoke_api_not_recreate_session(self):
        api_session = self._create_api_session(True)
        api_session._create_session = mock.Mock()
        vim_obj = api_session.vim
        vim_obj.SessionIsActive.return_value = True
        ret = mock.Mock()
        responses = [exceptions.VimConnectionException(None), ret]

        def api(*args, **kwargs):
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        module = mock.Mock()
        module.api = api
        with mock.patch.object(greenthread, 'sleep'):
            self.assertEqual(ret, api_session.invoke_api(module, 'api'))
        self.assertFalse(api_session._create_session.called)

    def test_invoke_api_with_vim_fault_exception(self):
        api_session = self._create_api_session(True)

        def api(*args, **kwargs):
            raise exceptions.VimFaultException([], None)

        module = mock.Mock()
        module.api = api
        self.assertRaises(exceptions.VimFaultException,
                          api_session.invoke_api,
                          module,
                          'api')

    def test_invoke_api_with_vim_fault_exception_details(self):
        api_session = self._create_api_session(True)
        fault_string = 'Invalid property.'
        fault_list = [exceptions.INVALID_PROPERTY]
        details = {u'name': suds.sax.text.Text(u'фира')}

        module = mock.Mock()
        module.api.side_effect = exceptions.VimFaultException(fault_list,
                                                              fault_string,
                                                              details=details)
        e = self.assertRaises(exceptions.InvalidPropertyException,
                              api_session.invoke_api,
                              module,
                              'api')
        details_str = u"{'name': 'фира'}"
        expected_str = "%s\nFaults: %s\nDetails: %s" % (fault_string,
                                                        fault_list,
                                                        details_str)
        self.assertEqual(expected_str, str(e))
        self.assertEqual(details, e.details)

    def test_invoke_api_with_empty_response(self):
        api_session = self._create_api_session(True)
        vim_obj = api_session.vim
        vim_obj.SessionIsActive.return_value = True

        def api(*args, **kwargs):
            raise exceptions.VimFaultException(
                [exceptions.NOT_AUTHENTICATED], None)

        module = mock.Mock()
        module.api = api
        ret = api_session.invoke_api(module, 'api')
        self.assertEqual([], ret)
        vim_obj.SessionIsActive.assert_called_once_with(
            vim_obj.service_content.sessionManager,
            sessionID=api_session._session_id,
            userName=api_session._session_username)

    def test_invoke_api_with_stale_session(self):
        api_session = self._create_api_session(True)
        api_session._create_session = mock.Mock()
        vim_obj = api_session.vim
        vim_obj.SessionIsActive.return_value = False
        result = mock.Mock()
        responses = [exceptions.VimFaultException(
            [exceptions.NOT_AUTHENTICATED], None), result]

        def api(*args, **kwargs):
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        module = mock.Mock()
        module.api = api
        with mock.patch.object(greenthread, 'sleep'):
            ret = api_session.invoke_api(module, 'api')
        self.assertEqual(result, ret)
        vim_obj.SessionIsActive.assert_called_once_with(
            vim_obj.service_content.sessionManager,
            sessionID=api_session._session_id,
            userName=api_session._session_username)
        api_session._create_session.assert_called_once_with()

    def test_invoke_api_with_unknown_fault(self):
        api_session = self._create_api_session(True)
        fault_list = ['NotAFile']

        module = mock.Mock()
        module.api.side_effect = exceptions.VimFaultException(fault_list,
                                                              'Not a file.')
        ex = self.assertRaises(exceptions.VimFaultException,
                               api_session.invoke_api,
                               module,
                               'api')
        self.assertEqual(fault_list, ex.fault_list)

    @mock.patch.object(context, 'get_current')
    def test_wait_for_task(self, mock_curr_ctx):
        ctx = mock.Mock()
        mock_curr_ctx.return_value = ctx
        api_session = self._create_api_session(True)
        task_info_list = [('queued', 0), ('running', 40), ('success', 100)]
        task_info_list_size = len(task_info_list)

        def invoke_api_side_effect(module, method, *args, **kwargs):
            (state, progress) = task_info_list.pop(0)
            task_info = mock.Mock()
            task_info.progress = progress
            task_info.queueTime = datetime(2016, 12, 6, 15, 29, 43, 79060)
            task_info.completeTime = datetime(2016, 12, 6, 15, 29, 50, 79060)
            task_info.state = state
            return task_info

        api_session.invoke_api = mock.Mock(side_effect=invoke_api_side_effect)
        task = mock.Mock()
        with mock.patch.object(greenthread, 'sleep'):
            ret = api_session.wait_for_task(task)
            self.assertEqual('success', ret.state)
            self.assertEqual(100, ret.progress)
        api_session.invoke_api.assert_called_with(vim_util,
                                                  'get_object_property',
                                                  api_session.vim, task,
                                                  'info',
                                                  skip_op_id=True)
        self.assertEqual(task_info_list_size,
                         api_session.invoke_api.call_count)
        mock_curr_ctx.assert_called_once()
        self.assertEqual(3, ctx.update_store.call_count)

    @mock.patch.object(context, 'get_current', return_value=None)
    def test_wait_for_task_no_ctx(self, mock_curr_ctx):
        api_session = self._create_api_session(True)
        task_info_list = [('queued', 0), ('running', 40), ('success', 100)]
        task_info_list_size = len(task_info_list)

        def invoke_api_side_effect(module, method, *args, **kwargs):
            (state, progress) = task_info_list.pop(0)
            task_info = mock.Mock()
            task_info.progress = progress
            task_info.queueTime = datetime(2016, 12, 6, 15, 29, 43, 79060)
            task_info.completeTime = datetime(2016, 12, 6, 15, 29, 50, 79060)
            task_info.state = state
            return task_info

        api_session.invoke_api = mock.Mock(side_effect=invoke_api_side_effect)
        task = mock.Mock()
        with mock.patch.object(greenthread, 'sleep'):
            ret = api_session.wait_for_task(task)
            self.assertEqual('success', ret.state)
            self.assertEqual(100, ret.progress)
        api_session.invoke_api.assert_called_with(vim_util,
                                                  'get_object_property',
                                                  api_session.vim, task,
                                                  'info',
                                                  skip_op_id=True)
        self.assertEqual(task_info_list_size,
                         api_session.invoke_api.call_count)
        mock_curr_ctx.assert_called_once()

    @mock.patch.object(context, 'get_current')
    def test_wait_for_task_with_error_state(self, mock_curr_ctx):
        api_session = self._create_api_session(True)
        task_info_list = [('queued', 0), ('running', 40), ('error', -1)]
        task_info_list_size = len(task_info_list)

        def invoke_api_side_effect(module, method, *args, **kwargs):
            (state, progress) = task_info_list.pop(0)
            task_info = mock.Mock()
            task_info.progress = progress
            task_info.state = state
            return task_info

        api_session.invoke_api = mock.Mock(side_effect=invoke_api_side_effect)
        task = mock.Mock()
        with mock.patch.object(greenthread, 'sleep'):
            self.assertRaises(exceptions.VimFaultException,
                              api_session.wait_for_task,
                              task)
        api_session.invoke_api.assert_called_with(vim_util,
                                                  'get_object_property',
                                                  api_session.vim, task,
                                                  'info',
                                                  skip_op_id=True)
        self.assertEqual(task_info_list_size,
                         api_session.invoke_api.call_count)
        mock_curr_ctx.assert_called_once()

    @mock.patch.object(context, 'get_current')
    def test_wait_for_task_with_invoke_api_exception(self, mock_curr_ctx):
        api_session = self._create_api_session(True)
        api_session.invoke_api = mock.Mock(
            side_effect=exceptions.VimException(None))
        task = mock.Mock()
        with mock.patch.object(greenthread, 'sleep'):
            self.assertRaises(exceptions.VimException,
                              api_session.wait_for_task,
                              task)
        api_session.invoke_api.assert_called_once_with(vim_util,
                                                       'get_object_property',
                                                       api_session.vim, task,
                                                       'info',
                                                       skip_op_id=True)
        mock_curr_ctx.assert_called_once()

    def test_wait_for_lease_ready(self):
        api_session = self._create_api_session(True)
        lease_states = ['initializing', 'ready']
        num_states = len(lease_states)

        def invoke_api_side_effect(module, method, *args, **kwargs):
            return lease_states.pop(0)

        api_session.invoke_api = mock.Mock(side_effect=invoke_api_side_effect)
        lease = mock.Mock()
        with mock.patch.object(greenthread, 'sleep'):
            api_session.wait_for_lease_ready(lease)
        api_session.invoke_api.assert_called_with(vim_util,
                                                  'get_object_property',
                                                  api_session.vim, lease,
                                                  'state',
                                                  skip_op_id=True)
        self.assertEqual(num_states, api_session.invoke_api.call_count)

    def test_wait_for_lease_ready_with_error_state(self):
        api_session = self._create_api_session(True)
        responses = ['initializing', 'error', 'error_msg']

        def invoke_api_side_effect(module, method, *args, **kwargs):
            return responses.pop(0)

        api_session.invoke_api = mock.Mock(side_effect=invoke_api_side_effect)
        lease = mock.Mock()
        with mock.patch.object(greenthread, 'sleep'):
            self.assertRaises(exceptions.VimException,
                              api_session.wait_for_lease_ready,
                              lease)
        exp_calls = [mock.call(vim_util, 'get_object_property',
                               api_session.vim, lease, 'state',
                               skip_op_id=True)] * 2
        exp_calls.append(mock.call(vim_util, 'get_object_property',
                                   api_session.vim, lease, 'error'))
        self.assertEqual(exp_calls, api_session.invoke_api.call_args_list)

    def test_wait_for_lease_ready_with_unknown_state(self):
        api_session = self._create_api_session(True)

        def invoke_api_side_effect(module, method, *args, **kwargs):
            return 'unknown'

        api_session.invoke_api = mock.Mock(side_effect=invoke_api_side_effect)
        lease = mock.Mock()
        self.assertRaises(exceptions.VimException,
                          api_session.wait_for_lease_ready,
                          lease)
        api_session.invoke_api.assert_called_once_with(vim_util,
                                                       'get_object_property',
                                                       api_session.vim,
                                                       lease, 'state',
                                                       skip_op_id=True)

    def test_wait_for_lease_ready_with_invoke_api_exception(self):
        api_session = self._create_api_session(True)
        api_session.invoke_api = mock.Mock(
            side_effect=exceptions.VimException(None))
        lease = mock.Mock()
        self.assertRaises(exceptions.VimException,
                          api_session.wait_for_lease_ready,
                          lease)
        api_session.invoke_api.assert_called_once_with(
            vim_util, 'get_object_property', api_session.vim, lease,
            'state', skip_op_id=True)

    def _poll_task_well_known_exceptions(self, fault,
                                         expected_exception):
        api_session = self._create_api_session(False)

        def fake_invoke_api(self, module, method, *args, **kwargs):
            task_info = mock.Mock()
            task_info.progress = -1
            task_info.state = 'error'
            error = mock.Mock()
            error.localizedMessage = "Error message"
            error_fault = mock.Mock()
            error_fault.__class__.__name__ = fault
            error.fault = error_fault
            task_info.error = error
            return task_info

        with (
            mock.patch.object(api_session, 'invoke_api', fake_invoke_api)
        ):
            fake_task = vim_util.get_moref('Task', 'task-1')
            ctx = mock.Mock()
            self.assertRaises(expected_exception,
                              api_session._poll_task,
                              fake_task,
                              ctx)

    def test_poll_task_well_known_exceptions(self):
        for k, v in exceptions._fault_classes_registry.items():
            self._poll_task_well_known_exceptions(k, v)

    def test_poll_task_unknown_exception(self):
        _unknown_exceptions = {
            'NotAFile': exceptions.VimFaultException,
            'RuntimeFault': exceptions.VimFaultException
        }

        for k, v in _unknown_exceptions.items():
            self._poll_task_well_known_exceptions(k, v)

    def test_update_pbm_wsdl_loc(self):
        session = mock.Mock()
        session.key = "12345"
        api_session = self._create_api_session(False)
        self.assertIsNone(api_session._pbm_wsdl_loc)
        api_session.pbm_wsdl_loc_set('fake_wsdl')
        self.assertEqual('fake_wsdl', api_session._pbm_wsdl_loc)

    def _make_task_info(self, state, **kwargs):
        kwargs.setdefault('completeTime', None)
        task_info = mock.Mock(state=state, **kwargs)
        task_info.name = 'TestTask'
        return task_info

    def _make_update_set(self, version, task_infos):
        """Build an UpdateSet like the one returned by WaitForUpdatesEx.

        :param version: property collector version of the update set
        :param task_infos: dict mapping task moref values to task infos
        """
        object_set = []
        for task_value, task_info in task_infos.items():
            change = mock.Mock(op='assign', val=task_info)
            change.name = 'info'
            obj_update = mock.Mock(obj=vim_util.get_moref(task_value, 'Task'),
                                   changeSet=[change])
            object_set.append(obj_update)
        return mock.Mock(version=version,
                         filterSet=[mock.Mock(objectSet=object_set)])

    def _create_property_collector_session(self, stop=True):
        api_session = self._create_api_session(
            False, use_property_collector_for_tasks=True)
        if stop:
            self.addCleanup(api_session._stop_property_collector_thread)
        vim_obj = api_session.vim
        vim_obj.CreatePropertyCollector.return_value = vim_util.get_moref(
            'session[1]', 'PropertyCollector')
        vim_obj.CreateFilter.return_value = vim_util.get_moref(
            'session[1]', 'PropertyFilter')
        return api_session

    def _submit_wait_for_task(self, api_session, task_value):
        """Call wait_for_task in a thread, so a hang fails the test."""
        executor = futures.ThreadPoolExecutor(max_workers=1)
        self.addCleanup(executor.shutdown, wait=False)
        return executor.submit(api_session.wait_for_task,
                               vim_util.get_moref(task_value, 'Task'))

    def _wait_for_updates_versions(self, api_session):
        return [call.kwargs['version'] for call in
                api_session.vim.WaitForUpdatesEx.call_args_list]

    def test_property_collector_thread_lifecycle(self):
        # Without the option there is no thread
        api_session = self._create_api_session(False)
        self.assertIsNone(api_session._property_collector_thread)

        # The thread is started in __init__ without a session; the
        # property collector is only created once a task arrives.
        api_session = self._create_property_collector_session(stop=False)
        vim_obj = api_session.vim
        thread = api_session._property_collector_thread
        self.assertTrue(thread.is_alive())
        self.assertTrue(thread.daemon)
        self.assertFalse(vim_obj.CreatePropertyCollector.called)
        self.assertFalse(api_session._property_collector_stopped.is_set())

        # Stopping the thread while it monitors a task fails the task
        vim_obj.WaitForUpdatesEx.return_value = None
        pending_tasks = api_session._pending_tasks

        def create_property_collector(pc):
            pending_tasks.put(None)
            return vim_util.get_moref('session[1]', 'PropertyCollector')

        vim_obj.CreatePropertyCollector.side_effect = (
            create_property_collector)
        result = self._submit_wait_for_task(api_session, 'task-1')
        ex = self.assertRaises(exceptions.VimException,
                               result.result, timeout=10)
        self.assertEqual("Property collector thread stopped.", str(ex))
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertTrue(api_session._property_collector_stopped.is_set())

        # Tasks submitted afterwards fail instead of waiting forever
        task = vim_util.get_moref('task-2', 'Task')
        ex = self.assertRaises(exceptions.VimException,
                               api_session.wait_for_task, task)
        self.assertEqual("Property collector thread is not running.",
                         str(ex))

        # Stopping is idempotent
        api_session._stop_property_collector_thread()
        self.assertIsNone(api_session._property_collector_thread)
        api_session._stop_property_collector_thread()

        # Dropping the session stops its thread: it must not keep the
        # session alive.
        api_session = self._create_property_collector_session(stop=False)
        thread = api_session._property_collector_thread
        session_ref = weakref.ref(api_session)
        del api_session
        gc.collect()
        self.assertIsNone(session_ref())
        thread.join(10)
        self.assertFalse(thread.is_alive())

    @mock.patch.object(context, 'get_current')
    def test_wait_for_task_with_property_collector(self, mock_curr_ctx):
        ctx = mock.Mock()
        mock_curr_ctx.return_value = ctx
        api_session = self._create_property_collector_session()
        vim_obj = api_session.vim
        collector = vim_obj.CreatePropertyCollector.return_value

        # A task progressing to success: the version of the collector is
        # carried over between calls, the filter is destroyed at the end.
        success = self._make_task_info(
            'success', progress=100,
            queueTime=datetime(2016, 12, 6, 15, 29, 43, 79060),
            completeTime=datetime(2016, 12, 6, 15, 29, 50, 79060))
        vim_obj.WaitForUpdatesEx.side_effect = [
            self._make_update_set(
                '1', {'task-1': self._make_task_info('queued', progress=0)}),
            self._make_update_set(
                '2', {'task-1': self._make_task_info('running',
                                                     progress=40)}),
            None,
            self._make_update_set('3', {'task-1': success}),
        ]
        result = self._submit_wait_for_task(api_session, 'task-1')
        self.assertEqual(success, result.result(timeout=10))

        vim_obj.CreatePropertyCollector.assert_called_once_with(
            vim_obj.service_content.propertyCollector)
        vim_obj.CreateFilter.assert_called_once_with(
            collector, spec=mock.ANY, partialUpdates=False)
        self.assertEqual(['', '1', '2', '2'],
                         self._wait_for_updates_versions(api_session))
        vim_obj.DestroyPropertyFilter.assert_called_once_with(
            vim_obj.CreateFilter.return_value)
        self.assertEqual(3, ctx.update_store.call_count)
        mock_curr_ctx.assert_called_once()

        # Several tasks are monitored at once with the same collector,
        # here one succeeding and one failing in the same update.
        filters = {
            'task-2': vim_util.get_moref('session[2]', 'PropertyFilter'),
            'task-3': vim_util.get_moref('session[3]', 'PropertyFilter'),
        }
        vim_obj.CreateFilter.side_effect = [filters['task-2'],
                                            filters['task-3']]
        error = mock.Mock(localizedMessage="Error message")
        error.fault.__class__.__name__ = 'RuntimeFault'
        task_infos = {'task-2': self._make_task_info('success'),
                      'task-3': self._make_task_info('error', error=error)}

        def wait_for_updates(pc, **kwargs):
            # Both filters have to exist before the update for both arrives
            if vim_obj.CreateFilter.call_count < 3:
                return None
            return self._make_update_set('4', task_infos)

        vim_obj.WaitForUpdatesEx.side_effect = wait_for_updates
        vim_obj.DestroyPropertyFilter.reset_mock()
        result_2 = self._submit_wait_for_task(api_session, 'task-2')
        result_3 = self._submit_wait_for_task(api_session, 'task-3')
        self.assertEqual(task_infos['task-2'], result_2.result(timeout=10))
        ex = self.assertRaises(exceptions.VimFaultException,
                               result_3.result, timeout=10)
        self.assertEqual(['RuntimeFault'], ex.fault_list)

        # The collector is kept across tasks
        vim_obj.CreatePropertyCollector.assert_called_once()
        self.assertFalse(vim_obj.DestroyPropertyCollector.called)
        self.assertEqual(3, vim_obj.CreateFilter.call_count)
        self.assertCountEqual(
            [mock.call(filters['task-2']), mock.call(filters['task-3'])],
            vim_obj.DestroyPropertyFilter.call_args_list)
        self.assertTrue(api_session._property_collector_thread.is_alive())

    def test_wait_for_task_with_property_collector_failures(self):
        api_session = self._create_property_collector_session()
        vim_obj = api_session.vim
        collectors = [
            vim_util.get_moref('session[%d]' % i, 'PropertyCollector')
            for i in range(1, 6)]
        vim_obj.CreatePropertyCollector.side_effect = collectors

        # A failing collector is created anew, along with the filter of
        # the running task, and the version starts over.
        success = self._make_task_info('success')
        vim_obj.WaitForUpdatesEx.side_effect = [
            self._make_update_set(
                '1', {'task-1': self._make_task_info('running')}),
            exceptions.VimException("Collector lost"),
            self._make_update_set('1', {'task-1': success}),
        ]
        result = self._submit_wait_for_task(api_session, 'task-1')
        self.assertEqual(success, result.result(timeout=10))

        vim_obj.DestroyPropertyCollector.assert_called_once_with(
            collectors[0])
        self.assertEqual(2, vim_obj.CreatePropertyCollector.call_count)
        self.assertEqual(
            [mock.call(collectors[0], spec=mock.ANY, partialUpdates=False),
             mock.call(collectors[1], spec=mock.ANY, partialUpdates=False)],
            vim_obj.CreateFilter.call_args_list)
        self.assertEqual(['', '1', ''],
                         self._wait_for_updates_versions(api_session))

        # A second consecutive failure fails the task with the error
        vim_obj.WaitForUpdatesEx.side_effect = exceptions.VimException(
            "Collector broken")
        result = self._submit_wait_for_task(api_session, 'task-2')
        ex = self.assertRaises(exceptions.VimException,
                               result.result, timeout=10)
        self.assertEqual("Collector broken", str(ex))
        # collectors[1] failed, collectors[2] was created and failed too
        self.assertEqual(3, vim_obj.CreatePropertyCollector.call_count)
        self.assertEqual(3, vim_obj.DestroyPropertyCollector.call_count)

        # A collector that cannot be created fails the task after a
        # second attempt
        vim_obj.CreatePropertyCollector.side_effect = (
            exceptions.VimFaultException([exceptions.NO_PERMISSION],
                                         "Not allowed"))
        result = self._submit_wait_for_task(api_session, 'task-3')
        self.assertRaises(exceptions.NoPermissionException,
                          result.result, timeout=10)
        self.assertEqual(5, vim_obj.CreatePropertyCollector.call_count)
        self.assertEqual(3, vim_obj.DestroyPropertyCollector.call_count)

        # A failing filter fails only its task. The collector is created
        # anew, as the failure may be due to a re-created session.
        vim_obj.CreatePropertyCollector.side_effect = collectors[3:]
        task_filter = vim_util.get_moref('session[5]', 'PropertyFilter')
        vim_obj.CreateFilter.side_effect = [
            exceptions.VimFaultException(
                [exceptions.MANAGED_OBJECT_NOT_FOUND], "No such task"),
            task_filter]
        vim_obj.WaitForUpdatesEx.side_effect = [
            self._make_update_set('1', {'task-5': success})]
        vim_obj.WaitForUpdatesEx.reset_mock()
        result = self._submit_wait_for_task(api_session, 'task-4')
        self.assertRaises(exceptions.ManagedObjectNotFoundException,
                          result.result, timeout=10)
        self.assertFalse(vim_obj.WaitForUpdatesEx.called)
        vim_obj.DestroyPropertyCollector.assert_called_with(collectors[3])

        # The thread keeps serving tasks after all of the above
        result = self._submit_wait_for_task(api_session, 'task-5')
        self.assertEqual(success, result.result(timeout=10))
        vim_obj.CreateFilter.assert_called_with(
            collectors[4], spec=mock.ANY, partialUpdates=False)
        vim_obj.DestroyPropertyFilter.assert_called_with(task_filter)
        self.assertTrue(api_session._property_collector_thread.is_alive())

    def test_process_task_updates(self):
        api_session = self._create_api_session(False)
        vim_obj = api_session.vim
        task_future = futures.Future()
        ctx = mock.Mock()
        task_filter = mock.Mock()
        running_tasks = {'task-1': (task_future, ctx, task_filter)}

        # Progress updates keep the task running
        api_session._process_task_updates(
            self._make_update_set(
                '1', {'task-1': self._make_task_info('running',
                                                     progress=40)}),
            running_tasks)
        self.assertFalse(task_future.done())
        self.assertIn('task-1', running_tasks)

        # Updates of tasks not monitored (anymore) are ignored
        api_session._process_task_updates(
            self._make_update_set(
                '2', {'task-2': self._make_task_info('success')}),
            running_tasks)
        self.assertFalse(task_future.done())

        # Updates without an info change are ignored
        update_set = self._make_update_set(
            '3', {'task-1': self._make_task_info('success')})
        update_set.filterSet[0].objectSet[0].changeSet[0].name = 'other'
        api_session._process_task_updates(update_set, running_tasks)
        self.assertFalse(task_future.done())

        # Success delivers the task info; a filter that cannot be
        # destroyed does not affect the task.
        vim_obj.DestroyPropertyFilter.side_effect = exceptions.VimException(
            "Cannot destroy")
        success = self._make_task_info(
            'success',
            queueTime=datetime(2016, 12, 6, 15, 29, 43),
            completeTime=datetime(2016, 12, 6, 15, 29, 50))
        api_session._process_task_updates(
            self._make_update_set('4', {'task-1': success}), running_tasks)
        self.assertEqual(success, task_future.result(timeout=0))
        self.assertEqual({}, running_tasks)
        self.assertEqual(2, ctx.update_store.call_count)
        vim_obj.DestroyPropertyFilter.assert_called_once_with(task_filter)

        # Errors are translated to the well-known exceptions, unknown
        # faults to VimFaultException. No context is fine, too.
        faults = dict(exceptions._fault_classes_registry)
        faults.update({'NotAFile': exceptions.VimFaultException,
                       'RuntimeFault': exceptions.VimFaultException})
        for fault, expected_exception in faults.items():
            task_future = futures.Future()
            running_tasks = {'task-1': (task_future, None, mock.Mock())}
            error = mock.Mock(localizedMessage="Error message")
            error.fault.__class__.__name__ = fault
            api_session._process_task_updates(
                self._make_update_set(
                    '5', {'task-1': self._make_task_info('error',
                                                         error=error)}),
                running_tasks)
            self.assertRaises(expected_exception, task_future.result,
                              timeout=0)
            self.assertEqual({}, running_tasks)
