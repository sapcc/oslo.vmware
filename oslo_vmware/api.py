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
Session and API call management for VMware ESX/VC server.

This module contains classes to invoke VIM APIs. It supports
automatic session re-establishment and retry of API invocations
in case of connection problems or server API call overload.
"""

from concurrent import futures
import logging
import queue
import threading

from oslo_concurrency import lockutils
from oslo_context import context
from oslo_utils import excutils
from oslo_utils import reflection

from oslo_vmware._i18n import _
from oslo_vmware.common import loopingcall
from oslo_vmware import exceptions
from oslo_vmware import pbm
from oslo_vmware import vim
from oslo_vmware import vim_util


LOG = logging.getLogger(__name__)


def _trunc_id(session_id):
    """Returns truncated session id which is suitable for logging."""
    if session_id is not None:
        return session_id[-5:]


# TODO(vbala) Move this class to excutils.py.
class RetryDecorator(object):
    """Decorator for retrying a function upon suggested exceptions.

    The decorated function is retried for the given number of times, and the
    sleep time between the retries is incremented until max sleep time is
    reached. If the max retry count is set to -1, then the decorated function
    is invoked indefinitely until an exception is thrown, and the caught
    exception is not in the list of suggested exceptions.
    """

    def __init__(self, max_retry_count=-1, inc_sleep_time=10,
                 max_sleep_time=60, exceptions=()):
        """Configure the retry object using the input params.

        :param max_retry_count: maximum number of times the given function must
                                be retried when one of the input 'exceptions'
                                is caught. When set to -1, it will be retried
                                indefinitely until an exception is thrown
                                and the caught exception is not in param
                                exceptions.
        :param inc_sleep_time: incremental time in seconds for sleep time
                               between retries
        :param max_sleep_time: max sleep time in seconds beyond which the sleep
                               time will not be incremented using param
                               inc_sleep_time. On reaching this threshold,
                               max_sleep_time will be used as the sleep time.
        :param exceptions: suggested exceptions for which the function must be
                           retried
        """
        self._max_retry_count = max_retry_count
        self._inc_sleep_time = inc_sleep_time
        self._max_sleep_time = max_sleep_time
        self._exceptions = exceptions
        self._retry_count = 0
        self._sleep_time = 0

    def __call__(self, f):
        func_name = reflection.get_callable_name(f)

        def _func(*args, **kwargs):
            result = None
            try:
                if self._retry_count:
                    LOG.debug("Invoking %(func_name)s; retry count is "
                              "%(retry_count)d.",
                              {'func_name': func_name,
                               'retry_count': self._retry_count})
                result = f(*args, **kwargs)
            except self._exceptions:
                with excutils.save_and_reraise_exception() as ctxt:
                    LOG.warning("Exception which is in the suggested list "
                                "of exceptions occurred while invoking "
                                "function: %s.",
                                func_name,
                                exc_info=True)
                    if (self._max_retry_count != -1 and
                            self._retry_count >= self._max_retry_count):
                        LOG.error("Cannot retry upon suggested exception "
                                  "since retry count (%(retry_count)d) "
                                  "reached max retry count "
                                  "(%(max_retry_count)d).",
                                  {'retry_count': self._retry_count,
                                   'max_retry_count': self._max_retry_count})
                    else:
                        ctxt.reraise = False
                        self._retry_count += 1
                        self._sleep_time += self._inc_sleep_time
                        return self._sleep_time
            raise loopingcall.LoopingCallDone(result)

        def func(*args, **kwargs):
            loop = loopingcall.DynamicLoopingCall(_func, *args, **kwargs)
            evt = loop.start(periodic_interval_max=self._max_sleep_time)
            return evt.wait()

        return func


class VMwareAPISession(object):
    """Setup a session with the server and handles all calls made to it.

    Example:
        api_session = VMwareAPISession('10.1.2.3', 'administrator',
                                       'password', 10, 0.1,
                                       create_session=False, port=443)
        result = api_session.invoke_api(vim_util, 'get_objects',
                                        api_session.vim, 'HostSystem', 100)
    """

    def __init__(self, host, server_username, server_password,
                 api_retry_count, task_poll_interval, scheme='https',
                 create_session=True, wsdl_loc=None, pbm_wsdl_loc=None,
                 port=443, cacert=None, insecure=True, pool_size=10,
                 connection_timeout=None, op_id_prefix='oslo.vmware',
                 use_property_collector_for_tasks=False):
        """Initializes the API session with given parameters.

        :param host: ESX/VC server IP address or host name
        :param port: port for connection
        :param server_username: username of ESX/VC server admin user
        :param server_password: password for param server_username
        :param api_retry_count: number of times an API must be retried upon
                                session/connection related errors
        :param task_poll_interval: sleep time in seconds for polling an
                                   on-going async task as part of the API call
        :param scheme: protocol-- http or https
        :param create_session: whether to setup a connection at the time of
                               instance creation
        :param wsdl_loc: VIM API WSDL file location
        :param pbm_wsdl_loc: PBM service WSDL file location
        :param cacert: Specify a CA bundle file to use in verifying a
                       TLS (https) server certificate.
        :param insecure: Verify HTTPS connections using system certificates,
                         used only if cacert is not specified
        :param pool_size: Maximum number of connections in http
                          connection pool
        :param connection_timeout: Maximum time in seconds to wait for peer to
                                   respond.
        :param op_id_prefix: String prefix for the operation ID.
        :param use_property_collector_for_tasks: Use WaitForUpdatesEx-based
                                                 property collector for
                                                 task monitoring instead
                                                 of polling
        :raises: VimException, VimFaultException, VimAttributeException,
                 VimSessionOverLoadException
        """
        self._host = host
        self._port = port
        self._server_username = server_username
        self._server_password = server_password
        self._api_retry_count = api_retry_count
        self._task_poll_interval = task_poll_interval
        self._scheme = scheme
        self._vim_wsdl_loc = wsdl_loc
        self._pbm_wsdl_loc = pbm_wsdl_loc
        self._session_id = None
        self._session_username = None
        self._vim = None
        self._pbm = None
        self._cacert = cacert
        self._insecure = insecure
        self._pool_size = pool_size
        self._connection_timeout = connection_timeout
        self._op_id_prefix = op_id_prefix

        self._use_property_collector_for_tasks = (
            use_property_collector_for_tasks)
        self._pending_tasks = queue.Queue()
        self._property_collector_thread = None

        if create_session:
            self._create_session()

    def __del__(self):
        self._stop_property_collector_thread()

    def pbm_wsdl_loc_set(self, pbm_wsdl_loc):
        self._pbm_wsdl_loc = pbm_wsdl_loc
        self._pbm = None
        LOG.info('PBM WSDL updated to %s', pbm_wsdl_loc)

    @property
    def vim(self):
        if not self._vim:
            self._vim = vim.Vim(protocol=self._scheme,
                                host=self._host,
                                port=self._port,
                                wsdl_url=self._vim_wsdl_loc,
                                cacert=self._cacert,
                                insecure=self._insecure,
                                pool_maxsize=self._pool_size,
                                connection_timeout=self._connection_timeout,
                                op_id_prefix=self._op_id_prefix)
        return self._vim

    @property
    def pbm(self):
        if not self._pbm and self._pbm_wsdl_loc:
            self._pbm = pbm.Pbm(protocol=self._scheme,
                                host=self._host,
                                port=self._port,
                                wsdl_url=self._pbm_wsdl_loc,
                                cacert=self._cacert,
                                insecure=self._insecure,
                                pool_maxsize=self._pool_size,
                                connection_timeout=self._connection_timeout,
                                op_id_prefix=self._op_id_prefix)
            if self._session_id:
                # To handle the case where pbm property is accessed after
                # session creation. If pbm property is accessed before session
                # creation, we set the cookie in _create_session.
                self._pbm.set_soap_cookie(self._vim.get_http_cookie())
        return self._pbm

    @RetryDecorator(exceptions=(exceptions.VimConnectionException,))
    @lockutils.synchronized('oslo_vmware_api_lock')
    def _create_session(self):
        """Establish session with the server."""
        # Another thread might have created the session while the current one
        # was waiting for the lock.
        if self._session_id and self.is_current_session_active():
            LOG.debug("Current session: %s is active.",
                      _trunc_id(self._session_id))
            return

        session_manager = self.vim.service_content.sessionManager
        # Login and create new session with the server for making API calls.
        LOG.debug("Logging into host: %s.", self._host)
        session = self.vim.Login(session_manager,
                                 userName=self._server_username,
                                 password=self._server_password,
                                 locale='en')
        self._session_id = session.key
        # We need to save the username in the session since we may need it
        # later to check active session. The SessionIsActive method requires
        # the username parameter to be exactly same as that in the session
        # object. We can't use the username used for login since the Login
        # method ignores the case.
        self._session_username = session.userName
        LOG.info("Successfully established new session; session ID is "
                 "%s.",
                 _trunc_id(self._session_id))

        # Set PBM client cookie.
        if self._pbm is not None:
            self._pbm.set_soap_cookie(self._vim.get_http_cookie())

        if self._use_property_collector_for_tasks:
            self._start_property_collector_thread()

    def _start_property_collector_thread(self):
        """Start background property collector thread for task monitoring."""
        if (self._property_collector_thread is not None and
                self._property_collector_thread.is_alive()):
            LOG.debug("Property collector thread already running.")
            return

        LOG.info("Starting property collector thread for task monitoring.")
        self._pending_tasks = queue.Queue()
        self._property_collector_thread = threading.Thread(
            target=self._property_collector_loop,
            daemon=True)
        self._property_collector_thread.start()

    def _property_collector_loop(self):
        """Background thread that monitors tasks via property collector.

        All property collector state (collector, version, running_tasks)
        is kept as local variables. The only shared state with the main
        thread is self._pending_tasks queue.
        """
        LOG.debug("Property collector thread started.")
        property_collector = None
        property_collector_version = ""
        # Maps task moref value -> (future, context, filter)
        running_tasks = {}

        try:
            pc = self.vim.service_content.propertyCollector
            property_collector = self.vim.CreatePropertyCollector(pc)
            LOG.debug("Created property collector: %s",
                      vim_util.get_moref_value(property_collector))

            while True:
                if not running_tasks:
                    LOG.debug("No running tasks, waiting for new tasks...")
                    pending_task = self._pending_tasks.get()
                    if pending_task is None:
                        break
                    self._add_task(property_collector, running_tasks,
                                   pending_task)

                # Drain additional pending tasks
                while True:
                    try:
                        task_data = self._pending_tasks.get_nowait()
                    except queue.Empty:
                        break
                    if task_data is None:
                        return
                    self._add_task(property_collector, running_tasks,
                                   task_data)

                if not running_tasks:
                    continue

                try:
                    options = self.vim.client.factory.create(
                        "ns0:WaitOptions")
                    options.maxWaitSeconds = 1
                    update_set = self.vim.WaitForUpdatesEx(
                        property_collector,
                        version=property_collector_version,
                        options=options)
                    if update_set:
                        property_collector_version = update_set.version
                        self._process_task_updates(update_set, running_tasks)
                except exceptions.VimException:
                    LOG.exception("Error in property collector, "
                                  "recreating collector.")
                    property_collector, property_collector_version = (
                        self._recreate_property_collector(
                            property_collector, running_tasks))

        except Exception:
            LOG.exception("Property collector loop failed.")
            for task_value, (task_future, _ctx, _flt) in running_tasks.items():
                try:
                    task_future.set_exception(exceptions.VimException(
                        _("Property collector failed")))
                except futures.InvalidStateError:
                    pass
        finally:
            if property_collector:
                try:
                    self.vim.DestroyPropertyCollector(property_collector)
                except Exception:
                    LOG.warning("Error destroying property collector.",
                                exc_info=True)

            # Notify remaining pending tasks
            while True:
                try:
                    task_data = self._pending_tasks.get_nowait()
                except queue.Empty:
                    break
                if task_data is not None:
                    _, task_future, _ = task_data
                    try:
                        task_future.set_exception(exceptions.VimException(
                            _("Property collector stopped")))
                    except futures.InvalidStateError:
                        pass

            # Notify remaining running tasks
            for task_value, (task_future, _ctx, _flt) in running_tasks.items():
                try:
                    task_future.set_exception(exceptions.VimException(
                        _("Property collector stopped while waiting for "
                          "task %s") % task_value))
                except futures.InvalidStateError:
                    pass

            LOG.debug("Property collector thread stopped.")

    def _add_task(self, property_collector, running_tasks, task_data):
        """Create a property filter for a task and add it to running_tasks.

        :param property_collector: the property collector managed object
        :param running_tasks: dict mapping task values to
                              (future, context, filter)
        :param task_data: tuple of (task_value, future, context)
        """
        task_value, task_future, ctx = task_data
        try:
            task_moref = vim_util.get_moref(task_value, 'Task')
            task_filter = self._create_task_filter(
                property_collector, task_moref)
            running_tasks[task_value] = (task_future, ctx, task_filter)
            LOG.debug("Monitoring task %s.", task_value)
        except Exception:
            LOG.exception("Failed to create filter for task %s", task_value)
            task_future.set_exception(exceptions.VimException(
                _("Failed to create property filter")))

    def _create_task_filter(self, property_collector, task_moref):
        """Create a property filter for a single task.

        :param property_collector: the property collector managed object
        :param task_moref: task managed object reference
        :returns: property filter object
        """
        client_factory = self.vim.client.factory
        property_spec = vim_util.build_property_spec(
            client_factory,
            type_='Task',
            properties_to_collect=['info'])

        object_spec = vim_util.build_object_spec(
            client_factory,
            task_moref,
            [])

        property_filter_spec = vim_util.build_property_filter_spec(
            client_factory,
            [property_spec],
            [object_spec])

        LOG.debug("Creating property filter for task: %s", task_moref.value)

        return self.vim.CreateFilter(
            property_collector,
            spec=property_filter_spec,
            partialUpdates=False)

    def _cleanup_task_filter(self, task_value, running_tasks):
        """Remove task from running_tasks and destroy its property filter.

        :param task_value: task moref value
        :param running_tasks: dict mapping task values to
                              (future, context, filter)
        """
        if task_value in running_tasks:
            _, _, task_filter = running_tasks.pop(task_value)
            try:
                self.vim.DestroyPropertyFilter(task_filter)
            except exceptions.VimException:
                LOG.warning("Error destroying property filter for task %s",
                            task_value, exc_info=True)

    def _recreate_property_collector(self, property_collector, running_tasks):
        """Recreate the property collector after an error.

        Preserves pending and running tasks and recreates filters for each.

        :param property_collector: the old property collector
        :param running_tasks: dict of currently running tasks (mutated)
        :returns: tuple of (new_property_collector, new_version)
        """
        LOG.info("Recreating property collector.")

        # Drain pending tasks into running_tasks
        while True:
            try:
                task_data = self._pending_tasks.get_nowait()
            except queue.Empty:
                break
            if task_data is not None:
                task_value, task_future, ctx = task_data
                running_tasks[task_value] = (task_future, ctx, None)

        # Destroy old collector (this also destroys all filters)
        if property_collector:
            try:
                self.vim.DestroyPropertyCollector(property_collector)
            except exceptions.VimException:
                LOG.warning("Error destroying old property collector.",
                            exc_info=True)

        pc = self.vim.service_content.propertyCollector
        property_collector = self.vim.CreatePropertyCollector(pc)

        tasks_to_recreate = list(running_tasks.items())
        running_tasks.clear()

        for task_value, (task_future, ctx, _flt) in tasks_to_recreate:
            try:
                task_moref = vim_util.get_moref(task_value, 'Task')
                task_filter = self._create_task_filter(
                    property_collector, task_moref)
                running_tasks[task_value] = (task_future, ctx, task_filter)
            except Exception:
                LOG.exception("Failed to recreate filter for task %s",
                              task_value)
                task_future.set_exception(exceptions.VimException(
                    _("Failed to recreate property filter")))

        LOG.info("Property collector recreated with %d task filters.",
                 len(running_tasks))
        return property_collector, ""

    def _process_task_updates(self, update_set, running_tasks):
        """Process task updates from WaitForUpdatesEx.

        :param update_set: UpdateSet from WaitForUpdatesEx
        :param running_tasks: dict mapping task values to
                              (future, context, filter)
        """
        if not update_set.filterSet:
            return

        for filter_set in update_set.filterSet:
            if not filter_set.objectSet:
                continue

            for obj_update in filter_set.objectSet:
                task_moref = obj_update.obj
                task_value = vim_util.get_moref_value(task_moref)

                if task_value not in running_tasks:
                    continue
                task_future, ctx, _ = running_tasks[task_value]

                task_info = None
                if hasattr(obj_update, 'changeSet'):
                    for change in obj_update.changeSet:
                        if (change.name == 'info' and
                                change.op in ('assign', 'modify')):
                            task_info = getattr(change, 'val', None)
                            break

                if not task_info:
                    continue

                if task_info.state in ['queued', 'running']:
                    if hasattr(task_info, 'progress'):
                        task_detail = {'id': task_value}
                        if getattr(task_info, 'name', None):
                            task_detail['name'] = task_info.name
                        LOG.debug("Task: %(task)s progress is %(progress)s%%.",
                                  {'task': task_detail,
                                   'progress': task_info.progress})
                elif task_info.state == 'success':
                    task_detail = {'id': task_value}
                    if getattr(task_info, 'name', None):
                        task_detail['name'] = task_info.name
                    complete_time = getattr(task_info, 'completeTime', None)
                    if complete_time:
                        duration = complete_time - task_info.queueTime
                        task_detail['duration_secs'] = duration.total_seconds()
                    LOG.debug("Task: %s completed successfully.", task_detail)

                    self._cleanup_task_filter(task_value, running_tasks)
                    if ctx:
                        ctx.update_store()
                    task_future.set_result(task_info)
                else:
                    LOG.debug("Task: %s entered state: %s",
                              task_value, task_info.state)

                    self._cleanup_task_filter(task_value, running_tasks)
                    if ctx:
                        ctx.update_store()
                    try:
                        exception = exceptions.translate_fault(
                            task_info.error)
                        task_future.set_exception(exception)
                    except Exception as e:
                        task_future.set_exception(e)

    def _stop_property_collector_thread(self):
        """Stop the background property collector thread."""
        if self._property_collector_thread is None:
            return

        LOG.info("Stopping property collector thread.")
        self._pending_tasks.put(None)
        self._property_collector_thread.join()
        self._property_collector_thread = None

    @lockutils.synchronized('oslo_vmware_api_lock')
    def logout(self):
        """Log out and terminate the current session."""
        if self._use_property_collector_for_tasks:
            self._stop_property_collector_thread()

        if self._session_id:
            LOG.info("Logging out and terminating the current session "
                     "with ID = %s.",
                     _trunc_id(self._session_id))
            try:
                self.vim.Logout(self.vim.service_content.sessionManager)
                self._session_id = None
            except Exception:
                LOG.exception("Error occurred while logging out and "
                              "terminating the current session with "
                              "ID = %s.",
                              _trunc_id(self._session_id))
        else:
            LOG.debug("No session exists to log out.")

    def invoke_api(self, module, method, *args, **kwargs):
        """Wrapper method for invoking APIs.

        The API call is retried in the event of exceptions due to session
        overload or connection problems.

        :param module: module corresponding to the VIM API call
        :param method: method in the module which corresponds to the
                       VIM API call
        :param args: arguments to the method
        :param kwargs: keyword arguments to the method
        :returns: response from the API call
        :raises: VimException, VimFaultException, VimAttributeException,
                 VimSessionOverLoadException, VimConnectionException
        """

        @RetryDecorator(max_retry_count=self._api_retry_count,
                        exceptions=(exceptions.VimSessionOverLoadException,
                                    exceptions.VimConnectionException))
        def _invoke_api(module, method, *args, **kwargs):
            try:
                api_method = getattr(module, method)
                return api_method(*args, **kwargs)
            except exceptions.VimFaultException as excep:
                # If this is due to an inactive session, we should re-create
                # the session and retry.
                if exceptions.NOT_AUTHENTICATED in excep.fault_list:
                    # The NotAuthenticated fault is set by the fault checker
                    # due to an empty response. An empty response could be a
                    # valid response; for e.g., response for the query to
                    # return the VMs in an ESX server which has no VMs in it.
                    # Also, the server responds with an empty response in the
                    # case of an inactive session. Therefore, we need a way to
                    # differentiate between these two cases.
                    if self.is_current_session_active():
                        LOG.debug("Returning empty response for "
                                  "%(module)s.%(method)s invocation.",
                                  {'module': module,
                                   'method': method})
                        return []
                    else:
                        # empty response is due to an inactive session
                        excep_msg = (
                            _("Current session: %(session)s is inactive; "
                              "re-creating the session while invoking "
                              "method %(module)s.%(method)s.") %
                            {'session': _trunc_id(self._session_id),
                             'module': module,
                             'method': method})
                        LOG.debug(excep_msg)
                        self._create_session()
                        raise exceptions.VimConnectionException(excep_msg,
                                                                excep)
                else:
                    # no need to retry for other VIM faults like
                    # InvalidArgument
                    # Raise specific exceptions here if possible
                    if excep.fault_list:
                        LOG.debug("Fault list: %s", excep.fault_list)
                        fault = excep.fault_list[0]
                        clazz = exceptions.get_fault_class(fault)
                        if clazz:
                            raise clazz(str(excep),
                                        details=excep.details)
                    raise

            except exceptions.VimConnectionException:
                with excutils.save_and_reraise_exception():
                    # Re-create the session during connection exception only
                    # if the session has expired. Otherwise, it could be
                    # a transient issue.
                    if not self.is_current_session_active():
                        LOG.debug("Re-creating session due to connection "
                                  "problems while invoking method "
                                  "%(module)s.%(method)s.",
                                  {'module': module,
                                   'method': method})
                        self._create_session()

        return _invoke_api(module, method, *args, **kwargs)

    def is_current_session_active(self):
        """Check if current session is active.

        :returns: True if the session is active; False otherwise
        """
        LOG.debug("Checking if the current session: %s is active.",
                  _trunc_id(self._session_id))

        is_active = False
        try:
            is_active = self.vim.SessionIsActive(
                self.vim.service_content.sessionManager,
                sessionID=self._session_id,
                userName=self._session_username)
        except exceptions.VimException as ex:
            LOG.debug("Error: %(error)s occurred while checking whether the "
                      "current session: %(session)s is active.",
                      {'error': str(ex),
                       'session': _trunc_id(self._session_id)})

        return is_active

    def wait_for_task(self, task):
        """Waits for the given task to complete and returns the result.

        The task is polled until it is done. The method returns the task
        information upon successful completion. In case of any error,
        appropriate exception is raised.

        :param task: managed object reference of the task
        :returns: task info upon successful completion of the task
        :raises: VimException, VimFaultException, VimAttributeException,
                 VimSessionOverLoadException, VimConnectionException
        """
        if self._use_property_collector_for_tasks:
            return self._wait_for_task_with_property_collector(task)
        else:
            return self._wait_for_task_with_polling(task)

    def _wait_for_task_with_property_collector(self, task):
        """Wait for task using centralized property collector.

        Submits the task to the background monitoring thread via
        the pending tasks queue and waits for the result.

        :param task: managed object reference of the task
        :returns: task info upon successful completion of the task
        :raises: VimException, VimFaultException, VimAttributeException,
                 VimSessionOverLoadException, VimConnectionException
        """
        ctx = context.get_current()
        task_future = futures.Future()
        task_value = vim_util.get_moref_value(task)
        self._pending_tasks.put((task_value, task_future, ctx))
        return task_future.result()

    def _wait_for_task_with_polling(self, task):
        """Wait for task using traditional polling approach.

        :param task: managed object reference of the task
        :returns: task info upon successful completion of the task
        :raises: VimException, VimFaultException, VimAttributeException,
                 VimSessionOverLoadException, VimConnectionException
        """
        ctx = context.get_current()
        loop = loopingcall.FixedIntervalLoopingCall(self._poll_task, task, ctx)
        evt = loop.start(self._task_poll_interval)
        LOG.debug("Waiting for the task: %s to complete.", task)
        return evt.wait()

    def _poll_task(self, task, ctx):
        """Poll the given task until completion.

        If the task completes successfully, the method returns the task info
        using the input event (param done). In case of any error, appropriate
        exception is set in the event.

        :param task: managed object reference of the task
        :param ctx: request context for the corresponding task
        """
        if ctx is not None:
            ctx.update_store()
        try:
            # we poll tasks too often, so skip logging the opID as it generates
            # too much noise in the logs
            task_info = self.invoke_api(vim_util,
                                        'get_object_property',
                                        self.vim,
                                        task,
                                        'info',
                                        skip_op_id=True)
        except exceptions.VimException:
            with excutils.save_and_reraise_exception():
                LOG.exception("Error occurred while reading info of "
                              "task: %s.",
                              task)
        else:
            task_detail = {'id': vim_util.get_moref_value(task)}
            # some internal tasks do not have 'name' set
            if getattr(task_info, 'name', None):
                task_detail['name'] = task_info.name

            if task_info.state in ['queued', 'running']:
                if hasattr(task_info, 'progress'):
                    LOG.debug("Task: %(task)s progress is %(progress)s%%.",
                              {'task': task_detail,
                               'progress': task_info.progress})
            elif task_info.state == 'success':
                def get_completed_task():
                    complete_time = getattr(task_info, 'completeTime', None)
                    if complete_time:
                        duration = complete_time - task_info.queueTime
                        task_detail['duration_secs'] = duration.total_seconds()
                    return task_detail
                LOG.debug("Task: %s completed successfully.",
                          get_completed_task())
                raise loopingcall.LoopingCallDone(task_info)
            else:
                raise exceptions.translate_fault(task_info.error)

    def wait_for_lease_ready(self, lease):
        """Waits for the given lease to be ready.

        This method return when the lease is ready. In case of any error,
        appropriate exception is raised.

        :param lease: lease to be checked for
        :raises: VimException, VimFaultException, VimAttributeException,
                 VimSessionOverLoadException, VimConnectionException
        """
        loop = loopingcall.FixedIntervalLoopingCall(self._poll_lease, lease)
        evt = loop.start(self._task_poll_interval)
        LOG.debug("Waiting for the lease: %s to be ready.", lease)
        evt.wait()

    def _poll_lease(self, lease):
        """Poll the state of the given lease.

        When the lease is ready, the event (param done) is notified. In case
        of any error, appropriate exception is set in the event.

        :param lease: lease whose state is to be polled
        """
        try:
            state = self.invoke_api(vim_util,
                                    'get_object_property',
                                    self.vim,
                                    lease,
                                    'state',
                                    skip_op_id=True)
        except exceptions.VimException:
            with excutils.save_and_reraise_exception():
                LOG.exception("Error occurred while checking "
                              "state of lease: %s.",
                              lease)
        else:
            if state == 'ready':
                LOG.debug("Lease: %s is ready.", lease)
                raise loopingcall.LoopingCallDone()
            elif state == 'initializing':
                LOG.debug("Lease: %s is initializing.", lease)
            elif state == 'error':
                LOG.debug("Invoking VIM API to read lease: %s error.",
                          lease)
                error_msg = self._get_error_message(lease)
                excep_msg = _("Lease: %(lease)s is in error state. Details: "
                              "%(error_msg)s.") % {'lease': lease,
                                                   'error_msg': error_msg}
                LOG.error(excep_msg)
                raise exceptions.translate_fault(error_msg, excep_msg)
            else:
                # unknown state
                excep_msg = _("Unknown state: %(state)s for lease: "
                              "%(lease)s.") % {'state': state,
                                               'lease': lease}
                LOG.error(excep_msg)
                raise exceptions.VimException(excep_msg)

    def _get_error_message(self, lease):
        """Get error message associated with the given lease."""
        try:
            return self.invoke_api(vim_util,
                                   'get_object_property',
                                   self.vim,
                                   lease,
                                   'error')
        except exceptions.VimException:
            LOG.warning("Error occurred while reading error message for "
                        "lease: %s.",
                        lease,
                        exc_info=True)
            return "Unknown"
