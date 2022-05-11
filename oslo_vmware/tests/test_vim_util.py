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

"""Unit tests for VMware API utility module."""

import collections
from unittest import mock

from oslo_vmware.tests import base
from oslo_vmware import vim_util


class FakeSXTypeDesc(object):
    def __init__(self, name, type):
        self.name = name
        self.type = [type]


class FakeSXType(object):
    def __init__(self, name, children):
        self.name = name
        self._children = [
            FakeSXTypeDesc(k, v) for k, v in children.items()
        ]

    def get_child(self, name):
        for child in self._children:
            if child.name == name:
                return child, None
        print([(child.name, child.type[0]) for child in self._children])
        raise ValueError(
            "Didn't expect child by name '{}' in '{}'".format(name, self.name))

    def children(self):
        for child in self._children:
            yield child, None

    def __eq__(self, other):
        return self.name == other.name


class FakeObject(object):
    DEFAULT_TYPE = "Class"

    def __init__(self, type=None, **members):
        sxtype = FakeFactory.find(type or FakeObject.DEFAULT_TYPE)
        if not sxtype:
            raise ValueError("Unknown type {}".format(type))
        self.__metadata__ = dict(sxtype=sxtype)
        self.__keylist__ = []
        for k, v in members.items():
            setattr(self, k, v)

    def __setattr__(self, name, value):
        if not name.startswith("__") and name not in self.__keylist__:
            self.__keylist__.append(name)
        self.__dict__[name] = value

    def __iter__(self):
        for key in self.__keylist__:
            yield key, getattr(self, key)

    def __str__(self):
        sxtype = self.__metadata__['sxtype']
        return "{}({})".format(
            sxtype.name,
            ", ".join("{}={!r}".format(k, getattr(self, k))
                      for k in self.__keylist__
                      if getattr(self, k) is not None))

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        own_type = self.__metadata__['sxtype']
        other_type = other.__metadata__['sxtype']
        if own_type != other_type:
            return False

        keylist = set(self.__keylist__) | set(other.__keylist__)
        for key in keylist:
            own_value = getattr(self, key, None)
            other_value = getattr(other, key, None)
            if own_value != other_value:
                return False

        return True

    def __ne__(self, other):
        return not (self == other)


class FakeFactory(object):
    __TYPES = {}

    def __init__(self):
        pass

    @staticmethod
    def create(qname):
        return FakeObject(qname.split(':')[-1])

    @property
    def resolver(self):
        return self

    @classmethod
    def _get_registry(cls):
        if cls.__TYPES:
            return cls.__TYPES

        children = dict(
            a=None,
            i=None,
            n=None,
            none=None,
            m=None,
            s=None,
            t=None,
            f=None,
            child="Class",
            children="Class",
            z=None,
        )
        class_ = FakeSXType("Class", children)
        otherclass = FakeSXType("OtherClass", children)
        cls.__TYPES["Class"] = class_
        cls.__TYPES["OtherClass"] = otherclass
        return cls.__TYPES

    @staticmethod
    def find(qname):
        sname = qname.split(':')[-1]
        registry = FakeFactory._get_registry()
        return registry.get(sname)


class VimUtilTest(base.TestCase):
    """Test class for utility methods in vim_util."""

    def test_get_moref(self):
        moref = vim_util.get_moref("vm-0", "VirtualMachine")
        self.assertEqual("vm-0", vim_util.get_moref_value(moref))
        self.assertEqual("VirtualMachine", vim_util.get_moref_type(moref))

    def test_build_selection_spec(self):
        client_factory = mock.Mock()
        sel_spec = vim_util.build_selection_spec(client_factory, "test")
        self.assertEqual("test", sel_spec.name)

    def test_build_traversal_spec(self):
        client_factory = mock.Mock()
        sel_spec = mock.Mock()
        traversal_spec = vim_util.build_traversal_spec(client_factory,
                                                       'dc_to_hf',
                                                       'Datacenter',
                                                       'hostFolder', False,
                                                       [sel_spec])
        self.assertEqual("dc_to_hf", traversal_spec.name)
        self.assertEqual("hostFolder", traversal_spec.path)
        self.assertEqual([sel_spec], traversal_spec.selectSet)
        self.assertFalse(traversal_spec.skip)
        self.assertEqual("Datacenter", traversal_spec.type)

    @mock.patch.object(vim_util, 'build_selection_spec')
    def test_build_recursive_traversal_spec(self, build_selection_spec_mock):
        sel_spec = mock.Mock()
        rp_to_rp_sel_spec = mock.Mock()
        rp_to_vm_sel_spec = mock.Mock()

        def build_sel_spec_side_effect(client_factory, name):
            if name == 'visitFolders':
                return sel_spec
            elif name == 'rp_to_rp':
                return rp_to_rp_sel_spec
            elif name == 'rp_to_vm':
                return rp_to_vm_sel_spec
            else:
                return None

        build_selection_spec_mock.side_effect = build_sel_spec_side_effect
        traversal_spec_dict = {'dc_to_hf': {'type': 'Datacenter',
                                            'path': 'hostFolder',
                                            'skip': False,
                                            'selectSet': [sel_spec]},
                               'dc_to_vmf': {'type': 'Datacenter',
                                             'path': 'vmFolder',
                                             'skip': False,
                                             'selectSet': [sel_spec]},
                               'dc_to_netf': {'type': 'Datacenter',
                                              'path': 'networkFolder',
                                              'skip': False,
                                              'selectSet': [sel_spec]},
                               'dc_to_df': {'type': 'Datacenter',
                                            'path': 'datastoreFolder',
                                            'skip': False,
                                            'selectSet': [sel_spec]},
                               'h_to_vm': {'type': 'HostSystem',
                                           'path': 'vm',
                                           'skip': False,
                                           'selectSet': [sel_spec]},
                               'cr_to_h': {'type': 'ComputeResource',
                                           'path': 'host',
                                           'skip': False,
                                           'selectSet': []},
                               'cr_to_ds': {'type': 'ComputeResource',
                                            'path': 'datastore',
                                            'skip': False,
                                            'selectSet': []},
                               'cr_to_rp': {'type': 'ComputeResource',
                                            'path': 'resourcePool',
                                            'skip': False,
                                            'selectSet': [rp_to_rp_sel_spec,
                                                          rp_to_vm_sel_spec]},
                               'ccr_to_h': {'type': 'ClusterComputeResource',
                                            'path': 'host',
                                            'skip': False,
                                            'selectSet': []},
                               'ccr_to_ds': {'type': 'ClusterComputeResource',
                                             'path': 'datastore',
                                             'skip': False,
                                             'selectSet': []},
                               'ccr_to_rp': {'type': 'ClusterComputeResource',
                                             'path': 'resourcePool',
                                             'skip': False,
                                             'selectSet': [rp_to_rp_sel_spec,
                                                           rp_to_vm_sel_spec]},
                               'rp_to_rp': {'type': 'ResourcePool',
                                            'path': 'resourcePool',
                                            'skip': False,
                                            'selectSet': [rp_to_rp_sel_spec,
                                                          rp_to_vm_sel_spec]},
                               'rp_to_vm': {'type': 'ResourcePool',
                                            'path': 'vm',
                                            'skip': False,
                                            'selectSet': [rp_to_rp_sel_spec,
                                                          rp_to_vm_sel_spec]},
                               }

        client_factory = mock.Mock()
        client_factory.create.side_effect = lambda ns: mock.Mock()
        trav_spec = vim_util.build_recursive_traversal_spec(client_factory)
        self.assertEqual("visitFolders", trav_spec.name)
        self.assertEqual("childEntity", trav_spec.path)
        self.assertFalse(trav_spec.skip)
        self.assertEqual("Folder", trav_spec.type)

        self.assertEqual(len(traversal_spec_dict) + 1,
                         len(trav_spec.selectSet))
        for spec in trav_spec.selectSet:
            if spec.name not in traversal_spec_dict:
                self.assertEqual(sel_spec, spec)
            else:
                exp_spec = traversal_spec_dict[spec.name]
                self.assertEqual(exp_spec['type'], spec.type)
                self.assertEqual(exp_spec['path'], spec.path)
                self.assertEqual(exp_spec['skip'], spec.skip)
                self.assertEqual(exp_spec['selectSet'], spec.selectSet)

    def test_build_property_spec(self):
        client_factory = mock.Mock()
        prop_spec = vim_util.build_property_spec(client_factory)
        self.assertFalse(prop_spec.all)
        self.assertEqual(["name"], prop_spec.pathSet)
        self.assertEqual("VirtualMachine", prop_spec.type)

    def test_build_object_spec(self):
        client_factory = mock.Mock()
        root_folder = mock.Mock()
        specs = [mock.Mock()]
        obj_spec = vim_util.build_object_spec(client_factory,
                                              root_folder, specs)
        self.assertEqual(root_folder, obj_spec.obj)
        self.assertEqual(specs, obj_spec.selectSet)
        self.assertFalse(obj_spec.skip)

    def test_build_property_filter_spec(self):
        client_factory = mock.Mock()
        prop_specs = [mock.Mock()]
        obj_specs = [mock.Mock()]
        filter_spec = vim_util.build_property_filter_spec(client_factory,
                                                          prop_specs,
                                                          obj_specs)
        self.assertEqual(obj_specs, filter_spec.objectSet)
        self.assertEqual(prop_specs, filter_spec.propSet)

    @mock.patch(
        'oslo_vmware.vim_util.build_recursive_traversal_spec')
    def test_get_objects(self, build_recursive_traversal_spec):
        vim = mock.Mock()
        trav_spec = mock.Mock()
        build_recursive_traversal_spec.return_value = trav_spec
        max_objects = 10
        _type = "VirtualMachine"

        def vim_RetrievePropertiesEx_side_effect(pc, specSet, options):
            self.assertTrue(pc is vim.service_content.propertyCollector)
            self.assertEqual(max_objects, options.maxObjects)

            self.assertEqual(1, len(specSet))
            property_filter_spec = specSet[0]

            propSet = property_filter_spec.propSet
            self.assertEqual(1, len(propSet))
            prop_spec = propSet[0]
            self.assertFalse(prop_spec.all)
            self.assertEqual(["name"], prop_spec.pathSet)
            self.assertEqual(_type, prop_spec.type)

            objSet = property_filter_spec.objectSet
            self.assertEqual(1, len(objSet))
            obj_spec = objSet[0]
            self.assertTrue(obj_spec.obj is vim.service_content.rootFolder)
            self.assertEqual([trav_spec], obj_spec.selectSet)
            self.assertFalse(obj_spec.skip)

        vim.RetrievePropertiesEx.side_effect = (
            vim_RetrievePropertiesEx_side_effect)
        vim_util.get_objects(vim, _type, max_objects)
        self.assertEqual(1, vim.RetrievePropertiesEx.call_count)

    def test_get_object_properties_with_empty_moref(self):
        vim = mock.Mock()
        ret = vim_util.get_object_properties(vim, None, None)
        self.assertIsNone(ret)

    @mock.patch('oslo_vmware.vim_util.cancel_retrieval')
    def test_get_object_properties(self, cancel_retrieval):
        vim = mock.Mock()
        moref = vim_util.get_moref('fake-ref', 'VirtualMachine')
        retrieve_result = mock.Mock()

        def vim_RetrievePropertiesEx_side_effect(pc, specSet, options,
                                                 skip_op_id=False):
            self.assertTrue(pc is vim.service_content.propertyCollector)
            self.assertEqual(1, options.maxObjects)

            self.assertEqual(1, len(specSet))
            property_filter_spec = specSet[0]

            propSet = property_filter_spec.propSet
            self.assertEqual(1, len(propSet))
            prop_spec = propSet[0]
            self.assertTrue(prop_spec.all)
            self.assertEqual(['name'], prop_spec.pathSet)
            self.assertEqual(vim_util.get_moref_type(moref), prop_spec.type)

            objSet = property_filter_spec.objectSet
            self.assertEqual(1, len(objSet))
            obj_spec = objSet[0]
            self.assertEqual(moref, obj_spec.obj)
            self.assertEqual([], obj_spec.selectSet)
            self.assertFalse(obj_spec.skip)

            return retrieve_result

        vim.RetrievePropertiesEx.side_effect = (
            vim_RetrievePropertiesEx_side_effect)

        res = vim_util.get_object_properties(vim, moref, None)
        self.assertEqual(1, vim.RetrievePropertiesEx.call_count)
        self.assertTrue(res is retrieve_result.objects)
        cancel_retrieval.assert_called_once_with(vim, retrieve_result)

    def test_get_token(self):
        retrieve_result = object()
        self.assertFalse(vim_util._get_token(retrieve_result))

    @mock.patch('oslo_vmware.vim_util.get_object_properties')
    def test_get_object_properties_dict_empty(self, mock_obj_prop):
        mock_obj_prop.return_value = None
        vim = mock.Mock()
        moref = mock.Mock()
        res = vim_util.get_object_properties_dict(vim, moref, None)
        self.assertEqual({}, res)

    @mock.patch('oslo_vmware.vim_util.get_object_properties')
    def test_get_object_properties_dict(self, mock_obj_prop):
        expected_prop_dict = {'name': 'vm01'}
        mock_obj_content = mock.Mock()
        prop = mock.Mock()
        prop.name = "name"
        prop.val = "vm01"
        mock_obj_content.propSet = [prop]
        del mock_obj_content.missingSet
        mock_obj_prop.return_value = [mock_obj_content]
        vim = mock.Mock()
        moref = mock.Mock()
        res = vim_util.get_object_properties_dict(vim, moref, None)
        self.assertEqual(expected_prop_dict, res)

    @mock.patch('oslo_vmware.vim_util.get_object_properties')
    def test_get_object_properties_dict_missing(self, mock_obj_prop):
        mock_obj_content = mock.Mock()
        missing_prop = mock.Mock()
        missing_prop.path = "name"
        missing_prop.fault = mock.Mock()
        mock_obj_content.missingSet = [missing_prop]
        del mock_obj_content.propSet
        mock_obj_prop.return_value = [mock_obj_content]
        vim = mock.Mock()
        moref = mock.Mock()
        res = vim_util.get_object_properties_dict(vim, moref, None)
        self.assertEqual({}, res)

    @mock.patch('oslo_vmware.vim_util._get_token')
    def test_cancel_retrieval(self, get_token):
        token = mock.Mock()
        get_token.return_value = token
        vim = mock.Mock()
        retrieve_result = mock.Mock()
        vim_util.cancel_retrieval(vim, retrieve_result)
        get_token.assert_called_once_with(retrieve_result)
        vim.CancelRetrievePropertiesEx.assert_called_once_with(
            vim.service_content.propertyCollector, token=token)

    @mock.patch('oslo_vmware.vim_util._get_token')
    def test_continue_retrieval(self, get_token):
        token = mock.Mock()
        get_token.return_value = token
        vim = mock.Mock()
        retrieve_result = mock.Mock()
        vim_util.continue_retrieval(vim, retrieve_result)
        get_token.assert_called_once_with(retrieve_result)
        vim.ContinueRetrievePropertiesEx.assert_called_once_with(
            vim.service_content.propertyCollector, token=token)

    @mock.patch('oslo_vmware.vim_util.continue_retrieval')
    @mock.patch('oslo_vmware.vim_util.cancel_retrieval')
    def test_with_retrieval(self, cancel_retrieval, continue_retrieval):
        vim = mock.Mock()
        retrieve_result0 = mock.Mock()
        retrieve_result0.objects = [mock.Mock(), mock.Mock()]
        retrieve_result1 = mock.Mock()
        retrieve_result1.objects = [mock.Mock(), mock.Mock()]
        continue_retrieval.side_effect = [retrieve_result1, None]
        expected = retrieve_result0.objects + retrieve_result1.objects

        with vim_util.WithRetrieval(vim, retrieve_result0) as iterator:
            self.assertEqual(expected, list(iterator))

        calls = [
            mock.call(vim, retrieve_result0),
            mock.call(vim, retrieve_result1)]
        continue_retrieval.assert_has_calls(calls)
        self.assertFalse(cancel_retrieval.called)

    @mock.patch('oslo_vmware.vim_util.continue_retrieval')
    @mock.patch('oslo_vmware.vim_util.cancel_retrieval')
    def test_with_retrieval_early_exit(self, cancel_retrieval,
                                       continue_retrieval):
        vim = mock.Mock()
        retrieve_result = mock.Mock()
        with vim_util.WithRetrieval(vim, retrieve_result):
            pass

        cancel_retrieval.assert_called_once_with(vim, retrieve_result)

    @mock.patch('oslo_vmware.vim_util.get_object_properties')
    def test_get_object_property(self, get_object_properties):
        prop = mock.Mock()
        prop.val = "ubuntu-12.04"
        properties = mock.Mock()
        properties.propSet = [prop]
        properties_list = [properties]
        get_object_properties.return_value = properties_list
        vim = mock.Mock()
        moref = mock.Mock()
        property_name = 'name'
        val = vim_util.get_object_property(vim, moref, property_name)
        self.assertEqual(prop.val, val)
        get_object_properties.assert_called_once_with(
            vim, moref, [property_name], skip_op_id=False)

    def test_find_extension(self):
        vim = mock.Mock()
        ret = vim_util.find_extension(vim, 'fake-key')
        self.assertIsNotNone(ret)
        service_content = vim.service_content
        vim.FindExtension.assert_called_once_with(
            service_content.extensionManager, extensionKey='fake-key')

    def test_register_extension(self):
        vim = mock.Mock()
        ret = vim_util.register_extension(vim, 'fake-key', 'fake-type')
        self.assertIsNone(ret)
        service_content = vim.service_content
        vim.RegisterExtension.assert_called_once_with(
            service_content.extensionManager, extension=mock.ANY)

    def test_get_vc_version(self):
        session = mock.Mock()
        expected_version = '6.0.1'
        session.vim.service_content.about.version = expected_version
        version = vim_util.get_vc_version(session)
        self.assertEqual(expected_version, version)
        expected_version = '5.5'
        session.vim.service_content.about.version = expected_version
        version = vim_util.get_vc_version(session)
        self.assertEqual(expected_version, version)

    def test_get_inventory_path_folders(self):
        ObjectContent = collections.namedtuple('ObjectContent', ['propSet'])
        DynamicProperty = collections.namedtuple('Property', ['name', 'val'])

        obj1 = ObjectContent(propSet=[
            DynamicProperty(name='Datacenter', val='dc-1'),
        ])
        obj2 = ObjectContent(propSet=[
            DynamicProperty(name='Datacenter', val='folder-2'),
        ])
        obj3 = ObjectContent(propSet=[
            DynamicProperty(name='Datacenter', val='folder-1'),
        ])
        objects = ['foo', 'bar', obj1, obj2, obj3]
        result = mock.sentinel.objects
        result.objects = objects
        session = mock.Mock()
        session.vim.RetrievePropertiesEx = mock.Mock()
        session.vim.RetrievePropertiesEx.return_value = result
        entity = mock.Mock()
        inv_path = vim_util.get_inventory_path(session.vim, entity, 100)
        self.assertEqual('/folder-2/dc-1', inv_path)

    def test_get_inventory_path_no_folder(self):
        ObjectContent = collections.namedtuple('ObjectContent', ['propSet'])
        DynamicProperty = collections.namedtuple('Property', ['name', 'val'])

        obj1 = ObjectContent(propSet=[
            DynamicProperty(name='Datacenter', val='dc-1'),
        ])
        objects = ['foo', 'bar', obj1]
        result = mock.sentinel.objects
        result.objects = objects
        session = mock.Mock()
        session.vim.RetrievePropertiesEx = mock.Mock()
        session.vim.RetrievePropertiesEx.return_value = result
        entity = mock.Mock()
        inv_path = vim_util.get_inventory_path(session.vim, entity, 100)
        self.assertEqual('dc-1', inv_path)

    def test_get_prop_spec(self):
        client_factory = mock.Mock()
        prop_spec = vim_util.get_prop_spec(
            client_factory, "VirtualMachine", ["test_path"])
        self.assertEqual(["test_path"], prop_spec.pathSet)
        self.assertEqual("VirtualMachine", prop_spec.type)

    def test_get_obj_spec(self):
        client_factory = mock.Mock()
        mock_obj = mock.Mock()
        obj_spec = vim_util.get_obj_spec(
            client_factory, mock_obj, select_set=["abc"])
        self.assertEqual(mock_obj, obj_spec.obj)
        self.assertFalse(obj_spec.skip)
        self.assertEqual(["abc"], obj_spec.selectSet)

    def test_get_prop_filter_spec(self):
        client_factory = mock.Mock()
        mock_obj = mock.Mock()
        filter_spec = vim_util.get_prop_filter_spec(
            client_factory, [mock_obj], ["test_prop"])
        self.assertEqual([mock_obj], filter_spec.objectSet)
        self.assertEqual(["test_prop"], filter_spec.propSet)

    @mock.patch('oslo_vmware.vim_util.get_prop_spec')
    @mock.patch('oslo_vmware.vim_util.get_obj_spec')
    @mock.patch('oslo_vmware.vim_util.get_prop_filter_spec')
    def _test_get_properties_for_a_collection_of_objects(
            self, objs, max_objects,
            mock_get_prop_filter_spec,
            mock_get_obj_spec,
            mock_get_prop_spec):
        vim = mock.Mock()
        if len(objs) == 0:
            self.assertEqual(
                [], vim_util.get_properties_for_a_collection_of_objects(
                    vim, 'VirtualMachine', [], {}))
            return

        mock_prop_spec = mock.Mock()
        mock_get_prop_spec.return_value = mock_prop_spec

        mock_get_obj_spec.side_effect = [mock.Mock()
                                         for obj in objs]
        get_obj_spec_calls = [mock.call(vim.client.factory, obj)
                              for obj in objs]

        mock_prop_spec = mock.Mock()
        mock_get_prop_spec.return_value = mock_prop_spec

        mock_prop_filter_spec = mock.Mock()
        mock_get_prop_filter_spec.return_value = mock_prop_filter_spec
        mock_options = mock.Mock()
        vim.client.factory.create.return_value = mock_options

        mock_return_value = mock.Mock()
        vim.RetrievePropertiesEx.return_value = mock_return_value
        res = vim_util.get_properties_for_a_collection_of_objects(
            vim, 'VirtualMachine', objs, ['runtime'], max_objects)
        self.assertEqual(mock_return_value, res)

        mock_get_prop_spec.assert_called_once_with(vim.client.factory,
                                                   'VirtualMachine',
                                                   ['runtime'])
        self.assertEqual(get_obj_spec_calls, mock_get_obj_spec.mock_calls)
        vim.client.factory.create.assert_called_once_with(
            'ns0:RetrieveOptions')
        self.assertEqual(max_objects if max_objects else len(objs),
                         mock_options.maxObjects)
        vim.RetrievePropertiesEx.assert_called_once_with(
            vim.service_content.propertyCollector,
            specSet=[mock_prop_filter_spec],
            options=mock_options)

    def test_get_properties_for_a_collection_of_objects(
            self):
        objects = ["m1", "m2"]
        self._test_get_properties_for_a_collection_of_objects(objects, None)

    def test_get_properties_for_a_collection_of_objects_max_objects_1(
            self):
        objects = ["m1", "m2"]
        self._test_get_properties_for_a_collection_of_objects(objects, 1)

    def test_get_properties_for_a_collection_of_objects_no_objects(
            self):
        self._test_get_properties_for_a_collection_of_objects([], None)

    def test_propset_dict(self):
        self.assertEqual({}, vim_util.propset_dict(None))

        mock_propset = []
        for i in range(2):
            mock_obj = mock.Mock()
            mock_obj.name = "test_name_%d" % i
            mock_obj.val = "test_val_%d" % i
            mock_propset.append(mock_obj)

        self.assertEqual({"test_name_0": "test_val_0",
                          "test_name_1": "test_val_1"},
                         vim_util.propset_dict(mock_propset))

    def test_serialize_object_managed_object_none(self):
        class_ = mock.NonCallableMagicMock(__name__="ManagedObjectReference")
        obj = mock.NonCallableMagicMock(value=None, __class__=class_)
        self.assertEqual(None, vim_util.serialize_object(obj))

    @staticmethod
    def _deserialize_test_fixtures():
        return [
            ("Empty default class",
             {},
             FakeObject()),
            ("Empty derived class",
             {"class": "OtherClass"},
             FakeObject("OtherClass")),
            ("Do not drop non-defaults",
             {'a': 'A', 'n': 0, 'i': 1, 's': "", 't': True, 'f': False,
              'child': {'class': 'OtherClass'}, 'z': 'Z'},
             FakeObject(a='A', n=0, i=1, s="", t=True, f=False,
                        child=FakeObject("OtherClass"),
                        z='Z')),
            ("Nested object",
             {'child': {'n': 1}, 'n': 0, },
             FakeObject(n=0, child=FakeObject(n=1)),),
            ("Nested object list",
             {'children': [{'n': 1}], 'n': 0, },
             FakeObject(n=0, children=[FakeObject(n=1)])),
            ("Nested derived class",
             {'child': {"class": "OtherClass", 'n': 1}, 'n': 0, },
             FakeObject(n=0, child=FakeObject("OtherClass", n=1)),),
            ("Nested derived class list",
             {'children': [{"class": "OtherClass", 'n': 1}], 'n': 0, },
             FakeObject(n=0, children=[FakeObject("OtherClass", n=1)]))]

    @staticmethod
    def _serialize_test_fixtures():
        return VimUtilTest._deserialize_test_fixtures() + [
            ("Drop default",
             {'a': 'A', 'z': 'Z', },
             FakeObject(a='A', none=None, m=[], child=FakeObject(), z='Z'))]

    def test_serialize(self):
        for msg, d, obj in self._serialize_test_fixtures():
            ser = vim_util.serialize_object(obj, True, FakeObject.DEFAULT_TYPE)
            self.assertEqual(d, ser, msg)

    def test_deserialize(self):
        cf = FakeFactory()
        for msg, d, obj in self._deserialize_test_fixtures():
            res = vim_util.deserialize_object(cf, d, FakeObject.DEFAULT_TYPE)
            self.assertEqual(obj, res, msg)
