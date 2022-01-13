# Copyright (c) 2022 SAP SE
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

from datetime import date, datetime
import json
import suds.sudsobject

from oslo_vmware import vim_util


def _custom_serializer(obj):
    """Custom serialiser for objects not serialisable by default"""

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError("{!r} is not JSON serializable".format(obj))


class _JsonPrinter(object):
    def tostr(self, obj, indent=-2):
        """Get s string representation of object."""
        return json.dumps(vim_util.serialize_object(obj),
                          default=_custom_serializer)


suds.sudsobject.Printer = _JsonPrinter
