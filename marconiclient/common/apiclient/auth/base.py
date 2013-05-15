# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
# Copyright 2013 Spanish National Research Council.
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

# E0202: An attribute inherited from %s hide this method
# pylint: disable=E0202

import abc
import argparse
import logging
import os

from stevedore import extension

from marconiclient.common.apiclient import exceptions


logger = logging.getLogger(__name__)


_discovered_plugins = {}


def discover_auth_systems():
    """Discover the available auth-systems.

    This won't take into account the old style auth-systems.
    """
    global _discovered_plugins
    _discovered_plugins = {}

    def add_plugin(ext):
        _discovered_plugins[ext.name] = ext.plugin

    mgr = extension.ExtensionManager("marconiclient.common.apiclient.auth")
    mgr.map(add_plugin)


def load_auth_system_opts(parser):
    """Load options needed by the available auth-systems into a parser.

    This function will try to populate the parser with options from the
    available plugins.
    """
    group = parser.add_argument_group("Common auth options")
    BaseAuthPlugin.add_common_opts(group)
    for name, auth_plugin in _discovered_plugins.iteritems():
        group = parser.add_argument_group(
            "Auth-system '%s' options" % name,
            conflict_handler="resolve")
        auth_plugin.add_opts(group)


def load_plugin(auth_system):
    try:
        plugin_class = _discovered_plugins[auth_system]
    except KeyError:
        raise exceptions.AuthSystemNotFound(auth_system)
    return plugin_class()


class BaseAuthPlugin(object):
    """Base class for authentication plugins.

    An authentication plugin needs to override at least the authenticate
    method to be a valid plugin.
    """

    __metaclass__ = abc.ABCMeta

    auth_system = None
    opt_names = []
    common_opt_names = [
        "auth_system",
        "username",
        "password",
        "tenant_name",
        "token",
        "auth_url",
    ]

    def __init__(self, **kwargs):
        self.opts = dict((name, kwargs.get(name))
                         for name in self.opt_names)

    @staticmethod
    def _parser_add_opt(parser, opt):
        """Add an option to parser in two variants.

        :param opt: option name (with underscores)
        """
        dashed_opt = opt.replace("_", "-")
        env_var = "OS_%s" % opt.upper()
        arg_default = os.environ.get(env_var, "")
        arg_help = "Defaults to env[%s]." % env_var
        parser.add_argument(
            "--os-%s" % dashed_opt,
            metavar="<%s>" % dashed_opt,
            default=arg_default,
            help=arg_help)
        parser.add_argument(
            "--os_%s" % opt,
            metavar="<%s>" % dashed_opt,
            help=argparse.SUPPRESS)

    @classmethod
    def add_opts(cls, parser):
        """Populate the parser with the options for this plugin.
        """
        for opt in cls.opt_names:
            if opt not in BaseAuthPlugin.common_opt_names:
                cls._parser_add_opt(parser, opt)

    @classmethod
    def add_common_opts(cls, parser):
        """Add options that are common for several plugins.
        """
        for opt in cls.common_opt_names:
            cls._parser_add_opt(parser, opt)

    @staticmethod
    def get_opt(opt_name, args):
        """Return option name and value.

        :param opt_name: name of the option, e.g., "username"
        :param args: parsed arguments
        """
        return (opt_name, getattr(args, "os_%s" % opt_name, None))

    def parse_opts(self, args):
        """Parse the actual auth-system options if any.

        This method is expected to populate the attribute self.opts with a
        dict containing the options and values needed to make authentication.
        """
        return dict(map(self.get_opt, self.opt_names))

    @abc.abstractmethod
    def authenticate(self, http_client):
        """Authenticate using plugin defined method."""
