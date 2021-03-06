#!/usr/bin/env python
""" Vpp QUIC tests """

import unittest
import os
import subprocess
import signal
from framework import VppTestCase, VppTestRunner, running_extended_tests, \
    Worker
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class QUICAppWorker(Worker):
    """ QUIC Test Application Worker """
    process = None

    def __init__(self, build_dir, appname, args, logger, env={}):
        app = "%s/vpp/bin/%s" % (build_dir, appname)
        self.args = [app] + args
        super(QUICAppWorker, self).__init__(self.args, logger, env)

    def run(self):
        super(QUICAppWorker, self).run()

    def teardown(self, logger, timeout):
        if self.process is None:
            return False
        try:
            logger.debug("Killing worker process (pid %d)" % self.process.pid)
            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            self.join(timeout)
        except OSError as e:
            logger.debug("Couldn't kill worker process")
            return True
        return False


class QUICTestCase(VppTestCase):
    """ QUIC Test Case """
    @classmethod
    def setUpClass(cls):
        cls.extra_vpp_plugin_config.append("plugin quic_plugin.so { enable }")
        super(QUICTestCase, cls).setUpClass()

    def setUp(self):
        super(QUICTestCase, self).setUp()
        var = "VPP_BUILD_DIR"
        self.build_dir = os.getenv(var, None)
        if self.build_dir is None:
            raise Exception("Environment variable `%s' not set" % var)
        self.vppDebug = 'vpp_debug' in self.build_dir
        self.timeout = 20
        self.vapi.session_enable_disable(is_enabled=1)
        self.pre_test_sleep = 0.3
        self.post_test_sleep = 0.2

        self.create_loopback_interfaces(2)
        self.uri = "quic://%s/1234" % self.loop0.local_ip4
        table_id = 1
        for i in self.lo_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()

            i.set_table_ip4(table_id)
            i.config_ip4()
            table_id += 1

        # Configure namespaces
        self.vapi.app_namespace_add_del(namespace_id=b"server",
                                        sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add_del(namespace_id=b"client",
                                        sw_if_index=self.loop1.sw_if_index)

        # Add inter-table routes
        self.ip_t01 = VppIpRoute(self, self.loop1.local_ip4, 32,
                                 [VppRoutePath("0.0.0.0",
                                               0xffffffff,
                                               nh_table_id=2)], table_id=1)
        self.ip_t10 = VppIpRoute(self, self.loop0.local_ip4, 32,
                                 [VppRoutePath("0.0.0.0",
                                               0xffffffff,
                                               nh_table_id=1)], table_id=2)
        self.ip_t01.add_vpp_config()
        self.ip_t10.add_vpp_config()
        self.logger.debug(self.vapi.cli("show ip fib"))

    def tearDown(self):
        self.vapi.session_enable_disable(is_enabled=0)
        # Delete inter-table routes
        self.ip_t01.remove_vpp_config()
        self.ip_t10.remove_vpp_config()

        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        super(QUICTestCase, self).tearDown()


class QUICEchoInternalTestCase(QUICTestCase):
    """QUIC Echo Internal Test Case"""

    def setUp(self):
        super(QUICEchoInternalTestCase, self).setUp()
        self.client_args = "uri %s fifo-size 64 test-bytes appns client" \
            % self.uri
        self.server_args = "uri %s fifo-size 64 appns server" % self.uri

    def server(self, *args):
        error = self.vapi.cli(
            "test echo server %s %s" %
            (self.server_args, ' '.join(args)))
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

    def client(self, *args):
        error = self.vapi.cli(
            "test echo client %s %s" %
            (self.client_args, ' '.join(args)))
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)


class QUICEchoInternalTransferTestCase(QUICEchoInternalTestCase):
    """QUIC Echo Internal Transfer Test Case"""
    def test_quic_internal_transfer(self):
        self.server()
        self.client("no-output", "mbytes", "2")


class QUICEchoInternalSerialTestCase(QUICEchoInternalTestCase):
    """QUIC Echo Internal Serial Transfer Test Case"""
    def test_quic_serial_internal_transfer(self):
        self.server()
        self.client("no-output", "mbytes", "2")
        self.client("no-output", "mbytes", "2")
        self.client("no-output", "mbytes", "2")
        self.client("no-output", "mbytes", "2")
        self.client("no-output", "mbytes", "2")


class QUICEchoInternalMStreamTestCase(QUICEchoInternalTestCase):
    """QUIC Echo Internal MultiStream Test Case"""
    def test_quic_internal_multistream_transfer(self):
        self.server()
        self.client("nclients", "10", "mbytes", "1", "no-output")


class QUICEchoExternalTestCase(QUICTestCase):
    extra_vpp_punt_config = ["session", "{", "evt_qs_memfd_seg", "}"]
    quic_setup = "default"

    def setUp(self):
        super(QUICEchoExternalTestCase, self).setUp()
        common_args = [
            "uri",
            self.uri,
            "fifo-size",
            "64",
            "test-bytes:assert",
            "socket-name",
            self.api_sock]
        self.server_echo_test_args = common_args + \
            ["server", "appns", "server", "quic-setup", self.quic_setup]
        self.client_echo_test_args = common_args + \
            ["client", "appns", "client", "quic-setup", self.quic_setup]

    def server(self, *args):
        _args = self.server_echo_test_args + list(args)
        self.worker_server = QUICAppWorker(
            self.build_dir,
            "vpp_echo",
            _args,
            self.logger)
        self.worker_server.start()
        self.sleep(self.pre_test_sleep)

    def client(self, *args):
        _args = self.client_echo_test_args + list(args)
        # self.client_echo_test_args += "use-svm-api"
        self.worker_client = QUICAppWorker(
            self.build_dir,
            "vpp_echo",
            _args,
            self.logger)
        self.worker_client.start()
        self.worker_client.join(self.timeout)
        self.worker_server.join(self.timeout)
        self.sleep(self.post_test_sleep)

    def validate_external_test_results(self):
        self.logger.info(
            "Client worker result is `%s'" %
            self.worker_client.result)
        server_result = self.worker_server.result
        client_result = self.worker_client.result
        server_kill_error = False
        if self.worker_server.result is None:
            server_kill_error = self.worker_server.teardown(
                self.logger, self.timeout)
        if self.worker_client.result is None:
            self.worker_client.teardown(self.logger, self.timeout)
        self.assertEqual(server_result, 0, "Wrong server worker return code")
        self.assertIsNotNone(
            client_result,
            "Timeout! Client worker did not finish in %ss" %
            self.timeout)
        self.assertEqual(client_result, 0, "Wrong client worker return code")
        self.assertFalse(server_kill_error, "Server kill errored")


class QUICEchoExternalTransferTestCase(QUICEchoExternalTestCase):
    """QUIC Echo External Transfer Test Case"""
    def test_quic_external_transfer(self):
        self.server()
        self.client()
        self.validate_external_test_results()


class QUICEchoExternalServerStreamTestCase(QUICEchoExternalTestCase):
    """QUIC Echo External Transfer Server Stream Test Case"""
    quic_setup = "serverstream"

    def test_quic_external_transfer_server_stream(self):
        self.server("TX=1Kb", "RX=0")
        self.client("TX=0", "RX=1Kb")
        self.validate_external_test_results()


class QUICEchoExternalServerStreamWorkersTestCase(QUICEchoExternalTestCase):
    """QUIC Echo External Transfer Server Stream MultiWorker Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_external_transfer_server_stream_multi_workers(self):
        self.server("nclients", "4/4", "TX=1Kb", "RX=0")
        self.client("nclients", "4/4", "TX=0", "RX=1Kb")
        self.validate_external_test_results()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
