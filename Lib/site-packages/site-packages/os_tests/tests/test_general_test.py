import unittest
from os_tests.libs import utils_lib

class TestGeneralTest(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)

    def test_change_clocksource(self):
        '''
        :avocado: tags=test_change_clocksource,fast_check
        polarion_id:
        '''
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource'

        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check current clock source')
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
available_clocksource'

        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        for clocksource in output.split(' '):
            cmd = 'echo %s > /sys/devices/system/clocksource/clocksource0/\
current_clocksource' % clocksource
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Change clocksource to %s' % clocksource)
            cmd = 'cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource'

            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw=clocksource,
                        msg='Check current clock source')
        utils_lib.run_cmd(self, 'dmesg|tail -30', expect_ret=0)

    def test_change_tracer(self):
        '''
        no hang happen
        polarion_id:
        bz#: 1650273
        '''
        cmd = 'sudo mount -t debugfs nodev /sys/kernel/debug'
        utils_lib.run_cmd(self, cmd, msg='mount debugfs')

        cmd = 'sudo cat /sys/kernel/debug/tracing/current_tracer'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check current tracer')
        cmd = 'sudo cat /sys/kernel/debug/tracing/available_tracers'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        for tracer in output.split(' '):
            tracer = tracer.rstrip('\n')
            cmd = 'echo %s > /sys/kernel/debug/tracing/current_tracer' % tracer
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Change tracer to %s' % tracer)
            cmd = 'sudo cat /sys/kernel/debug/tracing/current_tracer'

            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw=tracer,
                        msg='Check current tracer')
        utils_lib.run_cmd(self, 'dmesg|tail -30', expect_ret=0)

    def test_cpupower_exception(self):
        '''
        No exception when run cpupower command
        polarion_id: N/A
        bz#: 1626505, 1659883
        '''
        cmd = "sudo cpupower info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')
        cmd = "sudo cpupower idle-info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')
        cmd = "sudo cpupower frequency-info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')

    def test_xenfs_write_inability(self):
        '''
        polarion_id:
        BZ# 1663266
        '''
        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_kw="Xen",
                    msg="Only run in xen instance")

        utils_lib.run_cmd(self, 'sudo umount /proc/xen')
        cmd = r'sudo mount -t xenfs xenfs /proc/xen/'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        script_str = '''
#!/usr/bin/env python

import os
import struct

if __name__ == "__main__":
    fd = os.open("/proc/xen/xenbus", os.O_RDWR)
    # end a fake transaction
    os.write(fd, struct.pack("<IIII", 7, 2, 1234, 0))
        '''
        utils_lib.run_cmd(self, "echo '%s' > t.py" % script_str, expect_ret=0)
        utils_lib.run_cmd(self, 'sudo python3 t.py')
        utils_lib.run_cmd(self, "dmesg", expect_not_kw='Call Trace')

if __name__ == '__main__':
    unittest.main()