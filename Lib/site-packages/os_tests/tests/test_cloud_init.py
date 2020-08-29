import unittest
from os_tests.libs import utils_lib

class TestCloudInit(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)

        cmd = "sudo systemctl is-enabled cloud-init-local"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "check cloud-init-local is enabled")

    def test_check_cloudinit_ds_identify_found(self):
        '''
        polarion_id:
        bz#: 1746627
        check ds-identify run and ret found
        '''
        cmd = 'sudo cat /run/cloud-init/cloud-init-generator.log'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='ds-identify _RET=found',
                    msg='check /run/cloud-init/cloud-init-generator.log')

    def test_check_cloudinit_log_imdsv2(self):
        '''
        polarion_id:
        bz#: 1810704
        check cloud-init use imdsv2 in aws
        '''
        cmd = "sudo grep -Ri amazon /sys/devices/virtual/dmi/id/bios*"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "Only used in EC2 platform")
        cmd = "sudo rpm -ql cloud-init|grep -w DataSourceEc2.py"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Get DataSourceEc2.py')
        cmd = "sudo cat " + output + "|grep IMDSv2"
        utils_lib.run_cmd(self, cmd,
                    cancel_kw="Fetching Ec2 IMDSv2 API Token",
                    msg='Check IMDSv2 support')
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_kw='Fetching Ec2 IMDSv2 API Token,X-aws-ec2-metadata-token',
                    msg='check /var/log/cloud-init.log')

    def test_check_cloudinit_log_unexpected(self):
        '''
        polarion_id:
        bz#: 1827207
        check no unexpected error log in cloudinit logs
        '''
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='unexpected',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='unexpected',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_critical(self):
        '''
        polarion_id:
        bz#: 1827207
        check no critical log in cloudinit logs
        '''
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='CRITICAL',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='CRITICAL',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_warn(self):
        '''
        polarion_id:
        bz#: 1821999
        check no warning log in cloudinit logs
        '''
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='WARNING',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='WARNING',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_error(self):
        '''
        polarion_id:
        bz#: 1821999
        check no error log in cloudinit logs
        '''
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='ERROR',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='ERROR',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_metadata(self):
        '''
        polarion_id:
        https://cloudinit.readthedocs.io/en/latest/topics/datasources/ec2.html
        '''
        cmd = r"curl http://169.254.169.254/latest/meta-data/instance-type"

        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw="Not Found")

    def test_check_output_isexist(self):
        '''
        polarion_id:
        bz#: 1626117
        check whether /var/log/cloud-init-output.log exists
        '''
        utils_lib.run_cmd(self,
                    'uname -r',
                    cancel_not_kw='el7,el6',
                    msg='cancel it in RHEL7')
        cmd = 'sudo cat /var/log/cloud-init-output.log'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_kw='Datasource DataSourceEc2Local',
                    msg='check /var/log/cloud-init-output.log exists status')

    def test_check_cloudinit_service_status(self):
        '''
        polarion_id:
        bz#: 1829713
        The 4 cloud-init services status should be "active"
        '''
        service_list = ['cloud-init-local',
                        'cloud-init',
                        'cloud-config',
                        'cloud-final']
        for service in service_list:
            cmd = "sudo systemctl status %s" % service
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='Active: active', msg = "check %s status" % service)
            cmd = "sudo systemctl is-active %s" % service
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='active', msg = "check %s status" % service)
        

if __name__ == '__main__':
    unittest.main()