import time
import json
import re
import pytest

from swsscommon import swsscommon

class TestVrrp(object):
    def setup_db(self, dvs):
        self.pdb = swsscommon.DBConnector(0, dvs.redis_sock, 0)
        self.adb = swsscommon.DBConnector(1, dvs.redis_sock, 0)
        self.cdb = swsscommon.DBConnector(4, dvs.redis_sock, 0)

    def set_admin_status(self, dvs, interface, status):
        if interface.startswith("PortChannel"):
            tbl_name = "PORTCHANNEL"
        elif interface.startswith("Vlan"):
            tbl_name = "VLAN"
        else:
            tbl_name = "PORT"
        tbl = swsscommon.Table(self.cdb, tbl_name)
        fvs = swsscommon.FieldValuePairs([("admin_status", status)])
        tbl.set(interface, fvs)
        time.sleep(1)

        # when using FRR, route cannot be inserted if the neighbor is not
        # connected. thus it is mandatory to force the interface up manually
        if interface.startswith("PortChannel"):
            dvs.runcmd("bash -c 'echo " + ("1" if status == "up" else "0") +\
                    " > /sys/class/net/" + interface + "/carrier'")
        time.sleep(1)

    def create_vrf(self, vrf_name):
        tbl = swsscommon.Table(self.adb, "ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER")
        initial_entries = set(tbl.getKeys())

        tbl = swsscommon.Table(self.cdb, "VRF")
        fvs = swsscommon.FieldValuePairs([('empty', 'empty')])
        tbl.set(vrf_name, fvs)
        time.sleep(1)

        tbl = swsscommon.Table(self.adb, "ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER")
        current_entries = set(tbl.getKeys())
        assert len(current_entries - initial_entries) == 1
        return list(current_entries - initial_entries)[0]

    def remove_vrf(self, vrf_name):
        tbl = swsscommon.Table(self.cdb, "VRF")
        tbl._del(vrf_name)
        time.sleep(1)

    def create_l3_intf(self, interface, vrf_name):
        if interface.startswith("PortChannel"):
            tbl_name = "PORTCHANNEL_INTERFACE"
        elif interface.startswith("Vlan"):
            tbl_name = "VLAN_INTERFACE"
        elif interface.startswith("Loopback"):
            tbl_name = "LOOPBACK_INTERFACE"
        else:
            tbl_name = "INTERFACE"
        if len(vrf_name) == 0:
            fvs = swsscommon.FieldValuePairs([("NULL", "NULL")])
        else:
            fvs = swsscommon.FieldValuePairs([("vrf_name", vrf_name)])
        tbl = swsscommon.Table(self.cdb, tbl_name)
        tbl.set(interface, fvs)
        time.sleep(1)

    def remove_l3_intf(self, interface):
        if interface.startswith("PortChannel"):
            tbl_name = "PORTCHANNEL_INTERFACE"
        elif interface.startswith("Vlan"):
            tbl_name = "VLAN_INTERFACE"
        elif interface.startswith("Loopback"):
            tbl_name = "LOOPBACK_INTERFACE"
        else:
            tbl_name = "INTERFACE"
        tbl = swsscommon.Table(self.cdb, tbl_name)
        tbl._del(interface)
        time.sleep(1)
    
    def add_ip_address(self, interface, ip):
        if interface.startswith("PortChannel"):
            tbl_name = "PORTCHANNEL_INTERFACE"
        elif interface.startswith("Vlan"):
            tbl_name = "VLAN_INTERFACE"
        elif interface.startswith("Loopback"):
            tbl_name = "LOOPBACK_INTERFACE"
        else:
            tbl_name = "INTERFACE"
        tbl = swsscommon.Table(self.cdb, tbl_name)
        fvs = swsscommon.FieldValuePairs([("NULL", "NULL")])
        tbl.set(interface + "|" + ip, fvs)
        time.sleep(1)

    def remove_ip_address(self, interface, ip):
        if interface.startswith("PortChannel"):
            tbl_name = "PORTCHANNEL_INTERFACE"
        elif interface.startswith("Vlan"):
            tbl_name = "VLAN_INTERFACE"
        elif interface.startswith("Loopback"):
            tbl_name = "LOOPBACK_INTERFACE"
        else:
            tbl_name = "INTERFACE"
        tbl = swsscommon.Table(self.cdb, tbl_name)
        tbl._del(interface + "|" + ip)
        time.sleep(1)

    def addremove_vrrp_instance_vip(self, interface, vid, vip):
        tbl_name = "VRRP"
        tbl = swsscommon.Table(self.cdb, tbl_name)
        fvs = swsscommon.FieldValuePairs([("vip", vip)])
        tbl.set(interface + "|" + str(vid), fvs)
        time.sleep(1)

    def addremove_vrrp6_instance_vip(self, interface, vid, vip):
        tbl_name = "VRRP6"
        tbl = swsscommon.Table(self.cdb, tbl_name)
        fvs = swsscommon.FieldValuePairs([("vip", vip)])
        tbl.set(interface + "|" + str(vid), fvs)
        time.sleep(1)

    def remove_vrrp_instance(self, interface, vid):
        tbl_name = "VRRP"
        tbl = swsscommon.Table(self.cdb, tbl_name)
        tbl._del(interface + "|" + str(vid))
        time.sleep(1)

    def remove_vrrp6_instance(self, interface, vid):
        tbl_name = "VRRP6"
        tbl = swsscommon.Table(self.cdb, tbl_name)
        tbl._del(interface + "|" + str(vid))
        time.sleep(1)

    def find_vrrp_interface(self, dvs, prefix, parent, timeout=10):
        pattern = re.compile(r"^\d+:\s+([^:@]+)@" + re.escape(parent) + r":")
        deadline = time.time() + timeout
        while time.time() < deadline:
            rc, output = dvs.runcmd(['ip', '-o', 'link', 'show'])
            assert rc == 0
            for line in output.splitlines():
                match = pattern.match(line)
                if match and match.group(1).startswith(prefix):
                    return match.group(1)
            time.sleep(1)
        pytest.fail("VRRP interface {}*@{} was not created".format(prefix, parent))

    def base36_ifindex(self, ifindex):
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"
        encoded = ""
        while ifindex:
            ifindex, digit = divmod(ifindex, 36)
            encoded = digits[digit] + encoded
        assert len(encoded) <= 6
        return encoded.rjust(6, "0")

    def parent_scoped_vrrp_name(self, dvs, prefix, parent):
        rc, output = dvs.runcmd(['cat', '/sys/class/net/{}/ifindex'.format(parent)])
        assert rc == 0
        return prefix + self.base36_ifindex(int(output.strip()))

    def assert_vrrp_interface(self, dvs, prefix, parent, vip, mac, expected_name=None):
        vrrp_name = self.find_vrrp_interface(dvs, prefix, parent)
        if expected_name is None:
            expected_name = self.parent_scoped_vrrp_name(dvs, prefix, parent)
        assert vrrp_name == expected_name
        rc, output = dvs.runcmd(['ip', 'address', 'show', 'dev', vrrp_name])
        assert rc == 0
        assert vip in output
        assert mac in output
        return vrrp_name

    def wait_vrrp_interface_absent(self, dvs, vrrp_name, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            rc, _ = dvs.runcmd(['ip', 'link', 'show', 'dev', vrrp_name])
            if rc != 0:
                return
            time.sleep(1)
        pytest.fail("VRRP interface {} was not removed".format(vrrp_name))

    def test_VrrpDeterministicNameBoundaries(self):
        assert self.base36_ifindex(1) == "000001"
        assert self.base36_ifindex(2147483647) == "zik0zj"
        assert len("Vrrp4-255" + self.base36_ifindex(2147483647)) == 15

    def test_VrrpAddRemoveIpv6Address(self, dvs, testlog):
        self.setup_db(dvs)

        # create interface
        self.create_l3_intf("Ethernet8", "")

        # check application database
        tbl = swsscommon.Table(self.pdb, "INTF_TABLE")
        (status, fvs) = tbl.get("Ethernet8")
        assert status == True
        for fv in fvs:
            assert fv[0] != "vrf_name"

        # bring up interface
        # NOTE: For IPv6, only when the interface is up will the netlink message
        # get generated.
        self.set_admin_status(dvs, "Ethernet8", "up")

        # assign IP to interface
        self.add_ip_address("Ethernet8", "fc00::1/126")
        time.sleep(2)   # IPv6 netlink message needs longer time

        # add vrrp6 instance whith ipv6 address
        self.addremove_vrrp6_instance_vip("Ethernet8", 8, "fc00::2/126")

        # check kernel macvlan device info
        vrrp_name = self.assert_vrrp_interface(
            dvs, "Vrrp6-8", "Ethernet8", "fc00::2/126", "00:00:5e:00:02:08")

        # A SET must recreate a managed child that disappeared out of band.
        rc, _ = dvs.runcmd(['ip', 'link', 'del', vrrp_name])
        assert rc == 0
        self.addremove_vrrp6_instance_vip("Ethernet8", 8, "fc00::2/126")
        assert self.assert_vrrp_interface(
            dvs, "Vrrp6-8", "Ethernet8", "fc00::2/126",
            "00:00:5e:00:02:08") == vrrp_name

        # remove vrrp6 instance
        self.remove_vrrp6_instance("Ethernet8", 8)

        # remove IP from interface
        self.remove_ip_address("Ethernet8", "fc00::1/126")

        # remove interface
        self.remove_l3_intf("Ethernet8")

    def test_VrrpAddRemoveIpv4Address(self, dvs, testlog):
        self.setup_db(dvs)

        # create interface
        self.create_l3_intf("Ethernet8", "")

        # check application database
        tbl = swsscommon.Table(self.pdb, "INTF_TABLE")
        (status, fvs) = tbl.get("Ethernet8")
        assert status == True
        for fv in fvs:
            assert fv[0] != "vrf_name"

        # bring up interface
        # NOTE: For IPv4, only when the interface is up will the netlink message
        # get generated.
        self.set_admin_status(dvs, "Ethernet8", "up")

        # assign IP to interface
        self.add_ip_address("Ethernet8", "8.8.8.8/24")
        time.sleep(2)   # IPv4 netlink message needs longer time

        # add vrrp instance whith ipv4 address
        self.addremove_vrrp_instance_vip("Ethernet8", 8, "8.8.8.1/24")

        # check kernel macvlan device info
        vrrp_name = self.assert_vrrp_interface(
            dvs, "Vrrp4-8", "Ethernet8", "8.8.8.1/24", "00:00:5e:00:01:08")

        # Restart must adopt the existing parent-scoped link and its VIP.
        rc, _ = dvs.runcmd("supervisorctl restart vrrpmgrd")
        assert rc == 0
        time.sleep(2)
        assert self.assert_vrrp_interface(
            dvs, "Vrrp4-8", "Ethernet8", "8.8.8.1/24",
            "00:00:5e:00:01:08") == vrrp_name

        # Empty desired state after restart removes all managed VIPs and the
        # adopted child. Deleting the CONFIG_DB key afterwards is idempotent.
        self.addremove_vrrp_instance_vip("Ethernet8", 8, "")
        self.wait_vrrp_interface_absent(dvs, vrrp_name)
        self.remove_vrrp_instance("Ethernet8", 8)

        # remove IP from interface
        self.remove_ip_address("Ethernet8", "8.8.8.8/24")

        # remove interface
        self.remove_l3_intf("Ethernet8")

    def test_VrrpSameVridOnTwoInterfaces(self, dvs, testlog):
        self.setup_db(dvs)
        parents = [
            ("Ethernet8", "10.0.8.1/24", "10.0.8.254/24",
             "2001:db8:8::1/126", "2001:db8:8::2/126"),
            ("Ethernet12", "10.0.12.1/24", "10.0.12.254/24",
             "2001:db8:12::1/126", "2001:db8:12::2/126"),
        ]
        vrid = 19

        for parent, parent_v4, _, parent_v6, _ in parents:
            self.create_l3_intf(parent, "")
            self.set_admin_status(dvs, parent, "up")
            self.add_ip_address(parent, parent_v4)
            self.add_ip_address(parent, parent_v6)
        time.sleep(2)

        vrrp4_names = []
        vrrp6_names = []
        for parent, _, vip_v4, _, vip_v6 in parents:
            self.addremove_vrrp_instance_vip(parent, vrid, vip_v4)
            self.addremove_vrrp6_instance_vip(parent, vrid, vip_v6)
            vrrp4_names.append(self.assert_vrrp_interface(
                dvs, "Vrrp4-19", parent, vip_v4, "00:00:5e:00:01:13"))
            vrrp6_names.append(self.assert_vrrp_interface(
                dvs, "Vrrp6-19", parent, vip_v6, "00:00:5e:00:02:13"))

        assert len(set(vrrp4_names)) == len(parents)
        assert len(set(vrrp6_names)) == len(parents)

        # Removing one complete same-VRID tuple must leave the other parent's
        # independent v4/v6 tuple intact.
        self.remove_vrrp_instance(parents[0][0], vrid)
        self.remove_vrrp6_instance(parents[0][0], vrid)
        self.wait_vrrp_interface_absent(dvs, vrrp4_names[0])
        self.wait_vrrp_interface_absent(dvs, vrrp6_names[0])
        self.assert_vrrp_interface(
            dvs, "Vrrp4-19", parents[1][0], parents[1][2],
            "00:00:5e:00:01:13")
        self.assert_vrrp_interface(
            dvs, "Vrrp6-19", parents[1][0], parents[1][4],
            "00:00:5e:00:02:13")

        self.remove_vrrp_instance(parents[1][0], vrid)
        self.remove_vrrp6_instance(parents[1][0], vrid)
        for parent, parent_v4, _, parent_v6, _ in parents:
            self.remove_ip_address(parent, parent_v4)
            self.remove_ip_address(parent, parent_v6)
            self.remove_l3_intf(parent)
