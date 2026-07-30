import time
import json
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
        self.addremove_vrrp6_instance_vip("Ethernet8", 8, "fc00::8/126")

        # check kernel macvlan device info
        output = dvs.runcmd(['sh', '-c', "ip -d link show type macvlan | grep -E 'Vrrp6-8-.*@Ethernet8'"])
        assert "@Ethernet8" in output
        output = dvs.runcmd(['sh', '-c', "ip -6 address show dev $(ip -d link show type macvlan | awk '/Vrrp6-8-.*@Ethernet8/ {print $2}' | tr -d ':')"])
        assert "fc00::8/126" in output

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
        output = dvs.runcmd(['sh', '-c', "ip -d link show type macvlan | grep -E 'Vrrp4-8-.*@Ethernet8'"])
        assert "@Ethernet8" in output
        output = dvs.runcmd(['sh', '-c', "ip -4 address show dev $(ip -d link show type macvlan | awk '/Vrrp4-8-.*@Ethernet8/ {print $2}' | tr -d ':')"])
        assert "8.8.8.1/24" in output

        # remove vrrp instance
        self.remove_vrrp_instance("Ethernet8", 8)

        # remove IP from interface
        self.remove_ip_address("Ethernet8", "8.8.8.8/24")

        # remove interface
        self.remove_l3_intf("Ethernet8")

    def test_VrrpSameVidDifferentInterfaces(self, dvs, testlog):
        self.setup_db(dvs)

        self.create_l3_intf("Ethernet8", "")
        self.create_l3_intf("Ethernet12", "")

        self.set_admin_status(dvs, "Ethernet8", "up")
        self.set_admin_status(dvs, "Ethernet12", "up")

        self.add_ip_address("Ethernet8", "8.8.8.8/24")
        self.add_ip_address("Ethernet12", "12.12.12.12/24")
        time.sleep(2)

        self.addremove_vrrp_instance_vip("Ethernet8", 8, "8.8.8.1/24")
        self.addremove_vrrp_instance_vip("Ethernet12", 8, "12.12.12.1/24")
        time.sleep(2)

        output = dvs.runcmd(['sh', '-c', "ip -d link show type macvlan | grep -E 'Vrrp4-8-.*@(Ethernet8|Ethernet12)'"])
        assert "@Ethernet8" in output
        assert "@Ethernet12" in output

        self.remove_vrrp_instance("Ethernet8", 8)
        self.remove_vrrp_instance("Ethernet12", 8)

        self.remove_ip_address("Ethernet8", "8.8.8.8/24")
        self.remove_ip_address("Ethernet12", "12.12.12.12/24")

        self.remove_l3_intf("Ethernet8")
        self.remove_l3_intf("Ethernet12")

    def test_Vrrp6SameVidDifferentInterfaces(self, dvs, testlog):
        self.setup_db(dvs)

        self.create_l3_intf("Ethernet8", "")
        self.create_l3_intf("Ethernet12", "")

        self.set_admin_status(dvs, "Ethernet8", "up")
        self.set_admin_status(dvs, "Ethernet12", "up")

        self.add_ip_address("Ethernet8", "fc00::8/64")
        self.add_ip_address("Ethernet12", "fc00::12/64")
        time.sleep(2)

        self.addremove_vrrp6_instance_vip("Ethernet8", 29, "fc00::88/64")
        self.addremove_vrrp6_instance_vip("Ethernet12", 29, "fc00::99/64")
        time.sleep(2)

        output = dvs.runcmd(['sh', '-c', "ip -d link show type macvlan | grep -E 'Vrrp6-29-.*@(Ethernet8|Ethernet12)'"])
        assert "@Ethernet8" in output
        assert "@Ethernet12" in output

        self.remove_vrrp6_instance("Ethernet8", 29)
        self.remove_vrrp6_instance("Ethernet12", 29)

        self.remove_ip_address("Ethernet8", "fc00::8/64")
        self.remove_ip_address("Ethernet12", "fc00::12/64")

        self.remove_l3_intf("Ethernet8")
        self.remove_l3_intf("Ethernet12")
