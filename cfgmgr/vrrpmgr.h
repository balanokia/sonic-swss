#pragma once

#include "orch.h"
#include "producerstatetable.h"
#include "vrrpintf.h"

#include <map>
#include <string>

namespace swss {

struct VrrpIntfEntry
{
    std::set<IpPrefix> vips;
    std::string admin_status{};
};

struct VrrpIntfConf
{
    std::string alias{};

    VrrpIntf vrrp4;
    VrrpIntfEntry vrrp4_entry;

    VrrpIntf vrrp6;
    VrrpIntfEntry vrrp6_entry;

    VrrpIntfConf()
    {
        vrrp4 = VrrpIntf();
        vrrp4_entry = VrrpIntfEntry();
        vrrp6 = VrrpIntf();
        vrrp6_entry = VrrpIntfEntry();
    }
};

class VrrpMgr : public Orch
{
public:
    VrrpMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const std::vector<std::string> &tableNames);
    using Orch::doTask;

private:
    Table m_appPortTable;
    Table m_statePortTable, m_stateVlanTable, m_stateLagTable;

    /* <vid, VrrpIntfConf> */ 
    std::map<std::string, VrrpIntfConf> m_vrrpList;

    /* VRRP macvlans with IPv4 host-route VIP needing arp_ignore=1 (value unused) */
    std::map<std::string, bool> m_hostRouteArpMacvlans;
    /* Saved all.arp_ignore when temporarily lowered for host-route VIPs; -1 = unset */
    int m_savedAllArpIgnore;
    /* SONiC image default (90-sonic.conf); restore on VRRP cleanup to harden ARP */
    static const int SONIC_DEFAULT_ARP_IGNORE = 2;

    void doTask(Consumer &consumer);
    
    bool setIntfArpAccept(const std::string &intf_alias, const bool arp_accept = true);
    bool setVrrpMacvlanHostRouteArp(const std::string &vrrp_name, bool enable);
    bool restoreSonicDefaultAllArpIgnore();

    bool setVrrpIntf(const std::string &intf_alias, const std::string &vrid, const bool is_ipv4, 
        const std::set<IpPrefix> &vip_list, const std::string &admin_status);
    bool removeVrrpIntf(const std::string &intf_alias, const std::string &vrid, const bool is_ipv4);

    bool addVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name, const MacAddress &vrrp_mac, bool is_ipv4);
    bool delVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name);
    bool addVirtualInterfaceIp(const std::string &vrid, const IpPrefix &ip_addr);
    bool delVirtualInterfaceIp(const std::string &vrid, const IpPrefix &ip_addr);
    bool setVirtualInterfaceAdminStatus(const std::string &vrrp_name, const std::string &admin_status);
    bool setVirtualInterfaceVrf(const std::string &vrrp_name, const std::string &vrf_name);

    bool isIntfStateOk(const std::string &intf_alias);
    bool isVrrpOnIntf(const std::string &intf_alias);

    bool parseVrrpMac(const std::string &vrid, const bool is_ipv4, MacAddress& vrrp_mac);
};

}
