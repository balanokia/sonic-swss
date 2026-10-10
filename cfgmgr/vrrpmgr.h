#pragma once

#include "orch.h"
#include "producerstatetable.h"
#include "vrrpintf.h"

#include <cstdint>
#include <map>
#include <string>
#include <tuple>

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
    struct VrrpKey
    {
        std::string parent;
        uint8_t vrid;

        bool operator<(const VrrpKey &other) const
        {
            return std::tie(parent, vrid) < std::tie(other.parent, other.vrid);
        }

        bool operator==(const VrrpKey &other) const
        {
            return parent == other.parent && vrid == other.vrid;
        }
    };

    Table m_appPortTable;
    Table m_statePortTable, m_stateVlanTable, m_stateLagTable;

    std::map<VrrpKey, VrrpIntfConf> m_vrrpList;

    void doTask(Consumer &consumer);

    bool setIntfArpAccept(const std::string &intf_alias, const bool arp_accept = true);
    bool extractPrefixFromAddrLine(const std::string &line, bool is_ipv4, IpPrefix &prefix);
    bool resolveParentPrefixLen(const std::string &intf_alias, const IpAddress &vip, int &prefix_len);
    bool deriveRuntimeVipPrefix(const std::string &intf_alias, const IpAddress &vip, IpPrefix &runtime_vip);
    bool getVirtualInterfaceIps(const std::string &vrrp_name, bool is_ipv4, std::set<IpPrefix> &vips);

    bool setVrrpIntf(const std::string &intf_alias, const uint8_t vrid, const bool is_ipv4,
        const std::set<IpAddress> &vip_list, const std::string &admin_status);
    bool removeVrrpIntf(const std::string &intf_alias, const uint8_t vrid, const bool is_ipv4);

    bool addVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name, const MacAddress &vrrp_mac, bool is_ipv4);
    bool delVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name);
    bool addVirtualInterfaceIp(const std::string &vrrp_name, const IpPrefix &ip_addr);
    bool delVirtualInterfaceIp(const std::string &vrrp_name, const IpPrefix &ip_addr);
    bool setVirtualInterfaceAddrgenMode(const std::string &vrrp_name, bool is_ipv4);
    bool setVirtualInterfaceAdminStatus(const std::string &vrrp_name, const std::string &admin_status);
    bool setVirtualInterfaceVrf(const std::string &vrrp_name, const std::string &vrf_name);

    bool isIntfStateOk(const std::string &intf_alias);
    bool isVrrpOnIntf(const std::string &intf_alias);

    bool parseVrid(const std::string &vrid, uint8_t &canonical_vrid);
    void parseVrrpMac(const uint8_t vrid, const bool is_ipv4, MacAddress& vrrp_mac);
    bool generateParentScopedVrrpName(const unsigned int parent_ifindex, const uint8_t vrid,
                                      const bool is_ipv4, std::string &vrrp_name);
    bool reconcileVirtualInterface(const std::string &intf_alias, const unsigned int parent_ifindex,
                                   const std::string &parent_scoped_name, const MacAddress &vrrp_mac,
                                   std::string &selected_name, bool &create_required);
};

}
