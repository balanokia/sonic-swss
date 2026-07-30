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

struct VrrpParentTokenInfo
{
    char parent_type{'e'};
    unsigned int token{0};
    unsigned int ref_count{0};
};

struct VrrpTypeAllocator
{
    unsigned int next_token{0};
    std::map<unsigned int, bool> used_tokens;
    std::map<unsigned int, bool> free_tokens;
};

class VrrpMgr : public Orch
{
public:
    VrrpMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const std::vector<std::string> &tableNames);
    using Orch::doTask;

private:
    Table m_appPortTable;
    Table m_statePortTable, m_stateVlanTable, m_stateLagTable;

    /* <ifname|vid, VrrpIntfConf> */
    std::map<std::string, VrrpIntfConf> m_vrrpList;
    std::map<std::string, VrrpParentTokenInfo> m_parentTokenMap;
    std::map<char, VrrpTypeAllocator> m_typeAllocators;

    void doTask(Consumer &consumer);
    
    bool setIntfArpAccept(const std::string &intf_alias, const bool arp_accept = true);

    bool setVrrpIntf(const std::string &intf_alias, const std::string &vrid, const bool is_ipv4, 
        const std::set<IpPrefix> &vip_list, const std::string &admin_status);
    bool removeVrrpIntf(const std::string &intf_alias, const std::string &vrid, const bool is_ipv4);

    bool addVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name, const MacAddress &vrrp_mac, bool is_ipv4);
    bool delVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name);
    bool addVirtualInterfaceIp(const std::string &vrrp_name, const IpPrefix &ip_addr);
    bool delVirtualInterfaceIp(const std::string &vrrp_name, const IpPrefix &ip_addr);
    bool setVirtualInterfaceAdminStatus(const std::string &vrrp_name, const std::string &admin_status);
    bool setVirtualInterfaceVrf(const std::string &vrrp_name, const std::string &vrf_name);

    bool isIntfStateOk(const std::string &intf_alias);
    std::string makeVrrpListKey(const std::string &intf_alias, const std::string &vrid) const;
    bool isVrrpOnIntf(const std::string &intf_alias);
    char classifyParentType(const std::string &intf_alias) const;
    bool acquireParentToken(const std::string &intf_alias, char &parent_type, unsigned int &token);
    bool releaseParentToken(const std::string &intf_alias);
    std::string buildTokenizedVrrpName(const std::string &vrid, bool is_ipv4, char parent_type, unsigned int token) const;

    bool parseVrrpMac(const std::string &vrid, const bool is_ipv4, MacAddress& vrrp_mac);
};

}
