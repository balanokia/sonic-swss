#include "logger.h"
#include "dbconnector.h"
#include "producerstatetable.h"
#include "tokenize.h"
#include "ipprefix.h"
#include "vrrpmgr.h"
#include "exec.h"
#include "shellcmd.h"
#include <swss/redisutility.h>
#include <swss/stringutility.h>
#include "linkcache.h"

#include <cstring>
#include <net/if.h>
#include <netlink/addr.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/socket.h>

using namespace std;
using namespace swss;

#define VLAN_PREFIX         "Vlan"
#define LAG_PREFIX          "PortChannel"
#define SUBINTF_LAG_PREFIX  "Po"
#define LOOPBACK_PREFIX     "Loopback"
#define VRF_PREFIX          "Vrf"

#define VRRP_V4_MAC_PREFIX "00:00:5e:00:01:"
#define VRRP_V6_MAC_PREFIX "00:00:5e:00:02:"

struct VrrpKernelLinkState
{
    bool exists = false;
    bool parent_matches = false;
    bool identity_matches = false;
};

static bool inspectKernelLink(struct nl_sock *sock, const std::string &name, unsigned int parent_ifindex,
                              const MacAddress &expected_mac, VrrpKernelLinkState &state)
{
    unsigned int ifindex = if_nametoindex(name.c_str());
    if (ifindex == 0)
    {
        return true;
    }

    struct rtnl_link *link = nullptr;
    int err = rtnl_link_get_kernel(sock, static_cast<int>(ifindex), nullptr, &link);
    if (err < 0)
    {
        SWSS_LOG_ERROR("Unable to inspect kernel link[%s]: %s", name.c_str(), nl_geterror(err));
        return false;
    }

    state.exists = true;
    state.parent_matches = static_cast<unsigned int>(rtnl_link_get_link(link)) == parent_ifindex;

    const char *kind = rtnl_link_get_type(link);
    struct nl_addr *address = rtnl_link_get_addr(link);
    bool kind_matches = kind != nullptr && strcmp(kind, "macvlan") == 0;
    bool mac_matches = address != nullptr && nl_addr_get_len(address) == 6 &&
                       memcmp(nl_addr_get_binary_addr(address), expected_mac.getMac(), 6) == 0;
    state.identity_matches = state.parent_matches && kind_matches && mac_matches;

    rtnl_link_put(link);
    return true;
}

static bool queryKernelLink(const std::string &name, unsigned int parent_ifindex,
                            const MacAddress &expected_mac, VrrpKernelLinkState &state)
{
    struct nl_sock *sock = nl_socket_alloc();
    if (sock == nullptr)
    {
        SWSS_LOG_ERROR("Unable to allocate netlink socket while inspecting link[%s]", name.c_str());
        return false;
    }

    int err = nl_connect(sock, NETLINK_ROUTE);
    if (err < 0)
    {
        SWSS_LOG_ERROR("Unable to connect netlink socket while inspecting link[%s]: %s",
                       name.c_str(), nl_geterror(err));
        nl_socket_free(sock);
        return false;
    }

    bool inspected = inspectKernelLink(sock, name, parent_ifindex, expected_mac, state);
    nl_close(sock);
    nl_socket_free(sock);
    return inspected;
}

static std::string getIpOnly(const std::string &ip_prefix)
{
    auto pos = ip_prefix.find('/');
    return pos == std::string::npos ? ip_prefix : ip_prefix.substr(0, pos);
}

VrrpMgr::VrrpMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const std::vector<std::string> &tableNames) : 
        Orch(cfgDb, tableNames),
        m_appPortTable(appDb, APP_PORT_TABLE_NAME),
        m_stateLagTable(stateDb, STATE_LAG_TABLE_NAME),
        m_stateVlanTable(stateDb, STATE_VLAN_TABLE_NAME),
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME)
{
}

bool VrrpMgr::setIntfArpAccept(const std::string &intf_alias, const bool arp_accept)
{
    stringstream cmd;
    string res;

    if (arp_accept)
    {
        cmd << ECHO_CMD << " 2 > /proc/sys/net/ipv4/conf/" << shellquote(intf_alias) << "/arp_announce && ";
        cmd << ECHO_CMD << " 2 > /proc/sys/net/ipv4/conf/" << shellquote(intf_alias) << "/rp_filter && ";
        cmd << ECHO_CMD << " 1 > /proc/sys/net/ipv4/conf/" << shellquote(intf_alias) << "/accept_local";
    }
    else
    {
        cmd << ECHO_CMD << " 0 > /proc/sys/net/ipv4/conf/" << shellquote(intf_alias) << "/arp_announce && ";
        cmd << ECHO_CMD << " 0 > /proc/sys/net/ipv4/conf/" << shellquote(intf_alias) << "/rp_filter && ";
        cmd << ECHO_CMD << " 0 > /proc/sys/net/ipv4/conf/" << shellquote(intf_alias) << "/accept_local";
    }

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to set intf arp %s on interface[%s], retry. Runtime error: %s", arp_accept ? "accept" : "default", intf_alias.c_str(), e.what());
        return false;
    }

    SWSS_LOG_INFO("Set vrrp arp %s on interface[%s]", arp_accept ? "accept" : "default", intf_alias.c_str());
    return true;
}

bool VrrpMgr::extractPrefixFromAddrLine(const std::string &line, bool is_ipv4, IpPrefix &prefix)
{
    const std::string marker = is_ipv4 ? " inet " : " inet6 ";
    auto pos = line.find(marker);
    if (pos == std::string::npos)
    {
        return false;
    }

    pos += marker.size();
    auto end = line.find(' ', pos);
    std::string token = (end == std::string::npos) ? line.substr(pos) : line.substr(pos, end - pos);
    if (token.empty())
    {
        return false;
    }

    prefix = IpPrefix(token);
    return true;
}

bool VrrpMgr::resolveParentPrefixLen(const std::string &intf_alias, const IpAddress &vip, int &prefix_len)
{
    std::stringstream cmd;
    std::string res;
    bool is_ipv4 = vip.isV4();

    cmd << IP_CMD << (is_ipv4 ? " -o -4 " : " -o -6 ")
        << " address show dev " << shellquote(intf_alias);

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_WARN("Unable to get parent address inventory on [%s], cmd '%s' failed rc=%d",
                      intf_alias.c_str(), cmd.str().c_str(), ret);
        return false;
    }

    std::istringstream output(res);
    std::string line;
    int best_match = -1;
    while (std::getline(output, line))
    {
        if (line.empty())
        {
            continue;
        }

        try
        {
            IpPrefix candidate;
            if (!extractPrefixFromAddrLine(line, is_ipv4, candidate))
            {
                continue;
            }
            if (!candidate.isAddressInSubnet(vip))
            {
                continue;
            }
            int mask = candidate.getMaskLength();
            if (mask > best_match)
            {
                best_match = mask;
            }
        }
        catch (const std::exception &e)
        {
            SWSS_LOG_DEBUG("Skip parent addr parse line [%s], reason: %s", line.c_str(), e.what());
        }
    }

    if (best_match < 0)
    {
        return false;
    }

    prefix_len = best_match;
    return true;
}

bool VrrpMgr::deriveRuntimeVipPrefix(const std::string &intf_alias, const IpAddress &vip, IpPrefix &runtime_vip)
{
    int plen = 0;
    if (!resolveParentPrefixLen(intf_alias, vip, plen))
    {
        return false;
    }
    runtime_vip = IpPrefix(vip.getIp(), plen);
    return true;
}

bool VrrpMgr::getVirtualInterfaceIps(const std::string &vrrp_name, bool is_ipv4, std::set<IpPrefix> &vips)
{
    stringstream cmd;
    string res;
    cmd << IP_CMD << (is_ipv4 ? " -o -4 " : " -o -6 ")
        << " address show dev " << shellquote(vrrp_name) << " scope global";

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Unable to inventory addresses on VRRP link[%s], cmd '%s' failed rc=%d",
                       vrrp_name.c_str(), cmd.str().c_str(), ret);
        return false;
    }

    istringstream output(res);
    string line;
    while (getline(output, line))
    {
        // Only user configured macvlan VRRP VIPs. Discard other adddresses
        if (line.find(" dynamic ") != string::npos ||
            line.find(" temporary ") != string::npos ||
            line.find(" mngtmpaddr ") != string::npos)
        {
            continue;
        }

        try
        {
            IpPrefix prefix;
            if (extractPrefixFromAddrLine(line, is_ipv4, prefix))
            {
                vips.insert(prefix);
            }
        }
        catch (const exception &e)
        {
            SWSS_LOG_ERROR("Unable to parse address inventory line[%s] on VRRP link[%s]: %s",
                           line.c_str(), vrrp_name.c_str(), e.what());
            return false;
        }
    }
    return true;
}

bool VrrpMgr::generateParentScopedVrrpName(const unsigned int parent_ifindex, const uint8_t vrid,
                                           const bool is_ipv4, std::string &vrrp_name)
{
    static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    static const size_t ifindex_width = 6;
    string encoded(ifindex_width, '0');
    unsigned int value = parent_ifindex;
    for (size_t pos = ifindex_width; pos > 0; --pos)
    {
        encoded[pos - 1] = digits[value % 36];
        value /= 36;
    }
    if (value != 0)
    {
        SWSS_LOG_ERROR("Parent ifindex[%u] exceeds six base36 digits", parent_ifindex);
        return false;
    }

    vrrp_name = join(vrrp_name_delimiter, (is_ipv4 ? VRRP_V4_PREFIX : VRRP_V6_PREFIX),
                     to_string(static_cast<unsigned int>(vrid))) + encoded;
    if (vrrp_name.size() >= IFNAMSIZ)
    {
        SWSS_LOG_ERROR("Generated VRRP interface name[%s] exceeds IFNAMSIZ", vrrp_name.c_str());
        return false;
    }
    return true;
}

bool VrrpMgr::reconcileVirtualInterface(const std::string &intf_alias, const unsigned int parent_ifindex,
                                        const std::string &parent_scoped_name, const MacAddress &vrrp_mac,
                                        std::string &selected_name, bool &create_required)
{
    VrrpKernelLinkState parent_scoped_state;
    if (!queryKernelLink(parent_scoped_name, parent_ifindex, vrrp_mac, parent_scoped_state))
    {
        return false;
    }

    if (parent_scoped_state.exists && !parent_scoped_state.identity_matches)
    {
        SWSS_LOG_ERROR("Parent-scoped VRRP link[%s] exists with unexpected kind, parent, or MAC",
                       parent_scoped_name.c_str());
        return false;
    }

    selected_name = parent_scoped_name;
    create_required = !parent_scoped_state.identity_matches;
    if (!create_required)
    {
        SWSS_LOG_INFO("Adopt parent-scoped VRRP link[%s] on[%s]",
                      selected_name.c_str(), intf_alias.c_str());
    }
    return true;
}

bool VrrpMgr::setVrrpIntf(const std::string &intf_alias, const uint8_t vrid, const bool is_ipv4,
    const std::set<IpAddress> &vip_list, const std::string &admin_status)
{
    const VrrpKey vrrp_key{intf_alias, vrid};
    const string vrid_str = to_string(static_cast<unsigned int>(vrid));
    VrrpIntfConf vrrp_conf;
    if (m_vrrpList.find(vrrp_key) == m_vrrpList.end())
    {
        vrrp_conf.alias = intf_alias;
    }
    else
    {
        vrrp_conf = m_vrrpList[vrrp_key];
    }
    auto &vrrp = is_ipv4 ? vrrp_conf.vrrp4 : vrrp_conf.vrrp6;
    auto &vrrp_entry = is_ipv4 ? vrrp_conf.vrrp4_entry : vrrp_conf.vrrp6_entry;
    auto persist_state = [&]() {
        if (vrrp_conf.vrrp4.isValid() || vrrp_conf.vrrp6.isValid())
        {
            m_vrrpList[vrrp_key] = vrrp_conf;
        }
        else
        {
            m_vrrpList.erase(vrrp_key);
        }
    };
    auto enforce_parent_arp = [&]() {
        persist_state();
        return setIntfArpAccept(intf_alias, isVrrpOnIntf(intf_alias));
    };

    // generate vmac and derive runtime vip prefix from kernel installed parent address. (not from config_db)
    std::set<IpAddress> valid_vip_hosts;
    auto is_ipv4_check = [is_ipv4](const IpAddress &has_vip){ return has_vip.isV4() == is_ipv4; };
    copy_if(vip_list.begin(), vip_list.end(), std::inserter(valid_vip_hosts, valid_vip_hosts.begin()), is_ipv4_check);

    set<IpPrefix> vaild_vips;
    for (const auto &vip_host : valid_vip_hosts)
    {
        try
        {
            IpPrefix runtime_prefix;
            if (deriveRuntimeVipPrefix(intf_alias, vip_host, runtime_prefix))
            {
                vaild_vips.insert(runtime_prefix);
            }
            else
            {
                int fallback_mask = vip_host.isV4() ? 32 : 128;
                SWSS_LOG_WARN("Parent prefixlen unresolved for [%s] vip [%s], fallback to host mask /%d",
                              intf_alias.c_str(), vip_host.to_string().c_str(), fallback_mask);
                vaild_vips.insert(IpPrefix(vip_host.getIp(), fallback_mask));
            }
        }
        catch (const std::exception &e)
        {
            SWSS_LOG_WARN("Skip vip [%s] on [%s], runtime prefix derive failed: %s",
                          vip_host.to_string().c_str(), intf_alias.c_str(), e.what());
        }
    }

    MacAddress vmac;
    parseVrrpMac(vrid, is_ipv4, vmac);

    unsigned int parent_ifindex = if_nametoindex(intf_alias.c_str());
    if (parent_ifindex == 0)
    {
        SWSS_LOG_WARN("Unable to resolve ifindex for parent interface[%s], retry", intf_alias.c_str());
        return false;
    }

    string parent_scoped_name;
    if (!generateParentScopedVrrpName(parent_ifindex, vrid, is_ipv4, parent_scoped_name))
    {
        return false;
    }
    if (vrrp.isValid())
    {
        VrrpKernelLinkState retained_state;
        if (!queryKernelLink(vrrp.getVrrpName(), parent_ifindex, vmac, retained_state))
        {
            return false;
        }
        if (!retained_state.exists)
        {
            SWSS_LOG_WARN("Stored VRRP link[%s] disappeared; recreate on[%s]",
                          vrrp.getVrrpName().c_str(), intf_alias.c_str());
            vrrp = VrrpIntf();
            vrrp_entry = VrrpIntfEntry();
        }
        else if (!retained_state.identity_matches)
        {
            if (vrrp.getVrrpName() == parent_scoped_name || retained_state.parent_matches)
            {
                SWSS_LOG_ERROR("Stored VRRP link[%s] has unexpected parent, kind, or MAC",
                               vrrp.getVrrpName().c_str());
                return false;
            }

            // The parent was recreated with a new ifindex. Check this edge case
            SWSS_LOG_WARN("Stored VRRP link[%s] belongs to an old parent; reconcile on[%s]",
                          vrrp.getVrrpName().c_str(), intf_alias.c_str());
            vrrp = VrrpIntf();
            vrrp_entry = VrrpIntfEntry();
        }
    }

    if (!vrrp.isValid())
    {
        string selected_name;
        bool create_required = false;
        if (!reconcileVirtualInterface(intf_alias, parent_ifindex, parent_scoped_name,
                                       vmac, selected_name, create_required))
        {
            return false;
        }

        if (!create_required || !vaild_vips.empty())
        {
            vrrp = VrrpIntf(intf_alias, selected_name, vrid_str, is_ipv4, vmac.to_string());
            if (!vrrp.isValid())
            {
                SWSS_LOG_WARN("parse new vrrp intf fail, intf: %s, vrid: %s, is ipv4:%d",
                              intf_alias.c_str(), vrid_str.c_str(), is_ipv4);
                return false;
            }
            if (create_required && !addVirtualInterface(intf_alias, vrrp.getVrrpName(), vmac, is_ipv4))
            {
                vrrp = VrrpIntf();
                return false;
            }
        }
    }

    vrrp_entry.admin_status = admin_status;
    if (vrrp.isValid())
    {
        set<IpPrefix> kernel_vips;
        if (!getVirtualInterfaceIps(vrrp.getVrrpName(), is_ipv4, kernel_vips))
        {
            enforce_parent_arp();
            return false;
        }
        vrrp_entry.vips = kernel_vips;

        if (!setVirtualInterfaceAddrgenMode(vrrp.getVrrpName(), is_ipv4))
        {
            enforce_parent_arp();
            return false;
        }
        if (!setVirtualInterfaceAdminStatus(vrrp.getVrrpName(), admin_status))
        {
            enforce_parent_arp();
            return false;
        }
    }

    set<IpPrefix> original_vips = vrrp_entry.vips;
    set<IpPrefix> diff_vips;
    set_symmetric_difference(original_vips.begin(), original_vips.end(), vaild_vips.begin(), vaild_vips.end(), std::inserter(diff_vips, diff_vips.begin()));
    SWSS_LOG_INFO("original_ip size:%d, apply_vips size:%d, diff size:%d", (int)original_vips.size(), (int)vaild_vips.size(), (int)diff_vips.size());

    bool ip_ok = true;
    for (const IpPrefix &diff_ip : diff_vips)
    {
        if (vaild_vips.find(diff_ip) != vaild_vips.end())
        {
            if (!addVirtualInterfaceIp(vrrp.getVrrpName(), diff_ip))
            {
                ip_ok = false;
                continue;
            }
            vrrp_entry.vips.insert(diff_ip);
        }

        if (original_vips.find(diff_ip) != original_vips.end())
        {
            if (!delVirtualInterfaceIp(vrrp.getVrrpName(), diff_ip))
            {
                ip_ok = false;
                continue;
            }
            vrrp_entry.vips.erase(diff_ip);
        }
    }

    if (ip_ok && vrrp.isValid() && vrrp_entry.vips.empty())
    {
        if (!delVirtualInterface(intf_alias, vrrp.getVrrpName()))
        {
            ip_ok = false;
        }
        else
        {
            vrrp = VrrpIntf();
        }
    }

    if (!ip_ok)
    {
        enforce_parent_arp();
        SWSS_LOG_WARN("Set vrrp vip on intf[%s] vrid[%s] incomplete, retry",
                      intf_alias.c_str(), vrid_str.c_str());
        return false;
    }

    auto parent_link = LinkCache::getInstance().getLinkByName(intf_alias.c_str());
    if (vrrp.isValid() && !parent_link)
    {
        SWSS_LOG_WARN("Unable to resolve parent link[%s] for VRF reconciliation, retry",
                      intf_alias.c_str());
        enforce_parent_arp();
        return false;
    }
    if (vrrp.isValid())
    {
        string vrf_name;
        int vrf_id = rtnl_link_get_master(parent_link);
        if (vrf_id != 0)
        {
            vrf_name = LinkCache::getInstance().ifindexToName(vrf_id);
        }
        if (!setVirtualInterfaceVrf(vrrp.getVrrpName(), vrf_name))
        {
            rtnl_link_put(parent_link);
            enforce_parent_arp();
            return false;
        }
        SWSS_LOG_INFO("Set vrrp on intf[%s] vrid[%s] Vrf: %s",
                      intf_alias.c_str(), vrid_str.c_str(), vrf_name.c_str());
    }
    if (parent_link)
    {
        rtnl_link_put(parent_link);
    }

    if (!enforce_parent_arp())
    {
        return false;
    }

    SWSS_LOG_NOTICE("Set vrrp on intf[%s] vrid[%s] is_ipv4 %d",
                    intf_alias.c_str(), vrid_str.c_str(), is_ipv4);
    return true;
}

bool VrrpMgr::removeVrrpIntf(const std::string &intf_alias, const uint8_t vrid, const bool is_ipv4)
{
    const VrrpKey vrrp_key{intf_alias, vrid};
    const string vrid_str = to_string(static_cast<unsigned int>(vrid));
    auto it = m_vrrpList.find(vrrp_key);
    if (it == m_vrrpList.end())
    {
        SWSS_LOG_INFO("Not found vrid: %s", vrid_str.c_str());
        return setIntfArpAccept(intf_alias, isVrrpOnIntf(intf_alias));
    }

    auto &vrrp = is_ipv4 ? it->second.vrrp4 : it->second.vrrp6;
    auto &vrrp_entry = is_ipv4 ? it->second.vrrp4_entry : it->second.vrrp6_entry;
    if (vrrp.isValid())
    {
        if (if_nametoindex(vrrp.getVrrpName().c_str()) != 0)
        {
            unsigned int parent_ifindex = if_nametoindex(intf_alias.c_str());
            if (parent_ifindex == 0)
            {
                SWSS_LOG_WARN("Unable to resolve ifindex for parent interface[%s], retry", intf_alias.c_str());
                return false;
            }

            MacAddress vmac;
            parseVrrpMac(vrid, is_ipv4, vmac);
            VrrpKernelLinkState retained_state;
            if (!queryKernelLink(vrrp.getVrrpName(), parent_ifindex, vmac, retained_state))
            {
                return false;
            }
            if (!retained_state.identity_matches)
            {
                SWSS_LOG_ERROR("Refuse to delete mismatched VRRP link[%s] on[%s]",
                               vrrp.getVrrpName().c_str(), intf_alias.c_str());
                return false;
            }
            if (!delVirtualInterface(intf_alias, vrrp.getVrrpName()))
            {
                return false;
            }
        }
        vrrp = VrrpIntf();
        vrrp_entry = VrrpIntfEntry();
    }

    if (!it->second.vrrp4.isValid() && !it->second.vrrp6.isValid())
    {
        m_vrrpList.erase(it);
    }

    if (!setIntfArpAccept(intf_alias, isVrrpOnIntf(intf_alias)))
    {
        return false;
    }

    SWSS_LOG_NOTICE("Remove vrrp on intf[%s] vrid[%s] is_ipv4 %d",
                    intf_alias.c_str(), vrid_str.c_str(), is_ipv4);
    return true;
}

bool VrrpMgr::addVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name, const MacAddress &vrrp_mac, bool is_ipv4)
{
    stringstream create_cmd;
    stringstream init_cmd;
    string res;

    // Create the complete identity atomically. A newly-created link is down by
    // default; addrgenmode is initialized separately and re-enforced on SET.
    create_cmd << IP_CMD << " link add " << shellquote(vrrp_name)
               << " link " << shellquote(intf_alias)
               << " address " << vrrp_mac.to_string()
               << " type macvlan mode bridge";
    SWSS_LOG_DEBUG("Add vrrp virtual intf cmd: %s", create_cmd.str().c_str());

    try
    {
        EXEC_WITH_ERROR_THROW(create_cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to add vitrual intf[%s] on interface[%s], retry. Runtime error: %s", vrrp_name.c_str(), intf_alias.c_str(), e.what());
        return false;
    }

    init_cmd << IP_CMD << " link set dev " << shellquote(vrrp_name)
             << " addrgenmode " << string(is_ipv4 ? "none" : "random") << " down";
    try
    {
        EXEC_WITH_ERROR_THROW(init_cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        string cleanup_res;
        string cleanup_cmd = string(IP_CMD) + " link del " + shellquote(vrrp_name);
        int cleanup_ret = swss::exec(cleanup_cmd, cleanup_res);
        SWSS_LOG_ERROR("Failed to initialize newly-created virtual intf[%s] on[%s]: %s; cleanup rc=%d",
                       vrrp_name.c_str(), intf_alias.c_str(), e.what(), cleanup_ret);
        return false;
    }

    SWSS_LOG_INFO("Add vitrual intf[%s] on interface[%s]", vrrp_name.c_str(), intf_alias.c_str());
    return true;
}

bool VrrpMgr::delVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name)
{
    stringstream cmd;
    string res;

    if (if_nametoindex(vrrp_name.c_str()) == 0)
    {
        SWSS_LOG_INFO("Virtual intf[%s] on interface[%s] is already absent",
                      vrrp_name.c_str(), intf_alias.c_str());
        return true;
    }

    cmd << IP_CMD << " link del " << shellquote(vrrp_name);

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        if (if_nametoindex(vrrp_name.c_str()) == 0)
        {
            SWSS_LOG_INFO("Virtual intf[%s] disappeared during delete", vrrp_name.c_str());
            return true;
        }
        SWSS_LOG_ERROR("Failed to del vitrual intf[%s] on interface[%s], retry. Runtime error: %s", vrrp_name.c_str(), intf_alias.c_str(), e.what());
        return false;
    }

    SWSS_LOG_INFO("Del vitrual intf[%s] on interface[%s]", vrrp_name.c_str(), intf_alias.c_str());
    return true;
}

bool swss::VrrpMgr::addVirtualInterfaceIp(const std::string &vrrp_name, const IpPrefix &ip_addr)
{
    stringstream cmd;
    string res;

    bool ip_ipv4 = ip_addr.isV4();
    string ipPrefixStr = ip_addr.to_string();
    // Keep VIP address on VRRP child interface but suppress auto connected prefix route.
    cmd << IP_CMD << (ip_ipv4 ? "" : " -6 ") << " address replace " << shellquote(ipPrefixStr)
        << " dev " << shellquote(vrrp_name) << " noprefixroute";

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to add ip[%s] on vitrual intf[%s], retry. Runtime error: %s", ipPrefixStr.c_str(), vrrp_name.c_str(), e.what());
        return false;
    }

    SWSS_LOG_INFO("Add ip[%s] on vitrual intf[%s]", ipPrefixStr.c_str(), vrrp_name.c_str());
    return true;
}

bool swss::VrrpMgr::delVirtualInterfaceIp(const std::string &vrrp_name, const IpPrefix &ip_addr)
{
    stringstream cmd;
    string res;

    bool ip_ipv4 = ip_addr.isV4();
    string ipPrefixStr = ip_addr.to_string();
    // link del ip dev vrrp
    cmd << IP_CMD << (ip_ipv4 ? "" : " -6 ") << " address del " << shellquote(ipPrefixStr) << " dev " << shellquote(vrrp_name);

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to del ip[%s] on vitrual intf[%s], retry. Runtime error: %s", ipPrefixStr.c_str(), vrrp_name.c_str(), e.what());
        return false;
    }

    SWSS_LOG_INFO("Del ip[%s] on vitrual intf[%s]", ipPrefixStr.c_str(), vrrp_name.c_str());
    return true;
}

bool VrrpMgr::setVirtualInterfaceAddrgenMode(const std::string &vrrp_name, bool is_ipv4)
{
    stringstream cmd;
    string res;
    cmd << IP_CMD << " link set dev " << shellquote(vrrp_name)
        << " addrgenmode " << string(is_ipv4 ? "none" : "random");

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const exception &e)
    {
        SWSS_LOG_ERROR("Failed to set addrgenmode on virtual intf[%s], retry: %s",
                       vrrp_name.c_str(), e.what());
        return false;
    }
    return true;
}

bool VrrpMgr::setVirtualInterfaceAdminStatus(const std::string &vrrp_name, const std::string &admin_status)
{
    stringstream cmd;
    string res;

    cmd << IP_CMD << " link set dev " << shellquote(vrrp_name) << " " << shellquote(admin_status);
    SWSS_LOG_DEBUG("Set vrrp virtual intf admin status cmd: %s", cmd.str().c_str());

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to add vitrual intf[%s], retry. Runtime error: %s", vrrp_name.c_str(), e.what());
        return false;
    }

    SWSS_LOG_INFO("Add vitrual intf[%s]", vrrp_name.c_str());
    return true;
}

bool VrrpMgr::setVirtualInterfaceVrf(const string &vrrp_name, const string &vrf_name)
{
    stringstream cmd;
    string res;

    if (!vrf_name.empty() && vrf_name.compare(0, strlen(VRF_PREFIX), VRF_PREFIX) != 0)
    {
        SWSS_LOG_ERROR("Vrf %s is invalid", vrf_name.c_str());
        return false;
    }

    if (!vrf_name.empty())
    {
        cmd << IP_CMD << " link set " << shellquote(vrrp_name) << " master " << shellquote(vrf_name);
    }
    else
    {
        cmd << IP_CMD << " link set " << shellquote(vrrp_name) << " nomaster";
    }

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
        return false;
    }
    SWSS_LOG_INFO(" %s bind vrf [%s] successful", vrrp_name.c_str(), vrf_name.c_str());
    return true;
}

bool VrrpMgr::isIntfStateOk(const std::string &intf_alias)
{
    /* check router intf initialization is complete */
    vector<FieldValueTuple> temp;
    if (!intf_alias.compare(0, strlen(VLAN_PREFIX), VLAN_PREFIX))
    {
        if (m_stateVlanTable.get(intf_alias, temp))
        {
            SWSS_LOG_DEBUG("Vlan %s is ready", intf_alias.c_str());
            return true;
        }
    }
    else if (!intf_alias.compare(0, strlen(LAG_PREFIX), LAG_PREFIX))
    {
        if (m_stateLagTable.get(intf_alias, temp))
        {
            SWSS_LOG_DEBUG("Lag %s is ready", intf_alias.c_str());
            return true;
        }
    }
    else if (!intf_alias.compare(0, strlen(SUBINTF_LAG_PREFIX), SUBINTF_LAG_PREFIX))
    {
        if (m_stateLagTable.get(intf_alias, temp))
        {
            SWSS_LOG_DEBUG("Lag %s is ready", intf_alias.c_str());
            return true;
        }
    }
    else if (m_statePortTable.get(intf_alias, temp))
    {
        auto state_opt = swss::fvsGetValue(temp, "state", true);
        if (!state_opt)
        {
            return false;
        }
        SWSS_LOG_DEBUG("Port %s is ready", intf_alias.c_str());
        return true;
    }

    return false;
}

bool VrrpMgr::isVrrpOnIntf(const std::string &intf_alias)
{
    return find_if(m_vrrpList.begin(), m_vrrpList.end(), [intf_alias](const auto &pair) {
        return pair.second.alias == intf_alias &&
               (pair.second.vrrp4.isValid() || pair.second.vrrp6.isValid());
    }) != m_vrrpList.end();
}

bool VrrpMgr::parseVrid(const std::string &vrid, uint8_t &canonical_vrid)
{
    if (vrid.empty())
    {
        SWSS_LOG_WARN("vrid must be a number from 1 to 255");
        return false;
    }
    if (vrid.size() > 1 && vrid.front() == '0')
    {
        SWSS_LOG_WARN("vrid[%s] is not in canonical decimal form", vrid.c_str());
        return false;
    }

    unsigned int value = 0;
    for (char digit : vrid)
    {
        if (digit < '0' || digit > '9')
        {
            SWSS_LOG_WARN("vrid[%s] must be a number from 1 to 255", vrid.c_str());
            return false;
        }
        value = value * 10 + static_cast<unsigned int>(digit - '0');
        if (value > 255)
        {
            SWSS_LOG_WARN("vrid[%s] must be a number from 1 to 255", vrid.c_str());
            return false;
        }
    }

    if (value == 0)
    {
        SWSS_LOG_WARN("vrid[%s] must be a number from 1 to 255", vrid.c_str());
        return false;
    }

    canonical_vrid = static_cast<uint8_t>(value);
    return true;
}

void VrrpMgr::parseVrrpMac(const uint8_t vrid, const bool is_ipv4, MacAddress &vrrp_mac)
{
    stringstream vmac;
    string hex_vrid;

    uint8_t vrid_value = vrid;
    hex_vrid = binary_to_hex(&vrid_value, sizeof(vrid_value));
    SWSS_LOG_INFO("vrid: %u, hex_vrid: %s", static_cast<unsigned int>(vrid), hex_vrid.c_str());

    if (is_ipv4)
    {
        vmac << VRRP_V4_MAC_PREFIX << std::setw(2) << std::setfill('0') << hex_vrid;
    }
    else
    {
        vmac << VRRP_V6_MAC_PREFIX << std::setw(2) << std::setfill('0') << hex_vrid;
    }

    vrrp_mac = MacAddress(vmac.str());
}

void VrrpMgr::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    auto table = consumer.getTableName();

    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        vector<string> keys = tokenize(kfvKey(t), config_db_key_delimiter);
        const string &op = kfvOp(t);
        const vector<FieldValueTuple> &data = kfvFieldsValues(t);

        if (keys.size() != 2)
        {
            SWSS_LOG_WARN("vrrp table need intf and vrid, ignore it: %s", kfvKey(t).c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        string intf_alias(keys[0]);
        string vrrp_id(keys[1]);
        uint8_t canonical_vrid = 0;
        if (!parseVrid(vrrp_id, canonical_vrid))
        {
            SWSS_LOG_WARN("Invalid VRRP key[%s], ignore", kfvKey(t).c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        if (op == SET_COMMAND && !isIntfStateOk(intf_alias))
        {
            SWSS_LOG_INFO("Port %s is not ready, pending...", intf_alias.c_str());
            it++;
            continue;
        }

        string vrid, vip_str, admin_status;
        for (auto i : data)
        {
            if (fvField(i) == "vrid")
            {
                vrid = fvValue(i);
            }
            else if (fvField(i) == "vip" || fvField(i) == "vip@")
            {
                vip_str = fvValue(i);
            }
            else if (fvField(i) == "admin_status")
            {
                admin_status = fvValue(i);
            }
        }
        bool is_ipv4 = table == CFG_VRRP_TABLE_NAME ? true : false;
        if (op == SET_COMMAND)
        {
            set<IpAddress> vips;
            if (!vip_str.empty())
            {
                vector<string> vip_list = tokenize(vip_str, list_item_delimiter);
                try
                {
                    for (const auto &vip : vip_list)
                    {
                        if (vip.empty())
                        {
                            continue;
                        }
                        vips.insert(IpAddress(getIpOnly(vip)));
                    }
                }
                catch (const std::exception &e)
                {
                    SWSS_LOG_ERROR("vip has invaild ip addr on vrrp table %s, ignore. Runtime error: %s", kfvKey(t).c_str(), e.what());
                    it = consumer.m_toSync.erase(it);
                    continue;
                }
            }
            else
            {
                SWSS_LOG_NOTICE("Creat macvlan link on intf[%s] vrid[%s] without ip address", intf_alias.c_str(), vrrp_id.c_str());
            }

            if (admin_status.empty())
            {
                admin_status = "up";
            }
            else if(admin_status != "up" && admin_status != "down")
            {
                admin_status = "down";
                SWSS_LOG_WARN("Invaild admin status %s on intf[%s] vrid[%s].", admin_status.c_str(), intf_alias.c_str(), vrrp_id.c_str());
            }

            if (!setVrrpIntf(intf_alias, canonical_vrid, is_ipv4, vips, admin_status))
            {
                SWSS_LOG_WARN("Set vrrp on intf[%s] vrid[%s] failed, retry.", intf_alias.c_str(), vrrp_id.c_str());
                it++;
                continue;
            }
        }
        else if (op == DEL_COMMAND)
        {
            if (!removeVrrpIntf(intf_alias, canonical_vrid, is_ipv4))
            {
                SWSS_LOG_WARN("Del vrrp on intf[%s] vrid[%s] failed, retry.", intf_alias.c_str(), vrrp_id.c_str());
                it++;
                continue;
            }
        }

        it = consumer.m_toSync.erase(it);
    }
}
