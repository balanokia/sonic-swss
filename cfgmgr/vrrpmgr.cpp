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

using namespace std;
using namespace swss;

#define VLAN_PREFIX         "Vlan"
#define LAG_PREFIX          "PortChannel"
#define SUBINTF_LAG_PREFIX  "Po"
#define SUBINTF_LAG_PREFIX  "Po"
#define LOOPBACK_PREFIX     "Loopback"
#define VRF_PREFIX          "Vrf"

#define VRRP_V4_MAC_PREFIX "00:00:5e:00:01:"
#define VRRP_V6_MAC_PREFIX "00:00:5e:00:02:"

VrrpMgr::VrrpMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const std::vector<std::string> &tableNames) : 
        Orch(cfgDb, tableNames),
        m_appPortTable(appDb, APP_PORT_TABLE_NAME),
        m_stateLagTable(stateDb, STATE_LAG_TABLE_NAME),
        m_stateVlanTable(stateDb, STATE_VLAN_TABLE_NAME),
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME),
        m_savedAllArpIgnore(-1)
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

bool VrrpMgr::restoreSonicDefaultAllArpIgnore()
{
    /*
     * After all VRRP host-route macvlans are gone, restore SONiC default
     * all.arp_ignore=2 (90-sonic.conf) to re-enable strict ARP reply policy
     * and mitigate cross-interface ARP spoofing / flux attacks.
     */
    if (!m_hostRouteArpMacvlans.empty())
    {
        return true;
    }

    stringstream cmd;
    string res;
    cmd << ECHO_CMD << " " << SONIC_DEFAULT_ARP_IGNORE
        << " > /proc/sys/net/ipv4/conf/all/arp_ignore";
    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
        SWSS_LOG_NOTICE("Restored all.arp_ignore=%d (SONiC default) after VRRP macvlan cleanup",
                        SONIC_DEFAULT_ARP_IGNORE);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to restore all.arp_ignore=%d: %s", SONIC_DEFAULT_ARP_IGNORE, e.what());
        return false;
    }
    m_savedAllArpIgnore = -1;
    return true;
}

bool VrrpMgr::setVrrpMacvlanHostRouteArp(const std::string &vrrp_name, bool enable)
{
    /*
     * Stock SONiC sets net.ipv4.conf.all.arp_ignore=2. For a VIP programmed as
     * a host route (/32) on the VRRP macvlan, mode 2 suppresses ARP replies
     * (sender not on-link vs /32). Effective arp_ignore is max(all, iface), so
     * macvlan alone cannot override all=2 — lower all to 1 while any such
     * macvlan exists, and set iface arp_ignore=1 + arp_announce=2.
     * On last macvlan/VRRP cleanup, restore all.arp_ignore=2 (SONiC default).
     */
    stringstream cmd;
    string res;

    if (enable)
    {
        if (m_hostRouteArpMacvlans.count(vrrp_name) != 0)
        {
            return true;
        }

        if (m_hostRouteArpMacvlans.empty())
        {
            try
            {
                const std::string read_arp_ignore_cmd = "cat /proc/sys/net/ipv4/conf/all/arp_ignore";
                EXEC_WITH_ERROR_THROW(read_arp_ignore_cmd, res);
                m_savedAllArpIgnore = std::stoi(res);
            }
            catch (const std::exception &e)
            {
                SWSS_LOG_WARN("Failed to read all.arp_ignore, assume %d: %s",
                              SONIC_DEFAULT_ARP_IGNORE, e.what());
                m_savedAllArpIgnore = SONIC_DEFAULT_ARP_IGNORE;
            }

            if (m_savedAllArpIgnore > 1)
            {
                cmd.str("");
                cmd.clear();
                cmd << ECHO_CMD << " 1 > /proc/sys/net/ipv4/conf/all/arp_ignore";
                try
                {
                    EXEC_WITH_ERROR_THROW(cmd.str(), res);
                }
                catch (const std::exception &e)
                {
                    SWSS_LOG_ERROR("Failed to set all.arp_ignore=1 for host-route VIP: %s", e.what());
                    m_savedAllArpIgnore = -1;
                    return false;
                }
                SWSS_LOG_NOTICE("Lowered all.arp_ignore %d -> 1 for VRRP host-route VIP ARP",
                                m_savedAllArpIgnore);
            }
        }

        cmd.str("");
        cmd.clear();
        cmd << ECHO_CMD << " 1 > /proc/sys/net/ipv4/conf/" << shellquote(vrrp_name) << "/arp_ignore && ";
        cmd << ECHO_CMD << " 2 > /proc/sys/net/ipv4/conf/" << shellquote(vrrp_name) << "/arp_announce";
        try
        {
            EXEC_WITH_ERROR_THROW(cmd.str(), res);
        }
        catch (const std::exception &e)
        {
            SWSS_LOG_ERROR("Failed to set host-route ARP sysctls on %s: %s", vrrp_name.c_str(), e.what());
            return false;
        }

        m_hostRouteArpMacvlans[vrrp_name] = true;
        SWSS_LOG_NOTICE("Enabled host-route ARP on %s (arp_ignore=1 arp_announce=2)", vrrp_name.c_str());
        return true;
    }

    /* disable / macvlan removed */
    if (m_hostRouteArpMacvlans.erase(vrrp_name) == 0) /* map::erase returns count */
    {
        /* Still ensure SONiC default if nothing left (idempotent cleanup) */
        if (m_hostRouteArpMacvlans.empty())
        {
            restoreSonicDefaultAllArpIgnore();
        }
        return true;
    }

    if (m_hostRouteArpMacvlans.empty())
    {
        restoreSonicDefaultAllArpIgnore();
    }

    return true;
}

bool VrrpMgr::setVrrpIntf(const std::string &intf_alias, const std::string &vrid, const bool is_ipv4, 
    const std::set<IpPrefix> &vip_list, const std::string &admin_status)
{
    VrrpIntfConf vrrp_conf;
    if (m_vrrpList.find(vrid) == m_vrrpList.end())
    {
        vrrp_conf.alias = intf_alias;
    }
    else
    {
        vrrp_conf = m_vrrpList[vrid];
    }
    auto &vrrp = is_ipv4 ? vrrp_conf.vrrp4 : vrrp_conf.vrrp6;
    auto &vrrp_entry = is_ipv4 ? vrrp_conf.vrrp4_entry : vrrp_conf.vrrp6_entry;

    // generate vmac
    set<IpPrefix> vaild_vips;
    auto is_ipv4_check = [is_ipv4](const IpPrefix &has_vip){ return has_vip.isV4() == is_ipv4; };
    copy_if(vip_list.begin(), vip_list.end(), std::inserter(vaild_vips, vaild_vips.begin()), is_ipv4_check);
    if (!vaild_vips.empty())
    {
        // add vrrp intf
        if (!vrrp.isValid())
        {
            MacAddress vmac;
            if (!parseVrrpMac(vrid, is_ipv4, vmac))
            {
                return false;
            }
            vrrp = VrrpIntf(intf_alias, vrid, is_ipv4, vmac.to_string());
            if (!vrrp.isValid())
            {
                SWSS_LOG_WARN("parse new vrrp intf fail, intf: %s, vrid: %s, is ipv4:%d", intf_alias.c_str(), vrid.c_str(), is_ipv4);
                return false;
            }
            if (!addVirtualInterface(intf_alias, vrrp.getVrrpName(), vmac, is_ipv4))
            {
                vrrp = VrrpIntf();
                return false;
            }
        }
    }
    else
    {
        // del vrrp intf
        if (vrrp.isValid())
        {
            if (!delVirtualInterface(intf_alias, vrrp.getVrrpName()))
            {
                return false;
            }
            vrrp = VrrpIntf();
            vrrp_entry = VrrpIntfEntry();
        }
    }

    if (!vrrp.isValid())
    {
        SWSS_LOG_WARN("set vrrp fail");
        return false;
    }

    // set admin status
    vrrp_entry.admin_status = admin_status;
    if (vrrp.isValid())
    {
        setVirtualInterfaceAdminStatus(vrrp.getVrrpName(), admin_status);
    }

    // add/del vips
    set<IpPrefix> original_vips = vrrp_entry.vips;
    set<IpPrefix> diff_vips;
    set_symmetric_difference(original_vips.begin(), original_vips.end(), vaild_vips.begin(), vaild_vips.end(), std::inserter(diff_vips, diff_vips.begin()));
    SWSS_LOG_INFO("original_ip size:%d, apply_vips size:%d, diff size:%d", (int)original_vips.size(), (int)vaild_vips.size(), (int)diff_vips.size());
    vrrp_entry.vips = vaild_vips;

    for (const IpPrefix &diff_ip : diff_vips)
    {
        if (vaild_vips.find(diff_ip) != vaild_vips.end())
        {
            // add vip
            addVirtualInterfaceIp(vrid, diff_ip);
        }

        if (original_vips.find(diff_ip) != original_vips.end())
        {
            // del vip
            delVirtualInterfaceIp(vrid, diff_ip);
        }
    }

    m_vrrpList[vrid] = vrrp_conf;
    // set parent intf
    if (!isVrrpOnIntf(intf_alias))
    {
        SWSS_LOG_INFO("No vrrp on interface[%s], set arp accept", intf_alias.c_str());
        setIntfArpAccept(intf_alias);
    }
    // set vrrp vrf
    auto parent_link = LinkCache::getInstance().getLinkByName(intf_alias.c_str());
    int vrf_id = rtnl_link_get_master(parent_link);
    if (vrf_id != 0)
    {
        auto vrf_name = LinkCache::getInstance().ifindexToName(vrf_id);
        setVirtualInterfaceVrf(vrrp.getVrrpName(), vrf_name);
        SWSS_LOG_INFO("Set vrrp on intf[%s] vrid[%s] Vrf: %s", intf_alias.c_str(), vrid.c_str(), vrf_name.c_str());
    }

    SWSS_LOG_NOTICE("Set vrrp on intf[%s] vrid[%s] is_ipv4 %d", intf_alias.c_str(), vrid.c_str(), is_ipv4);
    return true;
}

bool VrrpMgr::removeVrrpIntf(const std::string &intf_alias, const std::string &vrid, const bool is_ipv4)
{
    auto it = m_vrrpList.find(vrid);
    if (it == m_vrrpList.end())
    {
        SWSS_LOG_INFO("Not found vrid: %s", vrid.c_str());
        return true;
    }

    auto &vrrp = is_ipv4 ? it->second.vrrp4 : it->second.vrrp6;
    auto &vrrp_entry = is_ipv4 ? it->second.vrrp4_entry : it->second.vrrp6_entry;
    if (vrrp.isValid())
    {
        delVirtualInterface(intf_alias, vrrp.getVrrpName());
        vrrp = VrrpIntf();
        vrrp_entry = VrrpIntfEntry();
    }

    if (!it->second.vrrp4.isValid() && !it->second.vrrp6.isValid())
    {
        m_vrrpList.erase(it);
        if (!isVrrpOnIntf(intf_alias))
        {
            SWSS_LOG_INFO("No vrrp on intf[%s], arp accept back to default", intf_alias.c_str());
            setIntfArpAccept(intf_alias, false);
            /*
             * Parent has no remaining VRRP children/macvlans: restore
             * all.arp_ignore=2 (SONiC default) if host-route ARP bookkeeping
             * is empty — guard against leaving a weakened ARP policy.
             */
            if (m_hostRouteArpMacvlans.empty())
            {
                restoreSonicDefaultAllArpIgnore();
            }
        }
    }

    SWSS_LOG_NOTICE("Remove vrrp on intf[%s] vrid[%s] is_ipv4 %d", intf_alias.c_str(), vrid.c_str(), is_ipv4);
    return true;
}

bool VrrpMgr::addVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name, const MacAddress &vrrp_mac, bool is_ipv4)
{
    stringstream cmd;
    string res;

    // link add vrrp type macvlan
    cmd << IP_CMD << " link add " << shellquote(vrrp_name) << " link " << shellquote(intf_alias) << " type macvlan mode bridge && ";
    cmd << IP_CMD << " link set dev " << shellquote(vrrp_name) << " addrgenmode " << string(is_ipv4 ? "none" : "random") << " && ";
    cmd << IP_CMD << " link set dev " << shellquote(vrrp_name) << " address " << vrrp_mac.to_string() << " && ";
    // create default is down, wait for admin status value(default up)
    cmd << IP_CMD << " link set dev " << shellquote(vrrp_name) << " down";
    SWSS_LOG_DEBUG("Add vrrp virtual intf cmd: %s", cmd.str().c_str());

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to add vitrual intf[%s] on interface[%s], retry. Runtime error: %s", vrrp_name.c_str(), intf_alias.c_str(), e.what());
        return false;
    }

    SWSS_LOG_INFO("Add vitrual intf[%s] on interface[%s]", vrrp_name.c_str(), intf_alias.c_str());
    return true;
}

bool VrrpMgr::delVirtualInterface(const std::string &intf_alias, const std::string &vrrp_name)
{
    stringstream cmd;
    string res;

    /* Clear host-route ARP bookkeeping before link delete */
    setVrrpMacvlanHostRouteArp(vrrp_name, false);

    // link del vrrp
    cmd << IP_CMD << " link del " << shellquote(vrrp_name);

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to del vitrual intf[%s] on interface[%s], retry. Runtime error: %s", vrrp_name.c_str(), intf_alias.c_str(), e.what());
        return false;
    }

    SWSS_LOG_INFO("Del vitrual intf[%s] on interface[%s]", vrrp_name.c_str(), intf_alias.c_str());
    return true;
}

bool swss::VrrpMgr::addVirtualInterfaceIp(const std::string &vrid, const IpPrefix &ip_addr)
{
    stringstream cmd;
    string res;

    bool ip_ipv4 = ip_addr.isV4();
    string vrrp_name = join(vrrp_name_delimiter, (ip_ipv4 ? VRRP_V4_PREFIX : VRRP_V6_PREFIX), vrid);
    string ipPrefixStr = ip_addr.to_string();
    // link add ip dev vrrp
    cmd << IP_CMD << (ip_ipv4 ? "" : " -6 ") << " address add " << shellquote(ipPrefixStr) << " dev " << shellquote(vrrp_name);

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to add ip[%s] on vitrual intf[%s], retry. Runtime error: %s", vrrp_name.c_str(), vrrp_name.c_str(), e.what());
        return false;
    }

    SWSS_LOG_INFO("Add ip[%s] on vitrual intf[%s]", ipPrefixStr.c_str(), vrrp_name.c_str());

    /* Plain VIP / IpPrefix default => /32 host route on macvlan; enable ARP replies */
    if (ip_ipv4 && ip_addr.getMaskLength() == 32)
    {
        setVrrpMacvlanHostRouteArp(vrrp_name, true);
    }

    return true;
}

bool swss::VrrpMgr::delVirtualInterfaceIp(const std::string &vrid, const IpPrefix &ip_addr)
{
    stringstream cmd;
    string res;

    bool ip_ipv4 = ip_addr.isV4();
    string vrrp_name = join(vrrp_name_delimiter, (ip_ipv4 ? VRRP_V4_PREFIX : VRRP_V6_PREFIX), vrid);
    string ipPrefixStr = ip_addr.to_string();
    // link del ip dev vrrp
    cmd << IP_CMD << (ip_ipv4 ? "" : " -6 ") << " address del " << shellquote(ipPrefixStr) << " dev " << shellquote(vrrp_name);

    try
    {
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to del ip[%s] on vitrual intf[%s], retry. Runtime error: %s", vrrp_name.c_str(), vrrp_name.c_str(), e.what());
        return false;
    }

    SWSS_LOG_INFO("Del ip[%s] on vitrual intf[%s]", ipPrefixStr.c_str(), vrrp_name.c_str());
    /* Host-route ARP sysctls cleared in delVirtualInterface when macvlan is removed */
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

    if (!vrf_name.compare(0, strlen(VRF_PREFIX), VRF_PREFIX))
    {
        SWSS_LOG_INFO("Vrf %s is invaild", vrf_name.c_str());
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
    return find_if(m_vrrpList.begin(), m_vrrpList.end(), [intf_alias](const auto &pair){ return pair.second.alias == intf_alias; }) != m_vrrpList.end();
}

bool VrrpMgr::parseVrrpMac(const std::string &vrid, const bool is_ipv4, MacAddress &vrrp_mac)
{
    stringstream vmac;
    string hex_vrid;

    if (!all_of(vrid.begin(), vrid.end(), ::isdigit))
    {
        SWSS_LOG_WARN("vrid : %s, must be a number", vrid.c_str());
        return false;
    }

    int ivrid = stoi(vrid);
    if (ivrid >= 256 || ivrid <= 0)
    {
        SWSS_LOG_WARN("vrid : %s, must less than 256, greater than 0", vrid.c_str());
        return false;
    }

    // just need one bit to mac
    hex_vrid = binary_to_hex(&ivrid, sizeof(char));
    SWSS_LOG_INFO("vrid: %s, hex_vrid: %s", vrid.c_str(), hex_vrid.c_str());

    if (is_ipv4)
    {
        vmac << VRRP_V4_MAC_PREFIX << std::setw(2) << std::setfill('0') << hex_vrid;
    }
    else
    {
        vmac << VRRP_V6_MAC_PREFIX << std::setw(2) << std::setfill('0') << hex_vrid;
    }

    vrrp_mac = MacAddress(vmac.str());
    return true;
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

        if (!isIntfStateOk(intf_alias))
        {
            SWSS_LOG_INFO("Port %s is not ready, pending...", intf_alias.c_str());
            it++;
            continue;
        }

        if (m_vrrpList.find(vrrp_id) != m_vrrpList.end() && m_vrrpList[vrrp_id].alias != intf_alias)
        {
            SWSS_LOG_WARN("vrid[%s] has been created on interface[%s], ignore it: %s",
                          vrrp_id.c_str(), m_vrrpList[vrrp_id].alias.c_str(), kfvKey(t).c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        string vrid, vip_str, admin_status;
        for (auto i : data)
        {
            if (fvField(i) == "vrid")
            {
                vrid = fvValue(i);
            }
            else if (fvField(i) == "vip")
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
            set<IpPrefix> vips;
            if (!vip_str.empty())
            {
                vector<string> vip_list = tokenize(vip_str, list_item_delimiter);
                try
                {
                    transform(vip_list.begin(), vip_list.end(), inserter(vips, vips.begin()), [](const string &vip){ return IpPrefix(vip); });
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

            if (!setVrrpIntf(intf_alias, vrrp_id, is_ipv4, vips, admin_status))
            {
                SWSS_LOG_WARN("Set vrrp on intf[%s] vrid[%s] failed.", intf_alias.c_str(), vrrp_id.c_str());
            }
        }
        else if (op == DEL_COMMAND)
        {
            if (!removeVrrpIntf(intf_alias, vrrp_id, is_ipv4))
            {
                SWSS_LOG_WARN("Del vrrp on intf[%s] vrid[%s] failed.", intf_alias.c_str(), vrrp_id.c_str());
            }
        }

        it = consumer.m_toSync.erase(it);
    }
}
