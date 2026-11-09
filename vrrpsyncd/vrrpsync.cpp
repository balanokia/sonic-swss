#include <string>
#include <sstream>
#include <algorithm>
#include <errno.h>
#include <system_error>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/route/nexthop.h>
#include <arpa/inet.h>
#include <fstream>


#include "logger.h"
#include "dbconnector.h"
#include "producerstatetable.h"
#include "ipaddress.h"
#include "netmsg.h"
#include "linkcache.h"
#include "exec.h"
#include "schema.h"
#include "vrrpsync.h"
#include "warm_restart.h"
#include "netmsg.h"

using namespace std;
using namespace swss;

static std::string getIpOnly(const std::string &ip_prefix)
{
    auto pos = ip_prefix.find('/');
    return pos == std::string::npos ? ip_prefix : ip_prefix.substr(0, pos);
}

static inline bool vrrpReadProtoDownSysfs(
    const char *ifname, bool &proto_down)
{
    std::string path = "/sys/class/net/" + std::string(ifname) + "/proto_down";
    std::ifstream fp(path);
    std::string value;

    if (!fp.is_open() || !std::getline(fp, value))
    {
        SWSS_LOG_DEBUG("Drop RTM_NEWLINK for disappearing interface %s: "
                       "unable to read %s", ifname, path.c_str());
        return false;
    }

    if (value != "0" && value != "1")
    {
        SWSS_LOG_ERROR("Invalid protodown value '%s' for interface %s",
                       value.c_str(), ifname);
        return false;
    }

    proto_down = value == "1";
    SWSS_LOG_DEBUG("protodown-read if=%s value=%d",
                   ifname, (int)proto_down);
    return true;
}


VrrpSync::VrrpSync(RedisPipeline *pipelineAppDB, DBConnector* cfgDb) :
    m_vrrpTable(pipelineAppDB, APP_VRRP_TABLE_NAME),
    m_cfgDeviceMetadataTable(cfgDb, CFG_DEVICE_METADATA_TABLE_NAME)
{
    m_nl_sock = nl_socket_alloc();
    nl_connect(m_nl_sock, NETLINK_ROUTE);
    rtnl_link_alloc_cache(m_nl_sock, AF_UNSPEC, &m_link_cache);
    m_AppRestartAssist = new AppRestartAssist(pipelineAppDB, "vrrpsyncd", "vrrp", 2);	
    if (m_AppRestartAssist)
    {
        m_AppRestartAssist->registerAppTable(APP_VRRP_TABLE_NAME, &m_vrrpTable);
    }
    if (getSystemMac(systemMac))
    {
        SWSS_LOG_NOTICE("Got system Mac %s", systemMac.c_str());
    }

    m_netLinkOnMsg = 0;
    m_netLinkOnMsgUse = 0;
    m_netLinkOnMsgLinkNew = 0;
    m_netLinkOnMsgLinkNewUse = 0;
    m_netLinkOnMsgLinkDel = 0;
    m_netLinkOnMsgLinkDelUse = 0;
    m_netLinkOnMsgAddrAdd = 0;
    m_netLinkOnMsgAddrAddUse = 0;
    m_netLinkOnMsgAddrDel = 0;
    m_netLinkOnMsgAddrDelUse = 0;
}

VrrpSync::~VrrpSync()
{
    delete m_AppRestartAssist;
}

bool VrrpIsVrrpIntf(const char *ifname)
{
    if (!ifname)
        return false;
    
    if (strncmp(ifname, "Vrrp", 4))
        return false;

    return true;
}

string VrrpSync::VrrpIfindexToName(int ifindex)
{
    char ifname[MAX_ADDR_SIZE + 1] = {0};

    if (rtnl_link_i2name(m_link_cache, ifindex, ifname, MAX_ADDR_SIZE) == NULL)
    {
        nl_cache_refill(m_nl_sock ,m_link_cache);
        if (rtnl_link_i2name(m_link_cache, ifindex, ifname, MAX_ADDR_SIZE) == NULL)
        {
            return to_string(ifindex);
        }

    }

    return string(ifname);
}

string VrrpSync::ReadLineFromFile(const string file, bool *exists)
{
    ifstream fp(file);
    if (!fp.is_open())
    {
        SWSS_LOG_ERROR("File %s is not readable", file.c_str());
        *exists = false;
        return "";
    }
    string line="";
    getline(fp, line);
    if (line.empty())
    {
        SWSS_LOG_NOTICE("File %s is empty", file.c_str());
    }
    *exists = true;
    fp.close();

    return string(line);
}


void VrrpSync::VrrpLinkProcess(int ifindex, string &ifname, string &parent_ifname, int afi, string vmac, unsigned int if_state, bool is_del, bool proto_down)
{
    int key;
    std::unordered_map<int, vrrpmacip>::iterator it_if;
    std::set<std::string>::iterator it_ip;
    std::string vip;
    vrrpmacip local;    
    bool up;
    bool was_active;
    int vip_afi;
    size_t  found;

    key = ifindex;

    was_active = m_vrrpinfo[key].active;
    m_vrrpinfo[key].if_state = if_state;
    m_vrrpinfo[key].ifname = ifname;
    m_vrrpinfo[key].parent_ifname = parent_ifname;
    m_vrrpinfo[key].vmac = vmac;


    bool up_from_flags = ((m_vrrpinfo[key].if_state & IFF_UP) &&
          (m_vrrpinfo[key].if_state & IFF_RUNNING) &&
          (m_vrrpinfo[key].if_state & IFF_LOWER_UP)) ? true : false;

    up = (!is_del) && up_from_flags && (!proto_down);
    m_vrrpinfo[key].active = up;

    if (was_active == up)
        return;

    for(it_ip = m_vrrpinfo[key].m_vip.begin(); it_ip != m_vrrpinfo[key].m_vip.end(); ++it_ip)
    {
        vip = *it_ip;
        found = vip.find(':');
        if (found == string::npos)
            vip_afi = AF_INET;
        else
            vip_afi = AF_INET6;

        VrrpDbUpdate(ifname, key, m_vrrpinfo[key].parent_ifname, vip_afi, vip, m_vrrpinfo[key].vmac, !up);
    }

}


void VrrpSync::VrrpAddrUp(int ifindex, string &ifname, int afi, string &vip)
{
    int key;
    string redis_key;
    string cmd, res;
    //int ret;
    string afi_str = (afi == AF_INET6)? "-6": "";
    
    key = ifindex;

    bool inserted = m_vrrpinfo[key].m_vip.insert(vip).second;

    if (!inserted || !m_vrrpinfo[key].active)
        return;

    VrrpDbUpdate(ifname, key, m_vrrpinfo[key].parent_ifname, afi, vip, m_vrrpinfo[key].vmac, false);
    VrrpUpdateVipNbr(ifname, m_vrrpinfo[key].parent_ifname, afi, vip);
    
}


void VrrpSync::VrrpAddrDown(int ifindex, string &ifname, int afi, string &vip)
{
    int key;
    string redis_key;    

    key = ifindex;

    auto state_it = m_vrrpinfo.find(key);
    if (state_it == m_vrrpinfo.end())
        return;

    auto &state = state_it->second;
    auto vip_it = state.m_vip.find(vip);
    if (vip_it == state.m_vip.end())
        return;

    if (state.active)
        VrrpDbUpdate(ifname, key, state.parent_ifname, afi, vip, state.vmac, true);
    state.m_vip.erase(vip_it);
}

bool VrrpSync::getSystemMac(string& mac)
{
#define LOCAL_HOST            "localhost"
    vector<FieldValueTuple> fvs;
    m_cfgDeviceMetadataTable.get(LOCAL_HOST, fvs);

    auto it = std::find_if(fvs.begin(), fvs.end(), [](const FieldValueTuple &fv)
            {
            return fv.first == "mac";
            });

    if (it == fvs.end())
    {
        SWSS_LOG_ERROR("Unable to fetch system MAC from Config DB");
        return false;
    }
    mac = it->second;
    SWSS_LOG_INFO("System MAC is %s", mac.c_str());
    return true;
}

bool VrrpSync::getAutoIPv6LL(const string& ifname, string& ipv6ll)
{
    std::string mac;
    int idx;
    uint8_t ll_addr[6];
    struct in6_addr l3_addr;
    std::size_t pos;
    string file = "/sys/class/net/"+ifname+"/address";
    bool exists = false;

    if (ifname == "eth0")
    {
        mac = systemMac;
    }
    else
    {
        mac = ReadLineFromFile(file, &exists);
        if (!exists)
        {
            SWSS_LOG_ERROR("Unable to get MAC on interface %s", ifname.c_str());
            ipv6ll = "::";
            return false;
        } 
    }

    std::string delimiter = ":";
    std::string token;
    idx = 0;
    while ((pos = mac.find(delimiter)) != std::string::npos) {
        token = mac.substr(0, pos);
        ll_addr[idx++] = (uint8_t)std::stoi(token, 0, 16);
        mac.erase(0, pos + delimiter.length());
    }
    token = mac.substr(0, pos);
    ll_addr[idx] = (uint8_t)std::stoi(token, 0, 16);

    /*Generate LL based interface mac*/
    l3_addr.s6_addr[0] = 0xfe;
    l3_addr.s6_addr[1] = 0x80;
    l3_addr.s6_addr16[1] = 0;
    l3_addr.s6_addr32[1] = 0;
    l3_addr.s6_addr[8] = ll_addr[0] | 0x02;
    l3_addr.s6_addr[9] = ll_addr[1];
    l3_addr.s6_addr[10] = ll_addr[2];
    l3_addr.s6_addr[11] = 0xff;
    l3_addr.s6_addr[12] = 0xfe;
    l3_addr.s6_addr[13] = ll_addr[3];
    l3_addr.s6_addr[14] = ll_addr[4];
    l3_addr.s6_addr[15] = ll_addr[5];

    char v6addr[50];
    inet_ntop(AF_INET6, &l3_addr, v6addr, INET6_ADDRSTRLEN);
    std::string llstr(v6addr);
    llstr = llstr + "/64";

    ipv6ll = llstr;

    return true;
}

void VrrpSync::VrrpUpdateNbr(string &ifname, int afi, string &vip)
{
    string cmd, res;
    int ret;
    string afi_str = (afi == AF_INET6)? "-6": "";
    string vip_addr = getIpOnly(vip);

    cmd = "ip " + afi_str + " neigh flush " + vip_addr + " dev " + ifname;

    ret = swss::exec(cmd, res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.c_str(), ret);
    }
}


void VrrpSync::VrrpUpdateVipNbr(string &macVlanIf, string &ifname, int afi, string &vip)
{
    VrrpUpdateNbr(ifname, afi, vip);
    VrrpUpdateNbr(macVlanIf, afi, vip);
}


void VrrpSync::VrrpDbUpdate(string &macVlanIf, int ifindex, string &ifname, int afi, string &vip, string &vmac, bool del)
{
    string key;
    string len;
    std::vector<FieldValueTuple> vec;
    string vip_addr = getIpOnly(vip);

    if (afi == AF_INET6)
    {
        len = "/128";
    }
    else
    {
        len = "/32";        
    }

    key += ifname;
    key += "|";
    key += vip_addr;
    key += len;


    FieldValueTuple fv("vmac", vmac);
    vec.push_back(fv);

    if (m_AppRestartAssist->isWarmStartInProgress())
        m_AppRestartAssist->insertToMap(APP_VRRP_TABLE_NAME, key, vec, del);
    else if (del)
    {
        m_vrrpTable.del(key);
    }
    else
    {
        m_vrrpTable.set(key, vec);
    }    
}


void VrrpSync::onMsg(int nlmsg_type, struct nl_object *obj)
{
    struct rtnl_link *link;
    struct rtnl_addr *addr;
    struct nl_addr *local;
    
    const char *ifname = NULL;
    string parent_ifname;
    char addr_str[MAX_ADDR_SIZE + 1] = {0};
    char macstr[MAX_ADDR_SIZE + 1] = {0};
    char *nil = "NULL";
    int afi;

    int ifindex;

    unsigned int    if_flags = 0;
    int l_link;
    
    m_netLinkOnMsg++;

    if ((nlmsg_type != RTM_NEWLINK) && (nlmsg_type != RTM_DELLINK) &&
        (nlmsg_type != RTM_NEWADDR) && (nlmsg_type != RTM_DELADDR))
        return;

    switch (nlmsg_type) 
    {

        case RTM_NEWLINK:
        {
            m_netLinkOnMsgLinkNew++;

            link = (struct rtnl_link *)obj; 
            ifname = rtnl_link_get_name(link);

            ifindex = rtnl_link_get_ifindex(link);
            afi = rtnl_link_get_family(link);

            if (!VrrpIsVrrpIntf(ifname))
            {
                /*
                SWSS_LOG_NOTICE("RTM_NEWLINK[%u/%u] Drop msg for ifname: %s",
                                m_netLinkOnMsgLinkNew, m_netLinkOnMsgLinkNewUse,
                                ifname ? ifname: nil);
                */
                return;
            }

            l_link = rtnl_link_get_link(link);
            parent_ifname = VrrpIfindexToName(l_link);            
            
            if_flags = rtnl_link_get_flags(link);
            bool proto_down = false;
            if (!vrrpReadProtoDownSysfs(ifname, proto_down))
            {
                return;
            }
            
            nl_addr2str(rtnl_link_get_addr(link), macstr, MAX_ADDR_SIZE);

            std::string if_name(ifname);
            std::string mac_val(macstr);            

            VrrpLinkProcess(ifindex, if_name, parent_ifname, afi, mac_val, if_flags, false, proto_down);
            m_netLinkOnMsgLinkNewUse++;
            m_netLinkOnMsgUse++;

            SWSS_LOG_NOTICE("RTM_NEWLINK[%u/%u] ifname: %s, if_flags = %d, proto_down=%d, mac = %s, l_link = %d",
                            m_netLinkOnMsgLinkNew, m_netLinkOnMsgLinkNewUse,
                            ifname ? ifname: nil, if_flags, (int)proto_down, macstr, l_link);
            
            break;
        }

        case RTM_DELLINK:
        {
            m_netLinkOnMsgLinkDel++;

            link = (struct rtnl_link *)obj;             
            ifname = rtnl_link_get_name(link);

            ifindex = rtnl_link_get_ifindex(link);
            afi = rtnl_link_get_family(link);

            if (!VrrpIsVrrpIntf(ifname)) 
            {
                /*
                SWSS_LOG_NOTICE("RTM_DELLINK[%u/%u] Drop msg for ifname: %s",
                            m_netLinkOnMsgLinkDel, m_netLinkOnMsgLinkDelUse,
                            ifname ? ifname: nil);
                */
                return;
            }
            
            l_link = rtnl_link_get_link(link);
            parent_ifname = VrrpIfindexToName(l_link);            
            
            if_flags = rtnl_link_get_flags(link);

            nl_addr2str(rtnl_link_get_addr(link), macstr, MAX_ADDR_SIZE);            

            std::string if_name(ifname);
            std::string mac_val(macstr);   

            VrrpLinkProcess(ifindex, if_name, parent_ifname, afi, mac_val, if_flags, true, true);
            m_vrrpinfo.erase(ifindex);
            m_netLinkOnMsgLinkDelUse++;
            m_netLinkOnMsgUse++;

            SWSS_LOG_NOTICE("RTM_DELLINK[%u/%u] ifname: %s, if_flags = %d", 
                            m_netLinkOnMsgLinkDel, m_netLinkOnMsgLinkDelUse,
                            ifname ? ifname: nil, if_flags);

            break;
        }

        case RTM_NEWADDR:
        {
            m_netLinkOnMsgAddrAdd++;

            addr = (struct rtnl_addr *)obj;
            ifindex = rtnl_addr_get_ifindex(addr); 
            afi = rtnl_addr_get_family(addr);

            std::string if_name = VrrpIfindexToName(ifindex);

            ifname = if_name.c_str();

            if (!VrrpIsVrrpIntf(ifname))
            {
                /*
                SWSS_LOG_NOTICE("RTM_NEWADDR[%u/%u] Drop msg for ifname: %s",
                                m_netLinkOnMsgAddrAdd, m_netLinkOnMsgAddrAddUse,
                                ifname ? ifname: nil);
                */
                return;
            }

            local = rtnl_addr_get_local(addr);

            if (NULL != local)
            {
                if (afi == AF_INET6 &&
                    IN6_IS_ADDR_LINKLOCAL(
                        static_cast<const struct in6_addr *>(
                            nl_addr_get_binary_addr(local))))
                {
                    nl_addr2str(local, addr_str, MAX_ADDR_SIZE);
                    SWSS_LOG_NOTICE("Skip unsupported IPv6 link-local VRRP address ifname: %s, address: %s",
                                    ifname ? ifname : nil, addr_str);
                    break;
                }

                nl_addr2str(local, addr_str, MAX_ADDR_SIZE);
                std::string vip_str(addr_str);

                m_netLinkOnMsgAddrAddUse++;
                m_netLinkOnMsgUse++;
                SWSS_LOG_NOTICE("RTM_NEWADDR[%u/%u] ifname: %s, addr = %s", 
                                m_netLinkOnMsgAddrAdd, m_netLinkOnMsgAddrAddUse,
                                ifname ? ifname: nil, addr_str); 

                VrrpAddrUp(ifindex, if_name, afi, vip_str);
            }
            
            break;
        }

        case RTM_DELADDR:
        {
            m_netLinkOnMsgAddrDel++;
            addr = (struct rtnl_addr *)obj;
            ifindex = rtnl_addr_get_ifindex(addr);                        
            afi = rtnl_addr_get_family(addr);
            
            std::string if_name = VrrpIfindexToName(ifindex);

            ifname = if_name.c_str();

            if (!VrrpIsVrrpIntf(ifname))
            {
                /*
                SWSS_LOG_NOTICE("RTM_DELADDR[%u/%u] Drop msg for ifname: %s",
                                m_netLinkOnMsgAddrDel, m_netLinkOnMsgAddrDelUse,
                                ifname ? ifname: nil);
                */
                return;           
            }
            
            local = rtnl_addr_get_local(addr);           

            if (NULL != local)
            {
                if (afi == AF_INET6 &&
                    IN6_IS_ADDR_LINKLOCAL(
                        static_cast<const struct in6_addr *>(
                            nl_addr_get_binary_addr(local))))
                {
                    nl_addr2str(local, addr_str, MAX_ADDR_SIZE);
                    SWSS_LOG_NOTICE("Skip unsupported IPv6 link-local VRRP address ifname: %s, address: %s",
                                    ifname ? ifname : nil, addr_str);
                    break;
                }

                nl_addr2str(local, addr_str, MAX_ADDR_SIZE);
                std::string vip_str(addr_str);                  

                m_netLinkOnMsgAddrDelUse++;
                m_netLinkOnMsgUse++;
                SWSS_LOG_NOTICE("RTM_DELADDR[%u/%u] ifname: %s, addr = %s", 
                                m_netLinkOnMsgAddrDel, m_netLinkOnMsgAddrDelUse,
                                ifname ? ifname: nil, addr_str);

                VrrpAddrDown(ifindex, if_name, afi, vip_str);
            }

            break;
        }

        default:
            SWSS_LOG_NOTICE("netlink[%u/%u]: unhandled event nlmsg_type: %d", 
                            m_netLinkOnMsg, m_netLinkOnMsgUse, nlmsg_type);
            break;
            
    } 

    SWSS_LOG_NOTICE("NETLINK_MSG[%u/%u]: linknew %u/%u linkdel %u/%u "
                    "Addradd %u/%u Addrdel %u/%u",
                    m_netLinkOnMsg, m_netLinkOnMsgUse, 
                    m_netLinkOnMsgLinkNew, m_netLinkOnMsgLinkNewUse,
                    m_netLinkOnMsgLinkDel, m_netLinkOnMsgLinkDelUse,
                    m_netLinkOnMsgAddrAdd, m_netLinkOnMsgAddrAddUse,
                    m_netLinkOnMsgAddrDel, m_netLinkOnMsgAddrDelUse);

}
