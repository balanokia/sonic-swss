#include "sai.h"
#include "macaddress.h"
#include "orch.h"
#include "request_parser.h"
#include "portsorch.h"
#include "port.h"
#include "saihelper.h"
#include "fdborch.h"
#include "intfsorch.h"
#include "vrrporch.h"

extern sai_router_interface_api_t*  sai_router_intfs_api;
extern PortsOrch *gPortsOrch;
extern sai_object_id_t gSwitchId;
extern FdbOrch *gFdbOrch;
extern IntfsOrch *gIntfsOrch;
/*
 * VIP is a kernel local address + noprefixroute and reached
 * through the parent subnet route, so no ASIC route programmed for it.
 */
bool VrrpOrch::addOperation(const Request& request)
{
    SWSS_LOG_ENTER();
    sai_attribute_t attr;
    vector<sai_attribute_t> vmac_attrs;
    Port port;
    MacAddress mac;
    sai_object_id_t vrrp_rif_id;
    sai_object_id_t port_oid;
    for (const auto& name: request.getAttrFieldNames())
    {
        if (name == "vmac")
        {
            mac = request.getAttrMacAddress("vmac");
            attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
            memcpy(attr.value.mac, mac.getMac(), sizeof(sai_mac_t));
            SWSS_LOG_INFO("vrrp orch add : vmac %s ",mac.to_string().c_str());
            vmac_attrs.push_back(attr);
        }
    }
    auto ip_pfx = request.getKeyIpPrefix(1);
    /* Check if the vmac,vip combination is already programmed on the port.If yes, skip & return*/
    auto key = vrrp_key_t(request.getKeyString(0),request.getKeyIpPrefix(1));
    auto it = vrrp_table_.find(key);
    if (it != vrrp_table_.end())
    {
       if (vrrp_table_[key].vmac == request.getAttrMacAddress("vmac"))
        {
            SWSS_LOG_ERROR("_vrrp_table entry already exists, with vmac %s, vip %s for port %s",mac.to_string().c_str(),
                ip_pfx.to_string().c_str(),request.getKeyString(0).c_str());
            return true;
        }
        SWSS_LOG_INFO("vip %s on port %s belongs to vmac %s, pending vmac %s until it is removed",
                ip_pfx.to_string().c_str(),request.getKeyString(0).c_str(),
                vrrp_table_[key].vmac.to_string().c_str(),mac.to_string().c_str());
        return false;
    }
    const auto& alias = request.getKeyString(0);

    if (!gPortsOrch->allPortsReady())
    {
        return false;
    }

    if (!gPortsOrch->getPort(alias, port))
    {
        SWSS_LOG_INFO("Port %s is not ready, pending VRRP %s",
                      alias.c_str(), ip_pfx.to_string().c_str());
        return false;
    }

    if (port.m_rif_id == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_INFO("Port %s has no router interface, pending VRRP %s",
                      alias.c_str(), ip_pfx.to_string().c_str());
        return false;
    }

    if (port.m_type == Port::VLAN &&
        port.m_vlan_info.vlan_oid == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_INFO("VLAN %s has no oid, pending VRRP", alias.c_str());
        return false;
    }

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    switch(port.m_type)
    {
        case Port::PHY:
        case Port::LAG:
            attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_PORT;
            break;
        case Port::VLAN:
            attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_VLAN;
            break;
        case Port::SUBPORT:
            attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_SUB_PORT;
            break;
        default:
            SWSS_LOG_ERROR("Unsupported port type: %d", port.m_type);
            return true;
    }
    vmac_attrs.push_back(attr);
    switch(port.m_type)
    {
        case Port::PHY:
            attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
            attr.value.oid = port.m_port_id;
            break;
        case Port::LAG:
            attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
            attr.value.oid = port.m_lag_id;
            break;
        case Port::VLAN:
            attr.id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
            attr.value.oid = port.m_vlan_info.vlan_oid;
            break;
        case Port::SUBPORT:
            attr.id = SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID;
            attr.value.u16 = port.m_vlan_info.vlan_id;
            vmac_attrs.push_back(attr);
            attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
            attr.value.oid = port.m_parent_port_id;
            break;
        default:
            SWSS_LOG_ERROR("Unsupported port type: %d", port.m_type);
            return true;
    }
    port_oid = attr.value.oid;
    vmac_attrs.push_back(attr);
    SWSS_LOG_NOTICE("vrrp orch add : port %s, ip %s, vmac %s",request.getKeyString(0).c_str(),ip_pfx.to_string().c_str(),mac.to_string().c_str());
    attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    if (port.m_vr_id != SAI_NULL_OBJECT_ID)
    {
        attr.value.oid = port.m_vr_id;
    }
    else
    {
        attr.value.oid = gVirtualRouterId;
    }
    vmac_attrs.push_back(attr);
    attr.id = SAI_ROUTER_INTERFACE_ATTR_IS_VIRTUAL;
    attr.value.booldata =  true;
    vmac_attrs.push_back(attr);
    //program VRRPMAC when first vip of the vrrp group configured and its master.
    auto& group = vrrp_group_table_[vrrp_group_key_t(alias, mac)];
    if (group.rifid == SAI_NULL_OBJECT_ID)
    {
        sai_status_t vmac_status = sai_router_intfs_api->create_router_interface(&vrrp_rif_id, gSwitchId, (uint32_t)vmac_attrs.size(), vmac_attrs.data());
        SWSS_LOG_NOTICE("vrrp orch add, after create_router_interface : port name %s, rif_id 0x%" PRIx64, request.getKeyString(0).c_str(),vrrp_rif_id);
        if (vmac_status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to program Vrrp Mac on interface %s, rv:%d",
                     port.m_alias.c_str(), vmac_status);
            task_process_status handle_status = handleSaiCreateStatus(SAI_API_ROUTER_INTERFACE, vmac_status);
            return parseHandleSaiStatusFailure(handle_status);
        }
        group.rifid = vrrp_rif_id;
        gIntfsOrch->increaseRouterIntfsRefCount(alias);
    }
    vrrp_rif_id = group.rifid;
    group.vip_count++;
    vrrp_table_[key] = {mac, vrrp_rif_id};
    SWSS_LOG_NOTICE("_vrrp_table add port %s, ip %s, vmac %s, rif_id 0x%" PRIx64 ", vips %u", request.getKeyString(0).c_str(),
                            ip_pfx.to_string().c_str(),mac.to_string().c_str(),vrrp_rif_id,group.vip_count);
    FdbEntry entry;
    entry.mac = request.getAttrMacAddress("vmac");
    entry.bv_id = port_oid;
    gFdbOrch->removeFdbEntry(entry, FDB_ORIGIN_LEARN);
    return true;
}
bool VrrpOrch::delOperation(const Request& request)
{
    SWSS_LOG_ENTER();
    Port port;
    sai_object_id_t port_oid = 0;
    auto key = vrrp_key_t(request.getKeyString(0),request.getKeyIpPrefix(1));
    auto it = vrrp_table_.find(key);
    if (it == vrrp_table_.end())
    {
        SWSS_LOG_ERROR("VRRP entry for port %s, vip %s doesn't exist", request.getKeyString(0).c_str(),request.getKeyIpPrefix(1).to_string().c_str());
        return true;
    }
    bool port_found = gPortsOrch->getPort(request.getKeyString(0), port);
    auto ip_pfx = request.getKeyIpPrefix(1);
    if (port_found)
    {
        switch(port.m_type)
        {
            case Port::PHY:
                port_oid = port.m_port_id;
                break;
            case Port::LAG:
                port_oid = port.m_lag_id;
                break;
            case Port::VLAN:
                port_oid = port.m_vlan_info.vlan_oid;
                break;
            case Port::SUBPORT:
                port_oid = port.m_parent_port_id;
                break;
            default:
                SWSS_LOG_ERROR("Unsupported port type: %d", port.m_type);
                break;
        }
        FdbEntry entry;
        entry.mac = vrrp_table_[key].vmac;
        entry.bv_id = port_oid;
        gFdbOrch->removeFdbEntry(entry, FDB_ORIGIN_LEARN);
    }

    //Remove VRRPMAC when last vip of the vrrp group removed
    auto& group = vrrp_group_table_[vrrp_group_key_t(request.getKeyString(0), vrrp_table_[key].vmac)];
    if (group.vip_count == 1)
    {
        sai_status_t vmac_status = sai_router_intfs_api->remove_router_interface (group.rifid);
        if (vmac_status == SAI_STATUS_ITEM_NOT_FOUND)
        {
            SWSS_LOG_WARN("Vrrp Mac rif 0x%" PRIx64 " on interface %s not found",
                     group.rifid, request.getKeyString(0).c_str());
        }
        else if (vmac_status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to delete Vrrp Mac on interface %s, rv:%d",
                     request.getKeyString(0).c_str(), vmac_status);
            task_process_status handle_status = handleSaiRemoveStatus(SAI_API_ROUTER_INTERFACE, vmac_status);
            return parseHandleSaiStatusFailure(handle_status);
        }
        gIntfsOrch->decreaseRouterIntfsRefCount(request.getKeyString(0));
        group.rifid = SAI_NULL_OBJECT_ID;
    }
    if (group.vip_count > 0)
    {
        group.vip_count--;
    }
    SWSS_LOG_NOTICE("vrrp orch del success,port %s vip %s vmac %s rifid 0x%" PRIx64 ", vips %u", request.getKeyString(0).c_str(),
        ip_pfx.to_string().c_str(),vrrp_table_[key].vmac.to_string().c_str(),vrrp_table_[key].rifid,group.vip_count);
    vrrp_table_.erase(key);
    return true;
}
