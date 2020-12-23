#include "parsetlvs.h"
#include "lldp_tlv.h"
#include "agent.h"

struct NotificationMessageQueue *notificationList = NULL;
struct NotificationMessageQueue *notificationListCashed = NULL;
pthread_mutex_t m_notificationListMutex;
pthread_mutex_t m_neighborDeleteMutex;
pthread_t notificationServiceThreadId;
pthread_cond_t m_cond;

char old_tlv_data[MAX_NOTIFICATION_TLV_TYPE][MAX_TLV_INFO];
struct sockaddr_in m_serverAddress;
int running = 1;

char chassisSubtypetoString[TOTAL_CHASSIS_SUBTYPES][MAX_CHASIS_ID_TYPE_LENGTH] = { "" ,
                                                                                   "CHASSIS_COMPONENT",
                                                                                   "INTERFACE_ALIAS",
                                                                                   "PORT_COMPONENT",
                                                                                   "MAC_ADDRESS",
                                                                                   "NETWORK_ADDRESS",
                                                                                   "INTERFACE_NAME",
                                                                                   "LOCAL"};
char portSubtypetoString[TOTAL_PORT_SUBTYPES][MAX_PORT_ID_TYPE_LENGTH] = { "" ,
                                                                           "INTERFACE_ALIAS",
                                                                           "PORT_COMPONENT",
                                                                           "MAC_ADDRESS",
                                                                           "NETWORK_ADDRESS",
                                                                           "INTERFACE_NAME",
                                                                           "AGENT_CIRCUIT_ID",
                                                                           "LOCAL"};

char tlvIdToString[TOTOAL_NOTIFICATION_TLVS][MAX_PORT_ID_TYPE_LENGTH] = { 	"" ,
                                                                            "chassis-id",
                                                                            "port-id",
                                                                            "",
                                                                            "port-description",
                                                                            "system-name",
                                                                            "system-description",
                                                                            "",
                                                                            "management-address",
                                                                            "chassis-id-type",
                                                                            "port-id-type",
                                                                            "management-address-type"
                                                                        };

char managementAddressSubtypetoString[TOTAL_MANAGEMENT_ADDRESS_SUBTYPES][MAX_MGMT_TYPE_LENGTH] ={ "",
                                                                                                  "IPV4",
                                                                                                  "IPV6"};
unsigned long getTickCount()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (tp.tv_sec*1000 + tp.tv_usec/1000);
}

void sendLLDPChangeNotification(const char* text, char *ifName, u16 neighborId, bool deleteNotification)
{
    LLDPAD_INFO("[%s]: %s \n", __FILE__, __func__);
    struct NotificationMessageQueue *p = malloc(sizeof(struct NotificationMessageQueue));
    if(p != NULL)
    {
        memset(p, 0, sizeof(struct NotificationMessageQueue));
        p->next = NULL;
        if(notificationList)
            p->next = notificationList;
        notificationList = p;
        p->message.header.type = NOTIFICATION_HEADER_TYPE;
        p->message.header.flags = 0;
        p->message.header.length = sizeof(NotificationMessage);

        p->message.content.eventType = NOTIFICATION;
        p->message.content.eventId = CFG_STATE_VALUE_CHANGED_EVT;
        memset(p->message.content.name,'\0', sizeof(p->message.content.name));
        memset(p->message.content.text,'\0', sizeof(p->message.content.text));
        snprintf(p->message.content.text, sizeof(p->message.content.text), "%s", text);
        if(deleteNotification)
            snprintf(p->message.content.name, sizeof(p->message.content.name), "lldp:interfaces,type:delete,interface:%s,id:%d:", ifName, neighborId);
        else
            snprintf(p->message.content.name, sizeof(p->message.content.name), "lldp:interfaces,type:update,interface:%s,id:%d:", ifName, neighborId);

            p->message.content.timecreated = getTickCount();
    }
}

void NotificationMessageSender(const char* serverIp, int port)
{
    char m_serverIp[20];
    int m_port;

    memset(&m_serverIp,0,sizeof(m_serverIp));
    strcpy(m_serverIp, serverIp);
    m_port = port;

    bzero(&m_serverAddress, sizeof(m_serverAddress));
    m_serverAddress.sin_family = AF_INET;
    inet_pton(AF_INET, m_serverIp, &m_serverAddress.sin_addr);
    m_serverAddress.sin_port = htons(port);
}


bool sendNotificationToServer(NotificationMessage message)
{
    bool ret = false;
    int m_sock;
    m_sock = socket(AF_INET, SOCK_STREAM, 0);

    struct timeval tv;
    tv.tv_sec =  1;
    tv.tv_usec = 0;

    if(setsockopt(m_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv)) < 0)
    {
        close(m_sock);
        return false;
    }

    if(setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)) < 0)
    {
        close(m_sock);
        return false;
    }

    if(connect(m_sock, (struct sockaddr*)&m_serverAddress, sizeof(m_serverAddress)) != -1)
    {
        NotificationMessage data = message;
        if(-1 != send(m_sock, &data, sizeof(NotificationMessage), 0))
        {
            ret = true;
        }
    }
    else
    {
        LLDPAD_ERR("Can not connect to Notification Server");
    }

    if(ret)
    {
        LLDPAD_DBG("Send notification to NBI OK : eventType:%d, eventId=%d, name=%s, text=%s\n",
                    message.content.eventType,
                    message.content.eventId,
                    message.content.name, message.content.text);
    }
    else
    {
        LLDPAD_ERR("Send notification to NBI Failed : eventType:%d, eventId=%d, name=%s\n",
                    message.content.eventType,
                    message.content.eventId,
                    message.content.name);
    }

    close(m_sock);
    return ret;
}

void convtlvinfo_to_string(int len,char *iinfo,char *oinfo)
{
    char *p = iinfo;
    unsigned char *printStr = oinfo;

    for(int i=0; i < len; i++)
    {
        sprintf(printStr, "%02X", *p);
        printStr += 2;
        p += 1;
    }
}

/*
 * This method prepares the notification text to be send out for delete notifications in case of timeout
 */
void ttlTimeoutNotification(struct neighbor *neighbor, char* NotificationText)
{
    char tlvs[512] = {0};
    char chassisId[64] = {0};
    char chassisIdType[64] = {0};
    char portId[64] = {0};
    char portIdType[64] = {0};
    char sysName[64] = {0};
    char sysDesc[512] = {0};
    char portDesc[512] = {0};
    char mgmtAddress[64] ={0};
    char mgmtAddressType[64] ={0};


    if(neighbor->tlvs_presence[CHASSIS_ID_TLV] && (neighbor->oldtlvs.chassis->info != NULL))
    {
        convtlvinfo_to_string(neighbor->oldtlvs.chassis->length, neighbor->oldtlvs.chassis->info, tlvs);
        extract_chassis_id(neighbor->oldtlvs.chassis->length, tlvs, chassisId, chassisIdType);
        addNotificationText(NotificationText, "chassis-id", chassisId);
        addNotificationText(NotificationText, "chassis-id-type", chassisIdType);
    }
    if(neighbor->tlvs_presence[PORT_ID_TLV] && (neighbor->oldtlvs.portid->info != NULL))
    {
        memset(tlvs, 0, sizeof(tlvs));
        convtlvinfo_to_string(neighbor->oldtlvs.portid->length, neighbor->oldtlvs.portid->info, tlvs);
        extract_port_id(neighbor->oldtlvs.portid->length, tlvs, portId, portIdType);
        addNotificationText(NotificationText, "port-id", portId);
        addNotificationText(NotificationText, "port-id-type", portIdType);
    }
    if(neighbor->tlvs_presence[SYSTEM_NAME_TLV] && (neighbor->oldtlvs.sysname->info != NULL))
    {
        memset(tlvs, 0, sizeof(tlvs));
        convtlvinfo_to_string(neighbor->oldtlvs.sysname->length, neighbor->oldtlvs.sysname->info, tlvs);
        extract_string_tlv(neighbor->oldtlvs.sysname->length, tlvs, sysName);
        addNotificationText(NotificationText, "system-name", sysName);
    }
    if(neighbor->tlvs_presence[PORT_DESCRIPTION_TLV] && (neighbor->oldtlvs.portdesc->info != NULL))
    {
        memset(tlvs, 0, sizeof(tlvs));
        convtlvinfo_to_string(neighbor->oldtlvs.portdesc->length,
                              neighbor->oldtlvs.portdesc->info, tlvs);
        extract_string_tlv(neighbor->oldtlvs.portdesc->length, tlvs, portDesc);
        addNotificationText(NotificationText, "port-description", portDesc);
    }
    if(neighbor->tlvs_presence[SYSTEM_DESCRIPTION_TLV] && (neighbor->oldtlvs.sysdesc->info != NULL))
    {
        memset(tlvs, 0, sizeof(tlvs));
        convtlvinfo_to_string(neighbor->oldtlvs.sysdesc->length,
                              neighbor->oldtlvs.sysdesc->info, tlvs);
        extract_string_tlv(neighbor->oldtlvs.sysdesc->length, tlvs, sysDesc);
        addNotificationText(NotificationText, "system-description", sysDesc);
    }
    if(neighbor->tlvs_presence[MANAGEMENT_ADDRESS_TLV] && (neighbor->oldtlvs.mgmtadd->info != NULL))
    {
        memset(tlvs, 0, sizeof(tlvs));
        convtlvinfo_to_string(neighbor->oldtlvs.mgmtadd->length, neighbor->oldtlvs.mgmtadd->info, tlvs);
        extract_mng_addr(neighbor->oldtlvs.mgmtadd->length, tlvs, mgmtAddress, mgmtAddressType);
        addNotificationText(NotificationText, "management-address", mgmtAddress);
        addNotificationText(NotificationText, "management-address-type", mgmtAddressType);
    }
}

/*
 * This method prepares the notification text to be send out for delete notifications.
 */
void deleteNotifications(struct neighbor *neighbor, char* NotificationText)
{
    char tlvs[512] = {0};
    char sysName[64] = {0};
    char sysDesc[512] = {0};
    char portDesc[512] = {0};
    char mgmtAddress[64] ={0};
    char mgmtAddressType[64] ={0};

    if(!(neighbor->tlvs_presence[SYSTEM_NAME_TLV]) && (neighbor->oldtlvs.sysname->info != NULL)) // check whether tlv is not available and old tlv have info
    {
        convtlvinfo_to_string(neighbor->oldtlvs.sysname->length, neighbor->oldtlvs.sysname->info, tlvs);
        extract_string_tlv(neighbor->oldtlvs.sysname->length, tlvs, sysName);
        addNotificationText(NotificationText, "system-name", sysName);
        memset(neighbor->oldtlvs.sysname->info,0,neighbor->oldtlvs.sysname->length);
        neighbor->oldtlvs.sysname->length = 0;
    }
    if(!(neighbor->tlvs_presence[PORT_DESCRIPTION_TLV]) && (neighbor->oldtlvs.portdesc->info != NULL))
    {
        memset(tlvs, 0, sizeof(tlvs));
        convtlvinfo_to_string(neighbor->oldtlvs.portdesc->length,
                              neighbor->oldtlvs.portdesc->info, tlvs);
        extract_string_tlv(neighbor->oldtlvs.portdesc->length, tlvs, portDesc);
        addNotificationText(NotificationText, "port-description", portDesc);
        memset(neighbor->oldtlvs.portdesc->info,0,neighbor->oldtlvs.portdesc->length);
        neighbor->oldtlvs.portdesc->length=0;
    }
    if(!(neighbor->tlvs_presence[SYSTEM_DESCRIPTION_TLV]) && (neighbor->oldtlvs.sysdesc->info != NULL))
    {
        memset(tlvs, 0, sizeof(tlvs));
        convtlvinfo_to_string(neighbor->oldtlvs.sysdesc->length,
                              neighbor->oldtlvs.sysdesc->info, tlvs);
        extract_string_tlv(neighbor->oldtlvs.sysdesc->length, tlvs, sysDesc);
        addNotificationText(NotificationText, "system-description", sysDesc);
        memset(neighbor->oldtlvs.sysdesc->info,0,neighbor->oldtlvs.sysdesc->length);
        neighbor->oldtlvs.sysdesc->length = 0;
    }
    if(!(neighbor->tlvs_presence[MANAGEMENT_ADDRESS_TLV]) && (neighbor->oldtlvs.mgmtadd->info != NULL))
    {
        memset(tlvs, 0, sizeof(tlvs));
        convtlvinfo_to_string(neighbor->oldtlvs.mgmtadd->length, neighbor->oldtlvs.mgmtadd->info, tlvs);
        extract_mng_addr(neighbor->oldtlvs.mgmtadd->length, tlvs, mgmtAddress,mgmtAddressType);
        addNotificationText(NotificationText, "management-address", mgmtAddress);
        addNotificationText(NotificationText, "management-address-type", mgmtAddressType);
        memset(neighbor->oldtlvs.mgmtadd->info,0,neighbor->oldtlvs.mgmtadd->length);
    }

    LLDPAD_DBG("DELETE NOTIFICATION FUNCTION : notificationText : %s\n", NotificationText);
}

void createNotifications(struct unpacked_tlv *tlv, struct unpacked_tlv *oldtlv, char *NotificationText)
{
    char tlvs[512] = {0};
    char old_tlvs[512] = {0};
    char tlv_ID[64] = {0};
    char old_tlv_ID[64] = {0};
    char tlv_ID_Type[64] = {0};
    char old_tlv_ID_Type[64] = {0};
    char tlv_des[512] = {0};
    char old_tlv_des[512] = {0};
    int idType = 0;

    //Convert to string the TLV info.
    convtlvinfo_to_string(tlv->length, tlv->info, tlvs);
    convtlvinfo_to_string(oldtlv->length, oldtlv->info, old_tlvs);

    if(tlv->type == CHASSIS_ID_TLV || tlv->type == PORT_ID_TLV || tlv->type == MANAGEMENT_ADDRESS_TLV)
    {
        if(tlv->type == CHASSIS_ID_TLV)
        {
            idType = CHASSIS_ID_TYPE;
            extract_chassis_id(tlv->length, tlvs, tlv_ID, tlv_ID_Type);
            extract_chassis_id(oldtlv->length, old_tlvs, old_tlv_ID, old_tlv_ID_Type);
        }
        else if(tlv->type == PORT_ID_TLV)
        {
            idType = PORT_ID_TYPE;
            extract_port_id(tlv->length, tlvs, tlv_ID, tlv_ID_Type);
            extract_port_id(oldtlv->length, old_tlvs, old_tlv_ID, old_tlv_ID_Type);
        }
        else
        {
            idType = MANAGEMENT_ADDRESS_TYPE;
            extract_mng_addr(tlv->length, tlvs, tlv_ID, tlv_ID_Type);
            extract_mng_addr(oldtlv->length, old_tlvs, old_tlv_ID, old_tlv_ID_Type);
        }

        /* comparing id type */
        if(strcmp(tlv_ID_Type, old_tlv_ID_Type) == 0)
            LLDPAD_DBG("Old and new %s matched, value:%s\n", tlvIdToString[idType], tlv_ID_Type);
        else
        {
            LLDPAD_DBG("Old and new %s not matched, new: %s, old: %s\n", tlvIdToString[idType], tlv_ID_Type, old_tlv_ID_Type);
            addNotificationText(NotificationText, tlvIdToString[idType], tlv_ID_Type);
        }

        /* comparing data */
        if(strcmp(tlv_ID, old_tlv_ID) == 0)
            LLDPAD_DBG("Old and new %s data matched.\n", tlvIdToString[idType]);
        else
        {
            LLDPAD_DBG("Old and new %s data not matched, new: %s, old: %s\n", tlvIdToString[tlv->type], tlv_ID, old_tlv_ID);
            addNotificationText(NotificationText, tlvIdToString[tlv->type], tlv_ID);
        }
    }
    else if(tlv->type == PORT_DESCRIPTION_TLV || tlv->type == SYSTEM_NAME_TLV || tlv->type == SYSTEM_DESCRIPTION_TLV)
    {
        extract_string_tlv(tlv->length, tlvs, tlv_des);
        extract_string_tlv(oldtlv->length, old_tlvs, old_tlv_des);

        if(strcmp(tlv_des, old_tlv_des) == 0)
            LLDPAD_DBG("Old and new %s matched, value: %s\n", tlvIdToString[tlv->type], tlvs);
        else
        {
            LLDPAD_DBG("Old and new %s not matched, new: %s, old: %s\n", tlvIdToString[tlv->type], tlv_des, old_tlv_des);
            addNotificationText(NotificationText, tlvIdToString[tlv->type], tlv_des);
        }
    }
}

olsRet_t extract_chassis_id(u16 len, char *info,char* chassis_id, char* chassis_id_type)
{
    u8 subtype;
    u8 addrnum;
    int i;
    olsRet_t ret=OLS_RET_OK;
    char chassisId[256];

    if(chassis_id == NULL || chassis_id_type == NULL )
        return OLS_RET_ERROR;

    memset(&chassisId, '\0', sizeof(chassisId));
    //check for length of tlv of chassis id
    if (!len || len > MAX_CHASSIS_ID_LENGTH)
        return OLS_RET_ERROR;

    hexstr2bin(info, (u8 *)&subtype, sizeof(subtype));

    switch (subtype) {
        case CHASSIS_ID_MAC_ADDRESS:
                if (len != 1 + 6)   //checking proper length of mac address
                        ret=OLS_RET_ERROR;

                //for loop to get chassis id, Here 12 is length of mac addess
                for (i = 0; i < 12; i+=2) {
                        snprintf(chassisId+strlen(chassisId), sizeof(chassisId+strlen(chassisId)), "%2.2s", info +2 + i); //info+2...here 2 bytes skipping which is for type and length
                        if (i < 10)
                        {
                              //  sprintf(chassisId+strlen(chassisId),":");  //putting ':' after byte to make proper format of mac address
                                chassisId[strlen(chassisId)] = ':' ; //putting ':' after byte to make proper format of mac address
                        }
                }
                snprintf(chassis_id, MAX_CHASSIS_ID_LENGTH, "%s", chassisId);
                snprintf(chassis_id_type, MAX_CHASIS_ID_TYPE_LENGTH, "MAC_ADDRESS");

                break;
        case CHASSIS_ID_NETWORK_ADDRESS:
                if (len <=2) {                                  //checking proper length of network address
                      LLDPAD_ERR("Bad Network Address\n");
                       ret=OLS_RET_ERROR;
                        break;
                }

                hexstr2bin(info+2, (u8 *)&addrnum, sizeof(addrnum));

                switch(addrnum) {
                case MANADDR_IPV4:
                        if (len == IPV4_LENGTH) {                 //checking length for IPV4(standard length 6)
                                struct in_addr addr;
                                hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
                                inet_ntop(AF_INET, (void *)&addr, chassisId,sizeof(chassisId));
                                snprintf(chassis_id, MAX_CHASSIS_ID_LENGTH, "%s", chassisId);
                                snprintf(chassis_id_type, MAX_CHASIS_ID_TYPE_LENGTH, "NETWORK_ADDRESS");
                        } else {
                               LLDPAD_ERR("Bad IPv4: %*.*s\n",2*(len-2), 2*(len-2), info+4);
                               ret=OLS_RET_ERROR;
                        }
                        break;
                case MANADDR_IPV6:
                        if (len == IPV6_LENGTH) {            //checking length for IPV6(standard length 18)
                                struct in6_addr addr;
                                hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
                                inet_ntop(AF_INET6, (void *)&addr, chassisId,sizeof(chassisId));
                                snprintf(chassis_id, MAX_CHASSIS_ID_LENGTH, "%s", chassisId);
                                snprintf(chassis_id_type, MAX_CHASIS_ID_TYPE_LENGTH, "NETWORK_ADDRESS");
                        } else {
                               LLDPAD_ERR("Bad IPv6: %*.*s\n",2*(len-2), 2*(len-2), info+4);
                                ret=OLS_RET_ERROR;
                        }
                        break;
                default:
                        break;
                }
                break;
        case CHASSIS_ID_CHASSIS_COMPONENT:
                hexstr2bin(info+2, (u8 *)&chassisId[0], len-1);  // info+2...here 2 bytes skipping which is for type and length
                snprintf(chassis_id, MAX_CHASSIS_ID_LENGTH, "%s", chassisId);
                snprintf(chassis_id_type, MAX_CHASIS_ID_TYPE_LENGTH, "CHASSIS_COMPONENT");
                break;
        case CHASSIS_ID_INTERFACE_ALIAS:
                hexstr2bin(info+2, (u8 *)&chassisId[0], len-1);  // info+2...here 2 bytes skipping which is for type and length
                snprintf(chassis_id, MAX_CHASSIS_ID_LENGTH, "%s", chassisId);
                snprintf(chassis_id_type, MAX_CHASIS_ID_TYPE_LENGTH, "INTERFACE_ALIAS");
                break;
        case CHASSIS_ID_PORT_COMPONENT:
                hexstr2bin(info+2, (u8 *)&chassisId[0], len-1);  // info+2...here 2 bytes skipping which is for type and length
                snprintf(chassis_id, MAX_CHASSIS_ID_LENGTH, "%s", chassisId);
                snprintf(chassis_id_type, MAX_CHASIS_ID_TYPE_LENGTH, "PORT_COMPONENT");
                break;
        case CHASSIS_ID_INTERFACE_NAME:
                hexstr2bin(info+2, (u8 *)&chassisId[0], len-1);  // info+2...here 2 bytes skipping which is for type and length
                snprintf(chassis_id, MAX_CHASSIS_ID_LENGTH, "%s", chassisId);
                snprintf(chassis_id_type, MAX_CHASIS_ID_TYPE_LENGTH, "INTERFACE_NAME");
                break;
        case CHASSIS_ID_LOCALLY_ASSIGNED:
                hexstr2bin(info+2, (u8 *)&chassisId[0], len-1);  // info+2...here 2 bytes skipping which is for type and length
                snprintf(chassis_id, MAX_CHASSIS_ID_LENGTH, "%s", chassisId);
                snprintf(chassis_id_type, MAX_CHASIS_ID_TYPE_LENGTH, "LOCAL");
                break;
        default:
               LLDPAD_ERR("Bad Chassis ID: %*.*s\n", 2*len, 2*len, info);
                break;
        }

    return ret;
}

olsRet_t extract_port_id(u16 len, char *info,char *port_id,char*port_id_type)
{
    u8 subtype;
    u8 addrnum;
    char buf[256];
    int i;
    char portId[256];
    olsRet_t ret=OLS_RET_OK;

    if(port_id == NULL || port_id_type == NULL )
    {
        LLDPAD_ERR("NULL VALUE DETECTED FOR %s",__func__ );
            return OLS_RET_ERROR;
    }

     memset(&portId, '\0', sizeof(portId));

        if (!len || len > MAX_PORT_ID_LENGTH) {    //check for proper length of tlv
               LLDPAD_ERR("Invalid length = %d\n", len);
                return OLS_RET_ERROR;
        }

        hexstr2bin(info, (u8 *)&subtype, sizeof(subtype));

        memset(buf, 0, sizeof(buf));
        switch (subtype) {
        case PORT_ID_MAC_ADDRESS:
                if (len != 1 + 6)//checking length for mac address
                        ret=OLS_RET_ERROR;
                //for loop to get portid, Here 12 is length of mac addess
                for (i = 0; i < 12; i+=2) {
                        snprintf(portId+strlen(portId), sizeof(portId+strlen(portId)), "%2.2s", info +2 + i); // info+2...here 2 bytes skipping which is for type and length
                        if (i < 10)
                            portId[strlen(portId)]=':';

                }
                snprintf(port_id, MAX_PORT_ID_LENGTH, "%s", portId);
                snprintf(port_id_type, MAX_PORT_ID_TYPE_LENGTH, "MAC_ADDRESS");
                break;
        case PORT_ID_NETWORK_ADDRESS:
                if (len <=2) {      //checking length for network address
                       LLDPAD_ERR("Bad Network Address\n");
            ret=OLS_RET_ERROR;
            break;
                }

                hexstr2bin(info+2, (u8 *)&addrnum, sizeof(addrnum));

                switch(addrnum) {
                case MANADDR_IPV4:
                        if (len == IPV4_LENGTH) {     //checking length for IPV4(standard length 6)
                                struct in_addr addr;
                                hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
                                inet_ntop(AF_INET, (void *)&addr, portId,
                                          sizeof(portId));
                                snprintf(port_id, MAX_PORT_ID_LENGTH, "%s", portId);
                                snprintf(port_id_type, MAX_PORT_ID_TYPE_LENGTH, "NETWORK_ADDRESS");
                        } else {
                               LLDPAD_ERR("Bad IPv4: %*.*s\n",2*(len-2), 2*(len-2), info+4);
                                ret=OLS_RET_ERROR;
                        }
                        break;
                case MANADDR_IPV6:
                        if (len == IPV6_LENGTH) {    //checking length for IPV6(standard length 18)
                                struct in6_addr addr;
                                hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
                                inet_ntop(AF_INET6, (void *)&addr, portId,
                                          sizeof(portId));
                                snprintf(port_id, MAX_PORT_ID_LENGTH, "%s", portId);
                                snprintf(port_id_type, MAX_PORT_ID_TYPE_LENGTH, "NETWORK_ADDRESS");
                        } else {
                               LLDPAD_ERR("Bad IPv6: %*.*s",2*(len-2), 2*(len-2), info+4);
                                ret=OLS_RET_ERROR;
                        }
                        break;
                default:
                       LLDPAD_ERR("Network Address Type %d: %*.*s\n", addrnum,2*(len-2), 2*(len-2), info+2);
                        break;
                }
                break;
        case PORT_ID_INTERFACE_ALIAS:
                hexstr2bin(info+2, (u8 *)&portId[0], len-1);// info+2...here 2 bytes skipping which is for type and length
                snprintf(port_id, MAX_PORT_ID_LENGTH, "%s", portId);
                snprintf(port_id_type, MAX_PORT_ID_TYPE_LENGTH, "INTERFACE_ALIAS");
                break;
        case PORT_ID_PORT_COMPONENT:
                hexstr2bin(info+2, (u8 *)&portId[0], len-1);// info+2...here 2 bytes skipping which is for type and length
                snprintf(port_id, MAX_PORT_ID_LENGTH, "%s", portId);
                snprintf(port_id_type, MAX_PORT_ID_TYPE_LENGTH, "PORT_COMPONENT");
                break;
        case PORT_ID_INTERFACE_NAME:
                hexstr2bin(info+2, (u8 *)&portId[0], len-1);// info+2...here 2 bytes skipping which is for type and length
                snprintf(port_id, MAX_PORT_ID_LENGTH, "%s", portId);
                snprintf(port_id_type, MAX_PORT_ID_TYPE_LENGTH, "INTERFACE_NAME");
                break;
        case PORT_ID_LOCALLY_ASSIGNED:
                hexstr2bin(info+2, (u8 *)&portId[0], len-1);// info+2...here 2 bytes skipping which is for type and length
                snprintf(port_id, MAX_PORT_ID_LENGTH, "%s", portId);
                snprintf(port_id_type, MAX_PORT_ID_TYPE_LENGTH, "LOCAL");
                break;
        case PORT_ID_AGENT_CIRCUIT_ID:
                snprintf(port_id, MAX_PORT_ID_LENGTH, "%s", portId);
                snprintf(port_id_type, MAX_PORT_ID_TYPE_LENGTH, "AGENT_CIRCUIT_ID");
                break;
        default:
               LLDPAD_ERR("Bad Port ID: %*.*s\n", 2*len, 2*len, info);
                break;
        }

        return ret;
}

olsRet_t extract_string_tlv(u16 len, char *info, char* tlv_value)
{
    int i;
    char buf[255];
    olsRet_t ret = OLS_RET_OK;

    memset(buf, '\0', sizeof(buf));

    if(tlv_value == NULL )
    {
        LLDPAD_ERR("NULL VALUE DETECTED FOR %s",__func__ );
            return OLS_RET_ERROR;
    }

    for (i = 0; i < 2*len; i+=2)
        buf[strlen(buf)] = hex2int(info+i);
    buf[strlen(buf)] =  '\0';

    if(strlen(buf) == 0)
        ret=OLS_RET_ERROR;

    snprintf(tlv_value, MAX_SYS_PORT_DESCRIPTION_LENGTH, "%s", buf);

    return ret;
}

olsRet_t extract_mng_addr(u16 len, char *info, char* managementAddress,char*managementAddressType)
{
    u8 addrlen;
    u8 addrnum;
    u8 iftype;
    u8 oidlen;
    u32 ifnum;
    u32 offset;
    int i;
    char buf[132];
    olsRet_t ret = OLS_RET_OK;

    if(managementAddress == NULL || managementAddressType == NULL)
    {
        LLDPAD_ERR("NULL VALUE DETECTED FOR %s",__func__ );
            return OLS_RET_ERROR;
    }
    if (len < 9 || len > 167) {
       LLDPAD_ERR("Bad Management Address TLV: %*.*s\n",2*len, 2*len, info);
        return OLS_RET_ERROR;
    }
    hexstr2bin(info, (u8 *)&addrlen, sizeof(addrlen));
    hexstr2bin(info+2, (u8 *)&addrnum, sizeof(addrnum));

    switch(addrnum) {
    case MANADDR_IPV4:
        if (addrlen == 5) {  //TODO: need to figure out
            struct in_addr addr;
            hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
            inet_ntop(AF_INET, (void *)&addr, buf,
                  sizeof(buf));
            snprintf(managementAddress, MAX_MGMT_LENGTH, "%s", buf);
            snprintf(managementAddressType, MAX_MGMT_TYPE_LENGTH, "IPV4");
        } else {
            LLDPAD_ERR("Bad IPv4: %*.*s",2*(addrlen-2), 2*(addrlen-2), info+4);
            ret = OLS_RET_ERROR;
        }
        break;
    case MANADDR_IPV6:
        if (addrlen == 17) {//TODO: need to figure out
            struct in6_addr addr;
            hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
            memset(buf, 0, sizeof(buf));
            inet_ntop(AF_INET6, (void *)&addr, buf,
                  sizeof(buf));
           snprintf(managementAddress, MAX_MGMT_LENGTH, "%s", buf);
           snprintf(managementAddressType, MAX_MGMT_TYPE_LENGTH, "IPV6");
        } else {
            /*OLS_LOG_WARN(NULL, OLS_LOG_TYPE_NETCONF,"Bad IPv6: %*.*s\n",
                   2*(addrlen-2), 2*(addrlen-2), info+4);*/
            ret = OLS_RET_ERROR;
        }
        break;
    default:
        LLDPAD_ERR("Network Address Type %d: %*.*s", addrnum,2*(addrlen-1), 2*(addrlen-1), info+4);
        break;
    }

    offset = 2*(1+addrlen);
    hexstr2bin(info+offset, (u8 *)&iftype, sizeof(iftype)); //getting iftype(2bytes) from info
    offset += 2;
    hexstr2bin(info+offset, (u8 *)&ifnum, sizeof(ifnum)); //getting ifnum(8bytes) from info
    offset += 2*sizeof(u32);
    ifnum = ntohl(ifnum);

    switch (iftype) {
    case IFNUM_UNKNOWN:
       //OLS_LOG_WARN(NULL, OLS_LOG_TYPE_NETCONF, "Unknown interface subtype: %d\n", ifnum);
        break;
    case IFNUM_IFINDEX:
       //OLS_LOG_INFO(NULL, OLS_LOG_TYPE_NETCONF, "Ifindex: %d\n", ifnum);
        break;
    case IFNUM_SYS_PORT_NUM:
       //OLS_LOG_INFO(NULL, OLS_LOG_TYPE_NETCONF, "System port number: %d\n", ifnum);
        break;
    default:
       //OLS_LOG_INFO(NULL, OLS_LOG_TYPE_NETCONF, "Bad interface numbering subtype: %d\n", ifnum);
        break;
    }

    //TODO:: needs to figure out about OID
    hexstr2bin(info+offset, (u8 *)&oidlen, sizeof(oidlen));
    offset += 2;

    if (oidlen && oidlen <= 128) {
        memset(buf, 0, sizeof(buf));
        if (hexstr2bin(info+offset, (u8 *)&buf, oidlen))
           {
        //Do Nothing

        }
        else {
            printf("\tOID: 0.");
            for (i = 0; i < oidlen; ++i) {
                printf("%d", buf[i]);
                if (i != (oidlen - 1));
                    printf(".");
            }
            printf("\n");
        }
    } else if (oidlen > 128) {  //TODO:: need to figure out about OID length
    }

    return ret;
}

olsRet_t extract_ttl( char *info)
{
    u16 ttl;
    olsRet_t ret=OLS_RET_OK;

    hexstr2bin(info, (u8 *)&ttl, sizeof(ttl));
    ttl = ntohs(ttl);
    return ret;

}

void replacecharOccurance(char * neighborText, char delim, char* delim_string)
{
    int i = 0, j = 0, k = 0;
       char neighbor[1024] = {0};
       while(neighborText[i] != '\0')
       {

           if(neighborText[i] == delim)
           {
               for(k=0;k<strlen(delim_string);k++,j++)
                   neighbor[j] = delim_string[k];

               i++;
               continue;
           }
           neighbor[j] = neighborText[i];
           i++;j++;
       }

    strcpy(neighborText,neighbor);
    LLDPAD_DBG("%s : neighborText=%s neighbor=%s\n\n\n",__func__,neighborText,  neighbor);

}

void addNotificationText(char* var, char* tlvName, char* tlvValue)
{
    char Value[1024] = {0};
    if(tlvValue != NULL)
    {
        strncpy(Value,tlvValue,strlen(tlvValue));
        replacecharOccurance(Value, ':', "%3A");
        replacecharOccurance(Value, ',', "%2C");
    }

    if(strlen(var))
    {
            sprintf(var+strlen(var), ",%s:%s", tlvName, Value);
    }
    else
            sprintf(var, "%s:%s", tlvName, Value);
    LLDPAD_DBG("%s : text=%s, name=%s, value=%s %s\n",__func__, var, tlvName, tlvValue, Value);

}

void initNotification(void)
{
    int parameter = -1;
    pthread_mutex_init(&m_notificationListMutex, NULL);
    pthread_mutex_init(&m_neighborDeleteMutex, NULL);
    pthread_cond_init(&m_cond, NULL);
    pthread_create(&notificationServiceThreadId, NULL, processNotification, (void*)&parameter);
    NotificationMessageSender(NBI_NOTIFICATION_SRV_ADDR, NBI_NOTIFICATION_SRV_PORT);
}

void lockNotificationList(void)
{
    pthread_mutex_lock(&m_notificationListMutex);
}

void unlockNotificationList(void)
{
    pthread_mutex_unlock(&m_notificationListMutex);
}

void lockNeighborDelete(void)
{
    pthread_mutex_lock(&m_neighborDeleteMutex);
}

void unlockNeighborDelete(void)
{
    pthread_mutex_unlock(&m_neighborDeleteMutex);
}

void NotificationWait(void)
{
    pthread_cond_wait(&m_cond, &m_notificationListMutex);
}

void pollNotificationListToSend(void)
{
    struct NotificationMessageQueue *message = NULL;
    struct NotificationMessageQueue *cashed = NULL;

    lockNotificationList();

    for(message=notificationList; message; message=message->next)
    {
        cashed = malloc(sizeof(struct NotificationMessageQueue));
        if(cashed)
        {
			memset(cashed, 0 , sizeof(struct NotificationMessageQueue));
			memcpy(&cashed->message, &message->message, sizeof(cashed->message));
			cashed->next = NULL;
			if(notificationListCashed)
				cashed->next = notificationListCashed;
			notificationListCashed = cashed;
        }
    }
    freeNotificationList(notificationList);
    notificationList = NULL;
    message = NULL;

    unlockNotificationList();

    //Send the notifications
    for(cashed=notificationListCashed; cashed; cashed=cashed->next)
    {
        LLDPAD_DBG("%s : text=%s, name=%s\n", __func__, cashed->message.content.text, cashed->message.content.name);
        sendNotificationToServer(cashed->message);
    }
    freeNotificationList(notificationListCashed);
    cashed = NULL;
    notificationListCashed = NULL;
}
void* processNotification(void* s)
{
    while(running)
    {
        pollNotificationListToSend();
        usleep(50000); //wait for 50 ms
    }
    return 0;
}

olsRet_t backup_tlv(struct unpacked_tlv *backup, struct unpacked_tlv *tlv)
{
    backup->type = tlv->type;
    backup->length = tlv->length;
    if(backup->info == NULL)
    {
        backup->info = (u8 *)malloc(tlv->length);
        memset(backup->info, 0, tlv->length);
        if(backup->info)
            memcpy((void *)backup->info, (void *)tlv->info, tlv->length);
        else
        {
            LLDPAD_INFO("malloc to backup tlv failed\n");
            return OLS_RET_ERROR;
        }

    }
    else
        memcpy((void *)backup->info, (void *)tlv->info, tlv->length);

    return OLS_RET_OK;
}

void free_tlv(struct unpacked_tlv *tlv)
{
    if(tlv->info != NULL)
    {
        free(tlv->info);
        tlv->info = NULL;
    }
    free(tlv);
    tlv = NULL;
}

void free_backup_tlvs(struct neighbor *neighbor)
{
    if(neighbor->oldtlvs.chassis != NULL)
        free_tlv(neighbor->oldtlvs.chassis);
    if(neighbor->oldtlvs.mgmtadd != NULL)
        free_tlv(neighbor->oldtlvs.mgmtadd);
    if(neighbor->oldtlvs.portdesc != NULL)
        free_tlv(neighbor->oldtlvs.portdesc);
    if(neighbor->oldtlvs.portid != NULL)
        free_tlv(neighbor->oldtlvs.portid);
    if(neighbor->oldtlvs.syscap != NULL)
        free_tlv(neighbor->oldtlvs.syscap);
    if(neighbor->oldtlvs.sysdesc != NULL)
        free_tlv(neighbor->oldtlvs.sysdesc);
    if(neighbor->oldtlvs.sysname != NULL)
        free_tlv(neighbor->oldtlvs.sysname);
    if(neighbor->oldtlvs.ttl != NULL)
        free_tlv(neighbor->oldtlvs.ttl);
}

olsRet_t create_backup_tlvs(struct neighbor *neighbor)
{
    //Allocate memory to hold previous info.
    if(neighbor->oldtlvs.chassis == NULL)
        neighbor->oldtlvs.chassis = create_tlv();
    if(neighbor->oldtlvs.portid == NULL)
        neighbor->oldtlvs.portid = create_tlv();
    if(neighbor->oldtlvs.mgmtadd == NULL)
        neighbor->oldtlvs.mgmtadd = create_tlv();
    if(neighbor->oldtlvs.portdesc == NULL)
        neighbor->oldtlvs.portdesc = create_tlv();
    if(neighbor->oldtlvs.syscap == NULL)
        neighbor->oldtlvs.syscap = create_tlv();
    if(neighbor->oldtlvs.sysdesc == NULL)
        neighbor->oldtlvs.sysdesc = create_tlv();
    if(neighbor->oldtlvs.sysname == NULL)
        neighbor->oldtlvs.sysname = create_tlv();
    if(neighbor->oldtlvs.ttl == NULL)
        neighbor->oldtlvs.ttl = create_tlv();

    if(neighbor->oldtlvs.chassis == NULL || neighbor->oldtlvs.portid == NULL || neighbor->oldtlvs.mgmtadd == NULL ||
       neighbor->oldtlvs.portdesc == NULL || neighbor->oldtlvs.syscap == NULL || neighbor->oldtlvs.sysname == NULL ||
       neighbor->oldtlvs.sysdesc == NULL || neighbor->oldtlvs.ttl == NULL)
        return OLS_RET_ERROR;

    return OLS_RET_OK;
}

void appendReservedTlvs(struct neighbor *neighbor, u8 tlvType, u16 *offset)
{
    //This code is to add the age and last-update tlv
    u64 currentTime;
    struct unpacked_tlv *tlv = create_tlv();

    if(tlvType == 125)
        currentTime = neighbor->age;
    if(tlvType == 126)
        currentTime = (unsigned)neighbor->lastUpdate;

    if(tlv)
    {
        tlv->type = tlvType;
        tlv->length=sizeof(s64);
        tlv->info = malloc(sizeof(s64));
        if(tlv->info)
        {
            memcpy((void *)tlv->info, (void *)&currentTime, tlv->length);
            struct  packed_tlv *ptlv =  NULL;
            ptlv = pack_tlv(tlv);
            if(ptlv)
            {
                memcpy(&neighbor->tlvs[(*offset)], ptlv->tlv, ptlv->size);
                neighbor->len += ptlv->size;
                (*offset) +=  ptlv->size;
                free(ptlv->tlv);
                ptlv->tlv = NULL;
                free(ptlv);
                ptlv = NULL;
            }
            free(tlv->info);
            tlv->info = NULL;
        }
        free(tlv);
        tlv = NULL;
    }
}

void freeNotificationList(struct NotificationMessageQueue *head)
{
	struct NotificationMessageQueue *tmp;
	while(head != NULL)
	{
		tmp = head;
		head = head->next;
		free(tmp);
	}
}
