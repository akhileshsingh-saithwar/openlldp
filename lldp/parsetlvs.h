#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include "messages.h"
#include "lldp.h"
#include "lldp_util.h"

/* IEEE 802.3AB Clause 9.5.2: Chassis subtypes */
#define CHASSIS_ID_RESERVED	     0
#define CHASSIS_ID_CHASSIS_COMPONENT 1
#define CHASSIS_ID_INTERFACE_ALIAS   2
#define CHASSIS_ID_PORT_COMPONENT    3
#define CHASSIS_ID_MAC_ADDRESS       4
#define CHASSIS_ID_NETWORK_ADDRESS   5
#define CHASSIS_ID_INTERFACE_NAME    6
#define CHASSIS_ID_LOCALLY_ASSIGNED  7
#define CHASSIS_ID_INVALID(t)	(((t) == 0) || ((t) > 7))


/* IEEE 802.3AB Clause 9.5.3: Port subtype */
#define PORT_ID_RESERVED	 0
#define PORT_ID_INTERFACE_ALIAS  1
#define PORT_ID_PORT_COMPONENT   2
#define PORT_ID_MAC_ADDRESS      3
#define PORT_ID_NETWORK_ADDRESS  4
#define PORT_ID_INTERFACE_NAME   5
#define PORT_ID_AGENT_CIRCUIT_ID 6
#define PORT_ID_LOCALLY_ASSIGNED 7
#define PORT_ID_INVALID(t)	(((t) == 0) || ((t) > 7))

#define MAX_CHASSIS_ID_LENGTH 256
#define MAX_PORT_ID_LENGTH 256
#define IPV4_LENGTH 6
#define IPV6_LENGTH 18
#define CUSTOM_TLV_ID  127


#define MAX_CHASIS_ID_TYPE_LENGTH 63
#define MAX_PORT_ID_TYPE_LENGTH 63
#define MAX_SYS_PORT_DESCRIPTION_LENGTH 255
#define MAX_MGMT_LENGTH 255
#define MAX_MGMT_TYPE_LENGTH 63


#define CHASSIS_ID_TLV          1
#define PORT_ID_TLV             2
#define TIME_TO_LIVE_TLV        3
#define PORT_DESCRIPTION_TLV	4
#define SYSTEM_NAME_TLV         5
#define SYSTEM_DESCRIPTION_TLV	6
#define SYSTEM_CAPABILITIES_TLV	7
#define MANAGEMENT_ADDRESS_TLV	8
#define ORG_SPECIFIC_TLV        127
#define END_OF_LLDPDU_TLV       0
#define INVALID_TLVID 127
#define CUSTOM_TLV_ID 127
#define CHASSIS_ID_TYPE         9
#define PORT_ID_TYPE            10
#define MANAGEMENT_ADDRESS_TYPE	11

#define IFNUM_UNKNOWN      1
#define IFNUM_IFINDEX      2
#define IFNUM_SYS_PORT_NUM 3

#define MAX_NOTIFICATION_TLV_TYPE 12
#define MAX_TLV_INFO 512

#define TOTAL_CHASSIS_SUBTYPES 8
#define TOTAL_PORT_SUBTYPES 8
#define TOTAL_MANAGEMENT_ADDRESS_SUBTYPES 3
#define TOTOAL_NOTIFICATION_TLVS 12

typedef enum
{
    OLS_RET_OK = 0,
    OLS_RET_ERROR = -1
}olsRet_t;


#define NOTIFICATION_HEADER_TYPE    30

#define CFG_STATE_VALUE_CHANGED_EVT 0x4A
#define NOTIFICATION 0x02
#define NBI_NOTIFICATION_SRV_ADDR "127.0.0.1"
#define NBI_NOTIFICATION_SRV_PORT 4004

typedef struct
{
    unsigned char type;  //NOTIFICATION_HEADER_TYPE
    unsigned char flags;
    unsigned short length;
}NotificationMessageHeader;

typedef struct
{
    unsigned short eventType; //AUTO_CFG, NOTIFICATION, ALARM
    unsigned short eventId;
    char name[64];
    char text[2048];
    unsigned long timecreated;
}NotificationMessageContent;

typedef struct
{
    NotificationMessageHeader header;
    NotificationMessageContent content;
}NotificationMessage;

struct NotificationMessageQueue
{
	NotificationMessage message;
	struct NotificationMessageQueue *next;
};

unsigned long getTickCount();
void convtlvinfo_to_string(int len,char *iinfo,char *oinfo);

void sendLLDPChangeNotification(const char* sysname, char *ifName, u16 neighborId, bool deleteNotification);
void NotificationMessageSender(const char* serverIp, int port);
bool sendNotificationToServer(const NotificationMessage message);

olsRet_t extract_chassis_id(u16 len, char *info,char* chassis_id,char* chassis_id_type);
olsRet_t extract_port_id(u16 len, char *info,char *port_id,char*port_id_type);
olsRet_t extract_string_tlv(u16 len, char *info, char* tlv_value);
olsRet_t extract_mng_addr(u16 len, char *info, char* managementAddress,char*managementAddressType);
olsRet_t extract_ttl( char *info);

void addNotificationText(char* var, char* tlvName, char*tlvValue);
void createNotifications(struct unpacked_tlv *tlv, struct unpacked_tlv *oldtlv, char *NotificationText);
void ttlTimeoutNotification(struct neighbor *neighbor, char* NotificationText);
void deleteNotifications(struct neighbor *neighbor, char* NotificationText);
void* processNotification(void* s);
void initNotification(void);
void lockNotificationList(void);
void unlockNotificationList(void);
void lockNeighborDelete(void);
void unlockNeighborDelete(void);
void NotificationWait(void);
void pollNotificationListToSend(void);
olsRet_t create_backup_tlvs(struct neighbor *neighbor);
olsRet_t backup_tlv(struct unpacked_tlv *backup, struct unpacked_tlv *tlv);
void free_tlv(struct unpacked_tlv *tlv);
void free_backup_tlvs(struct neighbor *neighbor);
void appendReservedTlvs(struct neighbor *neighbor, u8 tlvType, u16 *offset);
void replacecharOccurance(char * neighborText, char delim, char* delim_string);
void freeNotificationList(struct NotificationMessageQueue *head);
