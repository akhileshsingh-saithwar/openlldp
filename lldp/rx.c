/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2012 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  open-lldp Mailing List <lldp-devel@open-lldp.org>

*******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "ports.h"
#include "l2_packet.h"
#include "states.h"
#include "mibdata.h"
#include "messages.h"
#include "lldp.h"
#include "lldpad.h"
#include "lldp_mod.h"
#include "clif_msgs.h"
#include "lldp_mand.h"
#include "lldp_tlv.h"
#include "agent.h"
#include "parsetlvs.h"

u8 tlvs[2048];
int size = 0;

void rxInitializeLLDP(struct port *port, struct lldp_agent *agent)
{
	agent->rx.rcvFrame = false;
	agent->rx.badFrame = false;
	agent->rx.tooManyNghbrs = false;
	agent->rx.rxInfoAge = false;
	if (agent->rx.framein) {
		free(agent->rx.framein);
		agent->rx.framein = NULL;
	}
	agent->rx.sizein = 0;

	mibDeleteObjects(port, agent);
	return;
}

void rxReceiveClientFrame(const char *ifname, const u8 *buf, size_t len)
{
	struct port * newport;
	struct lldp_agent *agent;
	u8  frame_error = 0;
	struct l2_ethhdr *hdr;
	struct l2_ethhdr example_hdr,*ex;

	/* Drop and ignore zero length frames */
	if (!len)
		return;


	for (newport = porthead; newport; newport = newport->next) {
		if (!strcmp(ifname, newport->ifname))
			break;
	}
	if(!newport)
		return;

	/* walk through the list of agents for this interface and see if we
	 * can find a matching agent */
	LIST_FOREACH(agent, &newport->agent_head, entry) {

		ex = &example_hdr;
		ex->h_proto = htons(ETH_P_LLDP);
		hdr = (struct l2_ethhdr *)buf;

		if (hdr->h_proto != example_hdr.h_proto) {
			LLDPAD_INFO("ERROR Ethertype not LLDP ethertype but ethertype "
				"'%x' in incoming frame.\n", htons(hdr->h_proto));
			frame_error++;
			return;
		}

        break;
	}

	if (agent == NULL)
	{
        LLDPAD_ERR("[%s]:%s Agent not found.\n", __FILE__,__func__);
		return;
	}

	if (agent->adminStatus == disabled || agent->adminStatus == enabledTxOnly)
		return;

	if(agent->rx.sizein == 0  || (memcmp(agent->rx.srcMac, hdr->h_source, ETH_ALEN) != 0) )
	{
		memcpy(agent->rx.srcMac, hdr->h_source, ETH_ALEN);
	}

	if (agent->rx.framein)
		free(agent->rx.framein);

	agent->rx.sizein = (u16)len;
	agent->rx.framein = (u8 *)malloc(len);

	if (agent->rx.framein == NULL) {
		LLDPAD_DBG("ERROR - could not allocate memory for rx'ed frame\n");
		return;
	}

	memcpy(agent->rx.framein, buf, len);

	if (!frame_error) {
		agent->stats.statsFramesInTotal++;
		agent->rx.rcvFrame = 1;
	}

	run_rx_sm(newport, agent);
}

void rxReceiveFrame(void *ctx, UNUSED int ifindex, const u8 *buf, size_t len)
{
	struct port * port;
	struct lldp_agent *agent;
	u8  frame_error = 0;
	struct l2_ethhdr *hdr;
	struct l2_ethhdr example_hdr,*ex;

	/* Drop and ignore zero length frames */
	if (!len)
		return;

	port = (struct port *)ctx;

	/* walk through the list of agents for this interface and see if we
	 * can find a matching agent */
	LIST_FOREACH(agent, &port->agent_head, entry) {

		ex = &example_hdr;
		memcpy(ex->h_dest, agent->mac_addr, ETH_ALEN);
		ex->h_proto = htons(ETH_P_LLDP);
		hdr = (struct l2_ethhdr *)buf;

		if (hdr->h_proto != example_hdr.h_proto) {
			LLDPAD_INFO("ERROR Ethertype not LLDP ethertype but ethertype "
				"'%x' in incoming frame.\n", htons(hdr->h_proto));
			frame_error++;
			return;
		}

		if ((!memcmp(hdr->h_dest,ex->h_dest, ETH_ALEN)))
			break;
	}

	if (agent == NULL)
		return;

	if (agent->adminStatus == disabled || agent->adminStatus == enabledTxOnly)
		return;

	if (agent->rx.framein)
		free(agent->rx.framein);

	agent->rx.sizein = (u16)len;
	agent->rx.framein = (u8 *)malloc(len);

	if (agent->rx.framein == NULL) {
		LLDPAD_DBG("ERROR - could not allocate memory for rx'ed frame\n");
		return;
	}
	memcpy(agent->rx.framein, buf, len);

	if (!frame_error) {
		agent->stats.statsFramesInTotal++;
		agent->rx.rcvFrame = 1;
	}

	run_rx_sm(port, agent);
}

void rxProcessFrame(struct port *port, struct lldp_agent *agent)
{
	u16 tlv_cnt = 0;
	u8  tlv_type = 0;
	u16 tlv_length = 0;
	u16 tlv_offset = 0;
	u16 offset_before_endlldpdu = 0;
	u16 *tlv_head_ptr = NULL;
	u8  frame_error = 0;
	bool msap_compare_1 = false;
	bool msap_compare_2 = false;
	bool good_neighbor  = false;
	bool tlv_stored     = false;
	bool reassignNeighborId = false;
	int err;
	struct lldp_module *np;
	struct neighbor *neighbor;
	u8 mac[ETH_ALEN];
    char NotificationText[1024] = {0};
    char deleteNotificationText[1024] = {0};

	assert(agent->rx.framein && agent->rx.sizein);
	agent->lldpdu = 0;
	agent->rx.dupTlvs = 0;

	agent->rx.dcbx_st = 0;
	agent->rx.manifest = (rxmanifest *)malloc(sizeof(rxmanifest));
	if (agent->rx.manifest == NULL) {
		LLDPAD_DBG("ERROR - could not allocate memory for receive "
			"manifest\n");
		return;
	}

	//Lock the deletion of neighbor
	lockNeighborDelete();

	memset(agent->rx.manifest, 0, sizeof(rxmanifest));
	get_remote_peer_mac_addr(port, agent);
	tlv_offset = sizeof(struct l2_ethhdr);  /* Points to 1st TLV */

	memcpy(&mac, &agent->rx.framein[ETH_ALEN], ETH_ALEN);
	neighbor = neighbor_find_by_mac(agent, &mac);
	if(neighbor == NULL)	//This is new neighbor, not previously received or timeout.
	{
		if(agent->neighborCount < MAX_NEIGHBORS)
		{
			/* if not, create one and initialize it */
			LLDPAD_DBG("%s: creating new neighbor on agent %p.\n", __func__, agent);
			neighbor = malloc(sizeof(struct neighbor));
			if (neighbor != NULL) {
				memset(neighbor, 0, sizeof(struct neighbor));

				if(create_backup_tlvs(neighbor) != OLS_RET_OK)
				{
					LLDPAD_ERR("%s: create_backup_tlvs failed on neighbor %p.\n", __func__, neighbor);
					free_backup_tlvs(neighbor);
					free(neighbor);
					unlockNeighborDelete();
					return;
				}

				neighbor->next = NULL;
				neighbor->neighborId = 0;
				memcpy(&neighbor->mac_addr, &mac, ETH_ALEN);

				if(agent->neighborhead)
				{
					for(struct neighbor *p=agent->neighborhead; p; p=p->next)
					{
						if (p->next == NULL)
						{
							p->next = neighbor;		//Add neighbor at tail;
							break;
						}
					}
				}
				else
					agent->neighborhead = neighbor;

				neighbor->age = time(NULL);
				agent->neighborCount += 1;
				addNotificationText(NotificationText, "age", "0");

				reassignNeighborId = true;
			}
			else{
				LLDPAD_DBG("%s: creation of new neighbor failed !.\n", __func__);
				unlockNeighborDelete();
				return;
			}
		}
	}
	memset(neighbor->tlvs_presence, 0, sizeof(neighbor->tlvs_presence));
	memset(neighbor->ifname, 0, sizeof(neighbor->ifname));
	memcpy(neighbor->ifname, port->ifname, sizeof(neighbor->ifname));
	//Reassign neighbor id
	if(reassignNeighborId == true)
	{
		u16 id = 1;
		for(struct neighbor *p=agent->neighborhead; p; p=p->next)
		{
			p->neighborId = id++;
		}
	}

	do {
		tlv_cnt++;
		if (tlv_offset > agent->rx.sizein) {
			LLDPAD_INFO("ERROR: Frame overrun!\n");
			frame_error++;
			goto out;
		}

		tlv_head_ptr = (u16 *)&agent->rx.framein[tlv_offset];
		tlv_length = htons(*tlv_head_ptr) & 0x01FF;
		tlv_type = (u8)(htons(*tlv_head_ptr) >> 9);

		if (tlv_cnt <= 3) {
			if (tlv_cnt != tlv_type) {
				LLDPAD_INFO("ERROR:TLV missing or TLVs out "
					"of order!\n");
				frame_error++;
				goto out;
			}
		}

		if (tlv_cnt > 3) {
			if ((tlv_type == 1) || (tlv_type == 2) ||
				(tlv_type == 3)) {
				LLDPAD_INFO("ERROR: Extra Type 1 Type2, or "
					"Type 3 TLV!\n");
				frame_error++;
				goto out;
			}
		}

		if ((tlv_type == TIME_TO_LIVE_TLV) && (tlv_length != 2)) {
			LLDPAD_INFO("ERROR:TTL TLV validation error! \n");
			frame_error++;
			goto out;
		}

		u16 tmp_offset = tlv_offset + tlv_length;
		if (tmp_offset > agent->rx.sizein) {
			LLDPAD_INFO("ERROR: Frame overflow error: offset=%d, "
				"rx.size=%d \n", tmp_offset, agent->rx.sizein);
			frame_error++;
			goto out;
		}

		u8 *info = (u8 *)&agent->rx.framein[tlv_offset +
					sizeof(*tlv_head_ptr)];

		struct unpacked_tlv *tlv = create_tlv();

		if (!tlv) {
			LLDPAD_DBG("ERROR: Failed to malloc space for "
				"incoming TLV. \n");
			goto out;
		}

		if ((tlv_length == 0) && (tlv->type != TYPE_0)) {
				LLDPAD_INFO("ERROR: tlv_length == 0\n");
				free_unpkd_tlv(tlv);
				goto out;
		}
		tlv->type = tlv_type;
		tlv->length = tlv_length;
		tlv->info = (u8 *)malloc(tlv_length);
		if (tlv->info) {
			memset(tlv->info,0, tlv_length);
			memcpy(tlv->info, info, tlv_length);
		} else {
			LLDPAD_DBG("ERROR: Failed to malloc space for incoming "
				"TLV info \n");
			free_unpkd_tlv(tlv);
			goto out;
		}

		/* Validate the TLV */
		/* Get MSAP info */
        if (tlv->type == TYPE_0) { /* End of LLDPDU */
            agent->lldpdu |= RCVD_LLDP_TLV_TYPE0;
            tlv_stored = true;
            offset_before_endlldpdu = tlv_offset;
        }
		if (tlv->type == TYPE_1) { /* chassis ID */
			if (agent->lldpdu & RCVD_LLDP_TLV_TYPE1) {
				LLDPAD_INFO("Received multiple Chassis ID"
					    "TLVs in this LLDPDU\n");
				frame_error++;
				free_unpkd_tlv(tlv);
				goto out;
			} else {
				agent->lldpdu |= RCVD_LLDP_TLV_TYPE1;
				agent->rx.manifest->chassis = tlv;
				createNotifications(agent->rx.manifest->chassis, neighbor->oldtlvs.chassis, NotificationText);
				backup_tlv(neighbor->oldtlvs.chassis, agent->rx.manifest->chassis);
				tlv_stored = true;
				neighbor->tlvs_presence[CHASSIS_ID_TLV] = true;
			}
		}
		if (tlv->type == TYPE_2) { /* port ID */
			if (agent->lldpdu & RCVD_LLDP_TLV_TYPE2) {
				LLDPAD_INFO("Received multiple Port ID "
					"TLVs in this LLDPDU\n");
				frame_error++;
				free_unpkd_tlv(tlv);
				goto out;
			} else {
				agent->lldpdu |= RCVD_LLDP_TLV_TYPE2;
				agent->rx.manifest->portid = tlv;
				createNotifications(agent->rx.manifest->portid, neighbor->oldtlvs.portid, NotificationText);
				backup_tlv(neighbor->oldtlvs.portid, agent->rx.manifest->portid);
				tlv_stored = true;
				neighbor->tlvs_presence[PORT_ID_TLV] = true;
			}

		}
		if (tlv->type == TYPE_3) { /* time to live */
			if (agent->lldpdu & RCVD_LLDP_TLV_TYPE3) {
				LLDPAD_INFO("Received multiple TTL TLVs in this"
					" LLDPDU\n");
				frame_error++;
				free_unpkd_tlv(tlv);
				goto out;
			} else {
				agent->lldpdu |= RCVD_LLDP_TLV_TYPE3;
				agent->rx.manifest->ttl = tlv;
				backup_tlv(neighbor->oldtlvs.ttl, agent->rx.manifest->ttl);
				tlv_stored = true;
				neighbor->tlvs_presence[TIME_TO_LIVE_TLV] = true;
			}
			neighbor->rxTTL = ntohs(*(u16 *)tlv->info);
			neighbor->lastrxTTL = neighbor->rxTTL;
		}
		if (tlv->type == TYPE_4) { /* port description */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE4;
			agent->rx.manifest->portdesc = tlv;
			createNotifications(agent->rx.manifest->portdesc, neighbor->oldtlvs.portdesc, NotificationText);
			backup_tlv(neighbor->oldtlvs.portdesc, agent->rx.manifest->portdesc);
			tlv_stored = true;
			neighbor->tlvs_presence[PORT_DESCRIPTION_TLV] = true;
		}
		if (tlv->type == TYPE_5) { /* system name */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE5;
			agent->rx.manifest->sysname = tlv;
			createNotifications(agent->rx.manifest->sysname, neighbor->oldtlvs.sysname, NotificationText);
			backup_tlv(neighbor->oldtlvs.sysname, agent->rx.manifest->sysname);
			tlv_stored = true;
			neighbor->tlvs_presence[SYSTEM_NAME_TLV] = true;
		}
		if (tlv->type == TYPE_6) { /* system description */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE6;
			agent->rx.manifest->sysdesc = tlv;
			createNotifications(agent->rx.manifest->sysdesc, neighbor->oldtlvs.sysdesc, NotificationText);
			backup_tlv(neighbor->oldtlvs.sysdesc, agent->rx.manifest->sysdesc);
			tlv_stored = true;
			neighbor->tlvs_presence[SYSTEM_DESCRIPTION_TLV] = true;
		}
		if (tlv->type == TYPE_7) { /* system capabilities */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE7;
			agent->rx.manifest->syscap = tlv;
			backup_tlv(neighbor->oldtlvs.syscap, agent->rx.manifest->syscap);
			tlv_stored = true;
		}
		if (tlv->type == TYPE_8) { /* mgmt address */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE8;
			agent->rx.manifest->mgmtadd = tlv;
			createNotifications(agent->rx.manifest->mgmtadd, neighbor->oldtlvs.mgmtadd, NotificationText);
			backup_tlv(neighbor->oldtlvs.mgmtadd, agent->rx.manifest->mgmtadd);
			tlv_stored = true;
			neighbor->tlvs_presence[MANAGEMENT_ADDRESS_TLV] = true;
		}

		/* rx per lldp module */
		LIST_FOREACH(np, &lldp_head, lldp) {
			if (!np->ops || !np->ops->lldp_mod_rchange)
				continue;

			err = np->ops->lldp_mod_rchange(port, agent, tlv);

			if (!err)
				tlv_stored = true;
			else if (err == TLV_ERR) {
				frame_error++;
				free_unpkd_tlv(tlv);
				goto out;
			}
		}

		if (!tlv_stored) {
			LLDPAD_INFO("%s: allocated TLV %u was not stored! %p\n", __func__, tlv->type, tlv);
			tlv = free_unpkd_tlv(tlv);
			agent->stats.statsTLVsUnrecognizedTotal++;
		}
        agent->stats.statsTLVsAccepted++; // To maintain Accepted TLVs per interface
		tlv = NULL;
		tlv_stored = false;
		tlv_offset += sizeof(*tlv_head_ptr) + tlv_length;

	} while(tlv_type != 0);

	//If code reaches here, a valid frame is received.
	//Copy the frame to neighbor->tlvs except END LLDPDU
	neighbor->lastUpdate = time(NULL);
	u16 tlvs_offet = offset_before_endlldpdu - sizeof(struct l2_ethhdr);
	neighbor->len = agent->rx.sizein - sizeof(struct l2_ethhdr);
	memcpy((void *)&neighbor->tlvs,
		   (void *)agent->rx.framein + sizeof(struct l2_ethhdr),
		   tlvs_offet);

	//INSERT AGE AND LAST-UPDATE INFORMATION AS TLV 125 AND 126
	appendReservedTlvs(neighbor, 125, &tlvs_offet);	//125 is assigned to age TLV, insert the tlv
	appendReservedTlvs(neighbor, 126, &tlvs_offet);	//126 is assigned to last update TLV, insert the tlv

	//Copy the ENDLLDPDU to neighbor->tlvs
	memcpy((void *)&neighbor->tlvs[tlvs_offet],
		   (void *)agent->rx.framein + offset_before_endlldpdu,
		   (neighbor->len - tlvs_offet));

	//Add the last-update notification, need to be send every time neighbor is received.
	addNotificationText(NotificationText, "last-update", "0");

	if (agent->rx.framein)
	{
		free(agent->rx.framein);
		agent->rx.framein = NULL;
	}
	deleteNotifications(neighbor, deleteNotificationText);

	if(strlen(NotificationText))
		sendLLDPChangeNotification(NotificationText, port->ifname, neighbor->neighborId,0);
	if(strlen(deleteNotificationText))
		sendLLDPChangeNotification(deleteNotificationText, port->ifname, neighbor->neighborId, 1); //Send delete notification

out:
	if (frame_error) {
		/* discard the frame because of errors. */
		agent->stats.statsFramesDiscardedTotal++;
		agent->stats.statsFramesInErrorsTotal++;
		agent->rx.badFrame = true;
	}

	agent->lldpdu = 0;
	clear_manifest(agent);

	unlockNeighborDelete();

	return;
}

u8 mibDeleteObjects(struct port *port, struct lldp_agent *agent)
{
	struct lldp_module *np;

	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops || !np->ops->lldp_mod_mibdelete)
			continue;
		np->ops->lldp_mod_mibdelete(port, agent);
	}

	/* Clear history */
	agent->msap.length1 = 0;
	if (agent->msap.msap1) {
		free(agent->msap.msap1);
		agent->msap.msap1 = NULL;
	}

	agent->msap.length2 = 0;
	if (agent->msap.msap2) {
		free(agent->msap.msap2);
		agent->msap.msap2 = NULL;
	}
	return 0;
}

void run_rx_sm(struct port *port, struct lldp_agent *agent)
{
	set_rx_state(port, agent);
	do {
		switch(agent->rx.state) {
		case LLDP_WAIT_PORT_OPERATIONAL:
			break;
		case DELETE_AGED_INFO:
			process_delete_aged_info(port, agent);
			break;
		case RX_LLDP_INITIALIZE:
			process_rx_lldp_initialize(port, agent);
			break;
		case RX_WAIT_FOR_FRAME:
			process_wait_for_frame(agent);
			break;
		case RX_FRAME:
			process_rx_frame(port, agent);
			break;
		case DELETE_INFO:
			process_delete_info(port, agent);
			break;
		case UPDATE_INFO:
			process_update_info(agent);
			break;
		default:
			LLDPAD_DBG("ERROR: The RX State Machine is broken!\n");
		}
	} while (set_rx_state(port, agent) == true);
}

bool set_rx_state(struct port *port, struct lldp_agent *agent)
{
	if ((agent->rx.rxInfoAge == false) && (port->portEnabled == false)) {
		rx_change_state(agent, LLDP_WAIT_PORT_OPERATIONAL);
	}

	switch(agent->rx.state) {
	case LLDP_WAIT_PORT_OPERATIONAL:
		if (agent->rx.rxInfoAge == true) {
			rx_change_state(agent, DELETE_AGED_INFO);
			return true;
		} else if (port->portEnabled == true) {
			rx_change_state(agent, RX_LLDP_INITIALIZE);
			return true;
		}
		return false;
	case DELETE_AGED_INFO:
		rx_change_state(agent, LLDP_WAIT_PORT_OPERATIONAL);
		return true;
	case RX_LLDP_INITIALIZE:
		if ((agent->adminStatus == enabledRxTx) ||
			(agent->adminStatus == enabledRxOnly)) {
			rx_change_state(agent, RX_WAIT_FOR_FRAME);
			return true;
		}
		return false;
	case RX_WAIT_FOR_FRAME:
		if ((agent->adminStatus == disabled) ||
			(agent->adminStatus == enabledTxOnly)) {
			rx_change_state(agent, RX_LLDP_INITIALIZE);
			return true;
		}
		if (agent->rx.rxInfoAge == true) {
			rx_change_state(agent, DELETE_INFO);
			return true;
		} else if (agent->rx.rcvFrame == true) {
			rx_change_state(agent, RX_FRAME);
			return true;
		}
		return false;
	case DELETE_INFO:
		rx_change_state(agent, RX_WAIT_FOR_FRAME);
		return true;
	case RX_FRAME:
		if (agent->rxChanges == true) {
			rx_change_state(agent, UPDATE_INFO);
			return true;
		}
		rx_change_state(agent, RX_WAIT_FOR_FRAME);
		return true;
	case UPDATE_INFO:
		rx_change_state(agent, RX_WAIT_FOR_FRAME);
		return true;
	default:
		LLDPAD_DBG("ERROR: The RX State Machine is broken!\n");
		return false;
	}
}

void process_delete_aged_info(struct port *port, struct lldp_agent *agent)
{
	mibDeleteObjects(port, agent);
	agent->rx.rxInfoAge = false;
	agent->rx.remoteChange = true;
	return;
}

void process_rx_lldp_initialize(struct port *port, struct lldp_agent *agent)
{
	rxInitializeLLDP(port, agent);
	agent->rx.rcvFrame = false;
	return;
}

void process_wait_for_frame(struct lldp_agent *agent)
{
	agent->rx.badFrame  = false;
	agent->rx.rxInfoAge = false;
	return;
}

void process_rx_frame(struct port *port, struct lldp_agent *agent)
{
	agent->rx.remoteChange = false;
	agent->rxChanges = false;
	agent->rx.rcvFrame = false;
	rxProcessFrame(port, agent);
	return;
}

void process_delete_info(struct port *port, struct lldp_agent *agent)
{
	mibDeleteObjects(port, agent);

	if (agent->rx.framein) {
		free(agent->rx.framein);
		agent->rx.framein = NULL;
	}

	agent->rx.sizein = 0;
	agent->rx.remoteChange = true;
	return;
}

void process_update_info(struct lldp_agent *agent)
{
	agent->rx.remoteChange = true;
	return;
}

void update_rx_timers(struct lldp_agent *agent)
{
	struct neighbor *neighbor, *next;
	struct neighbor *parent = NULL;
	bool neighborIdReassign = false;

	for(neighbor=agent->neighborhead; neighbor; neighbor = next)
	{
		next = neighbor->next;
		if(neighbor->rxTTL)
		{
			//----------Send age and last-update notification every second---------
			char updateNotificationText[1024] = {0};
			char tmp[32] = {0};
			u64 age = time(NULL) - neighbor->age;
			sprintf(tmp, "%llu", age);
			addNotificationText(updateNotificationText, "age", tmp);
			memset(tmp, 0, sizeof(tmp));
			s64 lastUpdate = time(NULL) - neighbor->lastUpdate;
			sprintf(tmp, "%lld", lastUpdate);
			addNotificationText(updateNotificationText, "last-update", tmp);
			sendLLDPChangeNotification(updateNotificationText, neighbor->ifname, neighbor->neighborId, 0);
			//------------------------------------------------------------------------

			neighbor->rxTTL--;
			if(neighbor->rxTTL == 0)
			{
				lockNeighborDelete();
				//Check if neighbor->rxTTL is not update by this time with new frame reception.
				if(neighbor->rxTTL)
				{
					unlockNeighborDelete();
					continue;
				}
				//Delete neighbor
				char notificationText[2048] = {0};
				ttlTimeoutNotification(neighbor, notificationText); //prepare notification text to delete neighbor leaves
				char macstring[18];
				mac2str(&neighbor->mac_addr[0], macstring, sizeof(macstring));
				LLDPAD_INFO("%s: Removing neighbor with MAC: %s\n", __func__, macstring);
				if(parent == NULL)
					agent->neighborhead = neighbor->next;
				else if(parent->next == neighbor)
					parent->next = neighbor->next;
				else
					LLDPAD_ERR("***Should not reach here, function: %s*****\n", __func__);
				if(strlen(notificationText))
					sendLLDPChangeNotification(notificationText, neighbor->ifname, neighbor->neighborId, 1);
				free_backup_tlvs(neighbor);
				free(neighbor);
				agent->neighborCount -= 1;
				neighborIdReassign = true;
				agent->rx.rxInfoAge = true;
				agent->stats.statsAgeoutsTotal++;
				unlockNeighborDelete();
				continue;
			}
		}
		parent = neighbor;
	}

	if(neighborIdReassign == true)
	{
		u16 id = 1;
		struct neighbor *p;
		for(p=agent->neighborhead; p; p=p->next)
		{
			p->neighborId = id++;
		}
	}
}

void rx_change_state(struct lldp_agent *agent, u8 newstate)
{
	switch(newstate) {
		case LLDP_WAIT_PORT_OPERATIONAL:
			break;
		case RX_LLDP_INITIALIZE:
			assert((agent->rx.state == LLDP_WAIT_PORT_OPERATIONAL) ||
			       (agent->rx.state == RX_WAIT_FOR_FRAME));
			break;
		case DELETE_AGED_INFO:
			assert(agent->rx.state ==
				LLDP_WAIT_PORT_OPERATIONAL);
			break;
		case RX_WAIT_FOR_FRAME:
			if (!(agent->rx.state == RX_LLDP_INITIALIZE ||
				agent->rx.state == DELETE_INFO ||
				agent->rx.state == UPDATE_INFO ||
				agent->rx.state == RX_FRAME)) {
				assert(agent->rx.state !=
					RX_LLDP_INITIALIZE);
				assert(agent->rx.state != DELETE_INFO);
				assert(agent->rx.state != UPDATE_INFO);
				assert(agent->rx.state != RX_FRAME);
			}
			break;
		case RX_FRAME:
			assert(agent->rx.state == RX_WAIT_FOR_FRAME);
			break;
		case DELETE_INFO:
			if (!(agent->rx.state == RX_WAIT_FOR_FRAME ||
				agent->rx.state == RX_FRAME)) {
				assert(agent->rx.state == RX_WAIT_FOR_FRAME);
				assert(agent->rx.state == RX_FRAME);
			}
			break;
		case UPDATE_INFO:
			assert(agent->rx.state == RX_FRAME);
			break;
		default:
			LLDPAD_DBG("ERROR: The RX State Machine is broken!\n");
	}
	agent->rx.state = newstate;
}

void clear_manifest(struct lldp_agent *agent)
{
	if (agent->rx.manifest->mgmtadd)
		agent->rx.manifest->mgmtadd =
			free_unpkd_tlv(agent->rx.manifest->mgmtadd);
	if (agent->rx.manifest->syscap)
		agent->rx.manifest->syscap =
			free_unpkd_tlv(agent->rx.manifest->syscap);
	if (agent->rx.manifest->sysdesc)
		agent->rx.manifest->sysdesc =
			free_unpkd_tlv(agent->rx.manifest->sysdesc);
	if (agent->rx.manifest->sysname)
		agent->rx.manifest->sysname =
			free_unpkd_tlv(agent->rx.manifest->sysname);
	if (agent->rx.manifest->portdesc)
		agent->rx.manifest->portdesc =
			free_unpkd_tlv(agent->rx.manifest->portdesc);
	if (agent->rx.manifest->ttl)
		agent->rx.manifest->ttl =
			free_unpkd_tlv(agent->rx.manifest->ttl);
	if (agent->rx.manifest->portid)
		agent->rx.manifest->portid =
			free_unpkd_tlv(agent->rx.manifest->portid);
	if (agent->rx.manifest->chassis)
		agent->rx.manifest->chassis =
			free_unpkd_tlv(agent->rx.manifest->chassis);
	free(agent->rx.manifest);
	agent->rx.manifest = NULL;
}
