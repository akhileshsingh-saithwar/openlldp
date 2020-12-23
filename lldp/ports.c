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
#include <string.h>
#include "states.h"
#include "lldp_tlv.h"
#include "lldp_rtnl.h"
#include "ports.h"
#include "l2_packet.h"
#include "libconfig.h"
#include "lldp_mand_clif.h"
#include "lldp.h"
#include "config.h"
#include "messages.h"
#include "lldpad_status.h"
#include "lldp_rtnl.h"
#include "lldp_dcbx_nl.h"
#include "agent.h"
#include "lldp_dcbx_nl.h"
#include "lldp_util.h"

struct port *porthead = NULL; /* port Head pointer */

static struct customIndexRecord cir[32];

void agent_receive(void *, const u8 *, const u8 *, size_t);

/* Port routines used for command processing -- return cmd_xxx codes */

int get_lldp_agent_statistics(const char *ifname, struct agentstats *stats, int type)
{
	struct lldp_agent *agent;

	agent = lldp_agent_find_by_type(ifname, type);
	if (!agent)
		return cmd_agent_not_found;

	memcpy((void *)stats, (void *)&agent->stats, sizeof(struct agentstats));

	return 0;
}

int get_local_tlvs(char *ifname, int type, unsigned char *tlvs, int *size)
{
	struct lldp_agent *agent;

	agent = lldp_agent_find_by_type(ifname, type);
	if (!agent)
		return cmd_agent_not_found;

	if (agent->tx.frameout == NULL) {
		*size = 0;
		return cmd_success;
	}

	*size = agent->tx.sizeout - sizeof(struct l2_ethhdr);
	if (*size < 0)
		return cmd_invalid;
	memcpy((void *)tlvs,
	       (void *)agent->tx.frameout + sizeof(struct l2_ethhdr), *size);

	return cmd_success;
}

int get_neighbor_tlvs(char *ifname, int type, unsigned char *tlvs, int *size)
{
	struct lldp_agent *agent;
	struct neighbor *neighbor;

	agent = lldp_agent_find_by_type(ifname, type);
	if (!agent)
		return cmd_agent_not_found;

	for(neighbor=agent->neighborhead; neighbor; neighbor=neighbor->next)
	{
		if(neighbor->len)
		{
			memcpy((void *)tlvs, (void *)neighbor->tlvs, neighbor->len);
			tlvs += neighbor->len;
			*size += neighbor->len;
		}
	}

	return cmd_success;
}

/* Routines used for managing interfaces -- return std C return values */

int get_lldp_agent_admin(const char *ifname, int type)
{
	struct lldp_agent *agent = NULL;

	LLDPAD_DBG("%s: Requested if: %s type: %d.", __func__, ifname, type);

	agent = lldp_agent_find_by_type(ifname, type);

	if (agent == NULL)
		return disabled;

	return agent->adminStatus;
}

void set_lldp_agent_admin(const char *ifname, int type, int admin)
{
	struct port *port;
	struct lldp_agent *agent;
	int ifindex;

	if(!is_custom_port(ifname))
	{
		ifindex = get_ifidx(ifname);
		if(ifindex)
		{
			for (port = porthead; port; port = port->next) {
				if (ifindex == port->ifindex)
					break;
			}
		}
	}
	else
	{
		port = port_find_by_ifname(ifname);
	}

	if (!port)
	{
        LLDPAD_ERR("%s: line: %d, port is null\n", __func__, __LINE__);
		return;
	}

	agent = lldp_agent_find_by_type(port->ifname, type);
	if (!agent)
	{
        LLDPAD_ERR("%s: line: %d, agent is null\n", __func__, __LINE__);
		return;
	}

	/* Set ifname with ifindex reported ifname */
	if (strncmp(port->ifname, ifname, IFNAMSIZ) !=  0)
		memcpy(port->ifname, ifname, IFNAMSIZ);

    LLDPAD_DBG("%s: line: %d,  port->ifname: %s ifname: %s "
               "agent->adminStatus: %d agent address: %p\n", __func__, __LINE__,
               port->ifname, ifname, agent->adminStatus,agent);

	if (agent->adminStatus != admin) {
		agent->adminStatus = admin;
		somethingChangedLocal(port->ifname, type);
		run_tx_sm(port, agent);
		run_rx_sm(port, agent);
	}
}

void set_lldp_port_l3_enable(const char *ifname, int enable)
{
	struct port *port = port_find_by_ifname(ifname);
	struct lldp_agent *agent = NULL;

	if (!port)
		return;

	port->portEnabled = (u8)enable;

	if (!enable) { /* port->adminStatus = disabled; */
		LIST_FOREACH(agent, &port->agent_head, entry) {
			agent->rx.rxInfoAge = false;
		}
	}

	LIST_FOREACH(agent, &port->agent_head, entry) {
		run_tx_sm(port, agent);
		run_rx_sm(port, agent);
	}
}

void set_lldp_port_enable(const char *ifname, int enable)
{
	struct port *port = port_find_by_ifindex(get_ifidx(ifname));
	struct lldp_agent *agent = NULL;

	if (!port)
		return;

	port->portEnabled = (u8)enable;

	if (!enable) { /* port->adminStatus = disabled; */
		LIST_FOREACH(agent, &port->agent_head, entry) {
			agent->rx.rxInfoAge = false;
		}
	}

	LIST_FOREACH(agent, &port->agent_head, entry) {
		run_tx_sm(port, agent);
		run_rx_sm(port, agent);
	}
}

void set_port_oper_delay(const char *ifname)
{
	struct port *port = port_find_by_ifindex(get_ifidx(ifname));

	if (!port)
		return;

	port->dormantDelay = DORMANT_DELAY;

	return;
}

int set_port_hw_resetting(const char *ifname, int resetting)
{
	struct port *port = port_find_by_ifindex(get_ifidx(ifname));

	if (!port)
		return -1;

	port->hw_resetting = (u8)resetting;

	return port->hw_resetting;
}

int get_port_hw_resetting(const char *ifname)
{
	struct port *port = port_find_by_ifindex(get_ifidx(ifname));

	if (port)
		return port->hw_resetting;

	return 0;
}

int reinit_port(const char *ifname)
{
	struct port *port = port_find_by_ifindex(get_ifidx(ifname));
	struct lldp_agent *agent;

	if (!port)
		return -1;

	/* Reset relevant port variables */
	port->hw_resetting = false;
	port->portEnabled = false;
	port->dormantDelay = DORMANT_DELAY;

	LIST_FOREACH(agent, &port->agent_head, entry) {
		/* init TX path */

		/* Reset relevant state variables */
		agent->tx.state  = TX_LLDP_INITIALIZE;
		agent->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
		agent->msap.length1 = 0;
		agent->msap.msap1 = NULL;
		agent->msap.length2 = 0;
		agent->msap.msap2 = NULL;
		agent->lldpdu = false;
		agent->timers.state  = TX_TIMER_BEGIN;

		/* init & enable RX path */
		rxInitializeLLDP(port, agent);

		/* init TX path */
		txInitializeTimers(agent);
		txInitializeLLDP(port, agent);
	}

	return 0;
}

struct port *add_l3_port(const char *ifname)
{
	struct port *newport;

	for (newport = porthead; newport; newport = newport->next)
		if (strcmp(ifname, newport->ifname) == 0)
			return NULL;

    LLDPAD_DBG("%s: creating new port for Interface %s.\n", __func__, ifname);
	newport = malloc(sizeof(*newport));
	if (!newport) {
		LLDPAD_DBG("new port malloc failed\n");
		goto fail;
	}
	memset(newport, 0, sizeof(*newport));

	newport->ifindex = set_custom_ifindex(ifname);
	newport->next = NULL;
    strncpy(newport->ifname, ifname, IFNAMSIZ);
	newport->bond_master = false;
	newport->hw_resetting = false;
	newport->portEnabled = false;
	newport->isCustom = true;

	LIST_INIT(&newport->agent_head);

    newport->l2 = l2_custom_packet_init(newport->ifname, NULL, ETH_P_LLDP,
        rxReceiveClientFrame, newport, 1);

	if (newport->l2 == NULL) {
        LLDPAD_DBG("Failed to open layer 2 access to "
			"ETH_P_LLDP\n");
		goto fail;
	}

	/* init TX path */
	newport->dormantDelay = DORMANT_DELAY;

	/* enable TX path */
	if (porthead)
		newport->next = porthead;

	porthead = newport;
	return newport;

fail:
	if (newport)
		free(newport);
	return NULL;
}

struct port *add_port(int ifindex, const char *ifname)
{
	struct port *newport;

	for (newport = porthead; newport; newport = newport->next)
		if (ifindex == newport->ifindex)
			return NULL;

	newport = malloc(sizeof(*newport));
	if (!newport) {
		LLDPAD_DBG("new port malloc failed\n");
		goto fail;
	}
	memset(newport, 0, sizeof(*newport));
	newport->ifindex = ifindex;
	newport->next = NULL;
	strncpy(newport->ifname, ifname, IFNAMSIZ);

	newport->bond_master = is_bond(ifname);
	/* Initialize relevant port variables */
	newport->hw_resetting = false;
	newport->portEnabled = false;

	LIST_INIT(&newport->agent_head);

	newport->l2 = l2_packet_init(newport->ifname, NULL, ETH_P_LLDP,
		rxReceiveFrame, newport, 1);
	if (newport->l2 == NULL) {
		LLDPAD_DBG("Failed to open register layer 2 access to "
			"ETH_P_LLDP\n");
		goto fail;
	}

	/* init TX path */
	newport->dormantDelay = DORMANT_DELAY;

	/* enable TX path */
	if (porthead)
		newport->next = porthead;

	porthead = newport;
	return newport;

fail:
	if (newport)
		free(newport);
	return NULL;
}

int remove_port(const char *ifname)
{
	int ifindex = get_ifidx(ifname);
	struct port *port;    /* Pointer to port to remove */
	struct port *parent = NULL;  /* Pointer to previous on port stack */
	struct lldp_agent *agent;

	for (port = porthead; port; port = port->next) {
		if (!strncmp(ifname, port->ifname, IFNAMSIZ)) {
			LLDPAD_DBG("In %s: Found port %s\n", __func__,
				   port->ifname);
			break;
		}
		parent = port;
	}
	if (!port) {
		LLDPAD_DBG("%s: port not present\n", __func__);
		return -1;
	}

	LLDPAD_DBG("In %s: Found port %s\n", __func__, port->ifname);

	/* Set linkmode to off */
	set_linkmode(ifindex, port->ifname, 0);

	/* Close down the socket */
	l2_packet_deinit(port->l2);

	port->portEnabled  = false;

	while (!LIST_EMPTY(&port->agent_head)) {
		agent = LIST_FIRST(&port->agent_head);

		/* Re-initialize relevant port variables */
		agent->tx.state = TX_LLDP_INITIALIZE;
		agent->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
		agent->timers.state = TX_TIMER_BEGIN;
		agent->adminStatus  = disabled;
		agent->tx.txTTL = 0;

		/* Remove the tlvs */
		if (agent->msap.msap1) {
			free(agent->msap.msap1);
			agent->msap.msap1 = NULL;
		}

		if (agent->msap.msap2) {
			free(agent->msap.msap2);
			agent->msap.msap2 = NULL;
		}

		if (agent->rx.framein)
			free(agent->rx.framein);

		if (agent->tx.frameout)
			free(agent->tx.frameout);

		LIST_REMOVE(agent, entry);
		free(agent);
	}

	/* Take this port out of the chain */
	if (parent == NULL)
		porthead = port->next;
	else if (parent->next == port) /* Sanity check */
		parent->next = port->next;
	else
		return -1;

	free(port);

	return 0;
}

int remove_l3_port(const char *ifname)
{
	struct port *port;    /* Pointer to port to remove */
	struct port *parent = NULL;  /* Pointer to previous on port stack */
	struct lldp_agent *agent;

	for (port = porthead; port; port = port->next) {
		if (!strncmp(ifname, port->ifname, IFNAMSIZ)) {
            LLDPAD_DBG("%s: Found custom port %s\n", __func__,port->ifname);
			break;
		}
		parent = port;
	}
	if (!port) {
		LLDPAD_DBG("%s: port not present\n", __func__);
		return -1;
	}

	/* Close down the socket */
    l2_custom_packet_deinit(port->l2);

	port->portEnabled  = false;

	while (!LIST_EMPTY(&port->agent_head)) {
		agent = LIST_FIRST(&port->agent_head);

		/* Re-initialize relevant port variables */
		agent->tx.state = TX_LLDP_INITIALIZE;
		agent->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
		agent->timers.state = TX_TIMER_BEGIN;
		agent->adminStatus  = disabled;
		agent->tx.txTTL = 0;

		/* Remove the tlvs */
		if (agent->msap.msap1) {
			free(agent->msap.msap1);
			agent->msap.msap1 = NULL;
		}

		if (agent->msap.msap2) {
			free(agent->msap.msap2);
			agent->msap.msap2 = NULL;
		}

		if (agent->rx.framein)
			free(agent->rx.framein);

		if (agent->tx.frameout)
			free(agent->tx.frameout);

		LIST_REMOVE(agent, entry);
        LLDPAD_DBG("%s: Removing agent: %p for %s\n", __func__, agent,port->ifname);
		free(agent);
	}

	/* Take this port out of the chain */
	if (parent == NULL)
		porthead = port->next;
	else if (parent->next == port) /* Sanity check */
		parent->next = port->next;
	else
		return -1;

    LLDPAD_DBG("%s: Removing port: %p for Interface:%s\n", __func__, port, port->ifname);
	free(port);

	return 0;
}


/*
 * port_needs_shutdown - check if we need send LLDP shutdown frame on this port
 * @port: the port struct
 *
 * Return 1 for yes and 0 for no.
 *
 * No shutdown frame for port that has dcb enabled
 */
int port_needs_shutdown(struct port *port)
{
	return !check_port_dcb_mode(port->ifname);
}

/*
 * Checks if port is custom port. The ports which are created by lldptool are
 * set as custom port.
 */
int is_custom_port(const char *ifname)
{
	struct port *port;
	for (port = porthead; port; port = port->next) {
		if (!strncmp(ifname, port->ifname, IFNAMSIZ)) {
            //LLDPAD_DBG("%s: Found custom port at index %d\n", __func__,port->ifname,port->ifindex);
			return port->isCustom;
		}
	}
	return false;
}

int get_custom_ifindex(const char *ifname)
{
	struct port *port;
	for (port = porthead; port; port = port->next) {
		if (!strncmp(ifname, port->ifname, IFNAMSIZ)) {
            //LLDPAD_DBG("%s: Found custom port at index %d\n", __func__,port->ifname,port->ifindex);
			return port->ifindex;
		}
	}
	return false;
}

int set_custom_ifindex(const char *ifname)
{
	//Check if this port was earlier added, if not assign available index
	bool found = false;
	int index;
	int ifIndex = 0;
	for(index=0; index<MAX_CUSTOM_PORT; index++)
	{
		if(strcmp(cir[index].ifname, ifname) == 0)
		{
			found = true;
            LLDPAD_DBG("%s: Found Interface: %s entry in Custom-Table at index: %d with value:%d\n",
                       __func__,cir[index].ifname, index, cir[index].ifindex);
			ifIndex = cir[index].ifindex;
			break;
		}
	}

	//Interface name not found, add at first available location
	if(!found)
	{
		for(index=0; index<MAX_CUSTOM_PORT; index++)
		{
			if(strcmp(cir[index].ifname, "") == 0)
			{
				strcpy(cir[index].ifname, ifname);
				cir[index].ifindex = CUSTOM_INDEX_BASE + index;
                LLDPAD_DBG("%s: Added Interface: %s entry in Custom-Table at index: %d with value: %d\n",
                           __func__,cir[index].ifname, index, cir[index].ifindex);
				ifIndex = cir[index].ifindex;
				break;
			}
		}
	}

	return ifIndex;
}
