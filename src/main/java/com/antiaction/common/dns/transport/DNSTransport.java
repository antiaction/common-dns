/*
 * DNS message transport interface, abstract class for DNS packet transports.
 * Copyright (C) 2000, 2001  Nicholas Clarke
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

/*
 * History:
 *
 * 18-Aug-2001 : First implemenatation. Transfered methods/javadoc from DNSSocket.
 * 19-Aug-2001 : Added extends Iterator. To anticipate Datagram usage.
 * 20-Aug-2001 : Removed Iterator interface.
 *             : Moved Connect, Disconnect, sendMessage and receiveMessage to another interface.
 * 22-Aug-2001 : getConnector method added.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.common.dns.transport;

/**
 * DNS message transport interface, abstract class for DNS packet transports.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public interface DNSTransport {

	/**
	 * Set the connection timeout.
	 * @param timeout in milliseconds.
	 */
	public void setTimeout(int timeout);

	/**
	 * Get the connection timeout.
	 * @return timeout in milliseconds.
	 */
	public int getTimeout();

	/**
	 * Add a host to the pool of servers to attempt connection with.
	 * @param host destination host name.
	 * @param port destination port.
	 */
	public void addHost(String host, int port);

	/**
	 * Returns a connector object used to communicate with the contained servers.
	 * @return a connector object used to communicate with the contained servers.
	 */
	public DNSConnector getConnector();

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString();

}
