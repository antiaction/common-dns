/*
 * DNS transport host container, contains hostname/port information.
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
 * 13-Aug-2001 : First implementation.
 * 21-Aug-2001 : Renamed.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.dns.transport;

/**
 * DNS transport host container, contains hostname/port information.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSHostPort {

	/** Hostname. */
	private String host;
	/** Hostport. */
	private int port;

	/**
	 * Instantiate and initialize a <CODE>HostPort</CODE> object.
	 */
	public DNSHostPort(String host, int port) {
		this.host = host;
		this.port = port;
	}

	/**
	 * Get hostname.
	 * @return hostname.
	 */
	public String getHost() {
		return host;
	}

	/**
	 * Get hostport.
	 * @return hostport.
	 */
	public int getPort() {
		return port;
	}

}
