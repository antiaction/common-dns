/*
 * DNS Datagram message transport (UDP).
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
 * 10-May-2000 : Previous version.
 * 13-Aug-2001 : Mess.
 * 17-Aug-2001 : Removed all the contructors with parameters.
 * 18-aug-2001 : Close renamed to Disconnect.
 * 24-Aug-2001 : Implemented DNSTransport interface.
 *             : Moved connection code to inner class.
 *             : Renamed class.
 *
 */

package com.antiaction.common.net.dns.transport;

import java.io.*;
import java.net.*;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.NoSuchElementException;

/**
 * DNS Datagram message transport (UDP).
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSUDPTransport implements DNSTransport {

	/** List of server to choose from. */
	protected ArrayList listHostPort;
	/** Timeout when transmitting messages. */
	protected int connTimeout;

	/**
	 * Instantiate an empty socket object.
	 */
	public DNSUDPTransport() {
		listHostPort = new ArrayList();
		connTimeout = 0;
	}

	// Javadoc inherited from interface.
	public void setTimeout(int timeout) {
		connTimeout = timeout;
	}

	// Javadoc inherited from interface.
	public int getTimeout() {
		return connTimeout;
	}

	// Javadoc inherited from interface.
	public void addHost(String host, int port) {
		listHostPort.add(new DNSHostPort(host, port));
	}

	// Javadoc inherited from interface.
	public DNSConnector getConnector() {
		return (new DNSUDPConnector());
	}

	// Javadoc inherited from interface.
	public String toString() {
		String host;
		int port;
		String tmpStr = "";
		tmpStr += "Server(s):\n";
		tmpStr += "----------";
		for(int i=0; i<listHostPort.size(); i++) {
			host = ((DNSHostPort)listHostPort.get(i)).getHost();
			port = ((DNSHostPort)listHostPort.get(i)).getPort();
			tmpStr += " " + host + ":" + port + "\n";
		}
		return tmpStr;
	}

	/**
	 * Iterator based connector object.
	 */
	class DNSUDPConnector implements DNSConnector {

		/** Working socket */
		protected DatagramSocket socket = null;
		/** InputStream. */
		protected BufferedInputStream socketIn = null;
		/** OutputStream. */
		protected BufferedOutputStream socketOut = null;

		/** Message length. */
		protected int pLen;

		/** Host iterator. */
		protected Iterator iterator;
		/** Current host. */
		protected DNSHostPort currHostPort;

		/** InetAddr to lookup destination host. */
		protected InetAddress inetaddr = null;
		/** Datagram packet used to send/receive messages. */
		protected DatagramPacket dgpacket = null;

		/**
		 * Instantiates a connector and initialize the host iterator.
		 */
		public DNSUDPConnector() {
			reset();
		}

		// Javadoc inherited from interface.
		public void reset() {
			iterator = listHostPort.iterator();
			currHostPort = null;
		}

		// Javadoc inherited from interface.
		public boolean hasNext() {
			currHostPort = null;
			return iterator.hasNext();
		}

		// Javadoc inherited from interface.
		public Object next() throws NoSuchElementException {
			currHostPort = (DNSHostPort)iterator.next();
			return currHostPort;
		}

		// Javadoc inherited from interface.
		public boolean Connect() throws IllegalStateException {
			String host;
			int port;
			if ( currHostPort == null ) {
				throw new IllegalStateException("No iterator element.");
			}
			try {
				host = currHostPort.getHost();
				port = currHostPort.getPort();
				socket = new DatagramSocket();
				inetaddr = InetAddress.getByName(host);
				socket.connect(inetaddr, port);
				socket.setSoTimeout(connTimeout);
				return true;
			}
			catch(Exception e) {					// UnknownHostException / IOException / NullPointerException
				return false;
			}
		}

		// Javadoc inherited from interface.
		public void Disconnect() throws IllegalStateException {
			currHostPort = null;
			try {
				if ( socket != null ) {
					socket.disconnect();
					socket.close();
				}
			}
			catch(Exception e) {					// IOException / NullPointerException
			}
		}

		// Javadoc inherited from interface.
		public boolean sendMessage(byte[] pDat) throws IllegalStateException {
			if ( currHostPort == null ) {
				throw new IllegalStateException("No iterator element.");
			}
			pLen = pDat.length;
			if ( pLen > 0) {
				try {
					dgpacket = new DatagramPacket(pDat, pLen);
					socket.send(dgpacket);
				}
				catch (Exception e) {				// SocketException / InterruptedIOException / IOException
					return false;
				}
				return true;
			}
			else
				return false;
		}

		// Javadoc inherited from interface.
		public byte[] receiveMessage() throws IllegalStateException {
			if ( currHostPort == null ) {
				throw new IllegalStateException("No iterator element.");
			}
			byte[] pDat = null;
			byte[] recvdata = new byte[512];
			dgpacket = new DatagramPacket(recvdata, 512);
			try {
				socket.receive(dgpacket);
				pLen = dgpacket.getLength();
				if ( pLen > 0) {
					recvdata = dgpacket.getData();
					pDat = new byte[pLen];
					System.arraycopy(recvdata, 0, pDat, 0, pLen);
				}
			}
			catch (Exception e) {					// SocketException / InterruptedIOException / IOException
				pDat = null;
			}
			return pDat;
		}

	}

}
