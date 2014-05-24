/*
 * DNS Socket message transport (TCP).
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
 * 17-Aug-2001 : Removed all the contructors with parameters.
 *             : Added get/get methods instead of constructor parameters.
 *             : Recoded close, send/receive message methods.
 * 18-Aug-2001 : Recoded connect method to try all servers before failing.
 *             : Close renamed to Disconnect.
 *             : Javadoc.
 *             : Added toString.
 * 20-Aug-2001 : Moved connection methods to inner class.
 * 21-Aug-2001 : Renamed inner class.
 * 22-Aug-2001 : Added iterator type methods. Throws clauses.
 * 23-Aug-2001 : Fixed Connect, Disconnect, Send, Receive to work with the iterator style methods.
 * 24-Aug-2001 : Removed javadocs, inherits interface javadocs.
 *
 */

package com.antiaction.common.net.dns.transport;

import java.io.*;
import java.net.*;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.NoSuchElementException;

/**
 * DNS Socket message transport (TCP).
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSTCPTransport implements DNSTransport {

	/** List of server to choose from. */
	protected ArrayList listHostPort;
	/** Timeout when transmitting messages. */
	protected int connTimeout;

	/**
	 * Instantiate an empty socket object.
	 */
	public DNSTCPTransport() {
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
		return (new DNSTCPConnector());
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
	class DNSTCPConnector implements DNSConnector {

		/** Working socket */
		protected Socket socket = null;
		/** InputStream. */
		protected BufferedInputStream socketIn = null;
		/** OutputStream. */
		protected BufferedOutputStream socketOut = null;

		/** Array used to en/de-code the length. */
		protected byte[] pLenDat;
		/** Message length. */
		protected int pLen;

		/** Host iterator. */
		protected Iterator iterator;
		/** Current host. */
		protected DNSHostPort currHostPort;

		/**
		 * Instantiates a connector and initialize the host iterator.
		 */
		public DNSTCPConnector() {
			pLenDat = new byte[2];
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
				socket = new Socket(host, port);
				socketIn = new BufferedInputStream(socket.getInputStream(), 16384);
				socketOut = new BufferedOutputStream(socket.getOutputStream(), 16384);
				socket.setKeepAlive(true);
				socket.setSoTimeout(connTimeout);
				return true;
			}
			catch(Exception e) {					// UnknownHostException / IOException / NullPointerException
			}
			return false;
		}

		// Javadoc inherited from interface.
		public void Disconnect() throws IllegalStateException {
			currHostPort = null;
			try {
				if ( socket != null ) {
					if ( socketOut != null ) {
						socketOut.flush();
						socketOut.close();
					}
					if ( socketIn != null ) {
						socketIn.close();
					}
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
				pLenDat[0] = (byte)(pLen >> 8);
				pLenDat[1] = (byte)(pLen & 255);
				try {
					socketOut.write(pLenDat, 0, 2);
					socketOut.write(pDat, 0, pLen);
					socketOut.flush();
				}
				catch (Exception e) {				// SocketException / InterruptedIOException / IOException
					return false;
				}
				return true;
			}
			else {
				return false;
			}
		}

		// Javadoc inherited from interface.
		public byte[] receiveMessage() throws IllegalStateException {
			if ( currHostPort == null ) {
				throw new IllegalStateException("No iterator element.");
			}
			byte[] pDat = null;
			try {
				socketIn.read(pLenDat, 0, 2);
				pLen = (pLenDat[0] & 255) << 8 | (pLenDat[1] & 255);
				if ( pLen > 0) {
					pDat = new byte[pLen];
					socketIn.read(pDat, 0, pLen);
				}
			}
			catch (Exception e) {					// SocketException / InterruptedIOException / IOException
				pDat = null;
			}
			return pDat;
		}

	}

}
