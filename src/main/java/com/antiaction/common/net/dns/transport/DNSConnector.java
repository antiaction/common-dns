/*
 * DNS message connection interface, abstract class for DNS connections.
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
 * 20-Aug-2001 : First implementation.
 * 21-Aug-2001 : Renamed.
 * 22-Aug-2001 : Removed Iterator extends.
 *             : Added some throws.
 *             : Added some methods/javadoc.
 *             : Import cleanup.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.dns.transport;

import java.util.NoSuchElementException;

/**
 * DNS message connection interface, abstract class for DNS connections.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public interface DNSConnector {

	/**
	 * Puts the iterator in its initial state.
	 */
	public void reset();

	/**
	 * Returns true if the iteration has more elements.
	 * (In other words, returns true if next would return an element rather than throwing an exception.)
	 * @return true if the iterator has more elements.
	 */
	public boolean hasNext();

	/**
	 * Returns the next element in the interation.
	 * @return the next element in the iteration.
	 */
	public Object next() throws NoSuchElementException;

	/**
	 * Attempt to connect to the first server available in the pool of servers.
	 * Returns a boolean indicating whether a connection was succesful.
	 * @return boolean indicating if a connection was made.
	 * @see #Disconnect()
	 */
	public boolean Connect() throws IllegalStateException;

	/**
	 * Close the connection.
	 * @see #Connect()
	 */
	public void Disconnect() throws IllegalStateException;

	/**
	 * Send a message over the connection. Returns a boolean indicating success or failure.
	 * @param pDat array of byes containing the message.
	 * @return boolean indicating whether the message transfer was successful.
	 * @see #receiveMessage()
	 */
	public boolean sendMessage(byte[] pDat) throws IllegalStateException;

	/**
	 * Receive a message over the connection. Returns the message or null depending on
	 * wheter the transfer was a success.
	 * @return array of bytes containing the message or null if a failure was encountered.
	 * @see #sendMessage(byte[])
	 */
	public byte[] receiveMessage() throws IllegalStateException;

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString();

}
