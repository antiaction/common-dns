/*
 * DNS Response Code, defines various response constants.
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
 * 15-Jul-2001 : Refactoring/Javadoc.
 *             : Renamed.
 *
 */

package com.antiaction.dns;

/**
 * DNS Response Code, defines various response constants.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSResponseCode {

	/** No error condiction. */
	public static final int NOERROR = 0;
	/** Format error - The name server was unable to interpret the query. */
	public static final int FORMATERROR = 1;
	/** Server failure - The name server was unable to process this query due to a problem with the name server. */
	public static final int SERVERFAILURE = 2;
	/** Name error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist. */
	public static final int NAMEERROR = 3;
	/** Not implemented - The name server does not support the requested kind of query. */
	public static final int NOTIMPLEMENTED = 4;
	/** Refused - The name server refuses to perform the specified operation for a policy reason. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (eg., zone transfer) for particular data. */
	public static final int REFUSED = 5;

	/**
	 * Only the static methods are meant for public use.
	 */
	private DNSResponseCode() {
	}

	/**
	 * Given a response code returns a boolean indicating validity.
	 * @param i response code.
	 * @return response code validity.
	 * @see #toString(int)
	 */
	public static boolean validResponseCode(int i) {
		switch ( i ) {
			case NOERROR:
			case FORMATERROR:
			case SERVERFAILURE:
			case NAMEERROR:
			case NOTIMPLEMENTED:
			case REFUSED:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Given a response code returns a string representation.
	 * @param i response code.
	 * @return response code string.
	 * @see #validResponseCode(int)
	 */
	public static String toString(int i) {
		String tmpstr = null;
		switch ( i ) {
			case NOERROR:
				tmpstr = "No error condition";
				break;
			case FORMATERROR:
				tmpstr = "Format error";
				break;
			case SERVERFAILURE:
				tmpstr = "Server failure";
				break;
			case NAMEERROR:
				tmpstr = "Name Error";
				break;
			case NOTIMPLEMENTED:
				tmpstr = "Not Implemented";
				break;
			case REFUSED:
				tmpstr = "Refused";
				break;
			default:
				tmpstr = "Unknown";
				break;
		}
		return tmpstr;
	}

}
