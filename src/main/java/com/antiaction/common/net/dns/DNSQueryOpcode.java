/*
 * DNS Query Opcode, defines the various query constants.
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
 * DNS Query Opcode, defines the various query constants.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSQueryOpcode {

	/** Query. */
	public static final int QUERY = 0;
	/** Inverse-Query. */
	public static final int IQUERY = 1;
	/** Status. */
	public static final int STATUS = 2;

	/**
	 * Only the static methods are meant for public use.
	 */
	private DNSQueryOpcode() {
	}

	/**
	 * Given a query opcode returns a boolean indicating validity.
	 * @param i query opcode.
	 * @return query opcode validity.
	 * @see #toString(int)
	 */
	public static boolean validQueryOpcode(int i) {
		switch ( i ) {
			case QUERY:
			case IQUERY:
			case STATUS:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Given a query opcode returns a string representation.
	 * @param i query opcode.
	 * @return query opcode string.
	 * @see #validQueryOpcode(int)
	 */
	public static String toString(int i) {
		String tmpstr = null;
		switch ( i ) {
			case QUERY:
				tmpstr = "Query";
				break;
			case IQUERY:
				tmpstr = "Inverse-Query";
				break;
			case STATUS:
				tmpstr = "Status";
				break;
			default:
				tmpstr = "Reserved";
				break;
		}
		return tmpstr;
	}

}
