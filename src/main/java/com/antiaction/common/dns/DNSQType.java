/*
 * DNS QType constants, defines the various qtype constants.
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
 * 08-Oct-2001 : QType constants moved to this separate class.
 *
 */

package com.antiaction.common.dns;

/**
 * DNS QType constants, defines the various qtype constants.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSQType extends DNSType {

	/** Transfer for an entire zone. */
	public static final int AXFR = 252;		// Transfer for an entire zone
	/** Mailbox related records (MB, MG or MR). */
	public static final int MAILB = 253;	// Mailbox related records (MB, MG or MR)
	/** MailAgent, obsolete, use MX instead. */
	public static final int MAILA = 254;	// MailAgent, obsolete, use MX instead
	/** Request ALL records. */
	public static final int ALL = 255;		// Request ALL records

	/**
	 * Only the static methods are meant for public use.
	 */
	protected DNSQType() {
	}

	/**
	 * Given a record type returns a boolean indicating validity.
	 * @param i record type.
	 * @return record type validity.
	 * @see #toString(int)
	 */
	public static boolean validQType(int i) {
		switch ( i ) {
			case AXFR:
			case MAILB:
			case MAILA:
			case ALL:
				return true;
			default:
				return DNSType.validType(i);
		}
	}

	/**
	 * Given a record type returns a string representation.
	 * @param i record type.
	 * @return record type string.
	 * @see #validQType(int)
	 */
	public static String toString(int i) {
		String tmpstr = null;
		switch ( i ) {
			case AXFR:
				tmpstr = "Transfer for an entire zone";
				break;
			case MAILB:
				tmpstr = "Mailbox related records (MB, MG or MR)";
				break;
			case MAILA:
				tmpstr = "MailAgent, obsolete, use MX instead";
				break;
			case ALL:
				tmpstr = "Request ALL records";
				break;
			default:
				tmpstr = DNSType.toString(i);
				break;
		}
		return tmpstr;
	}

}
