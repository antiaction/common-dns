/*
 * DNS Type, defines the various record type constants.
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
 * 11-Aug-2001 : Added generic type.
 * 08-Oct-2001 : Moved QType constants to seperate class.
 *
 */

package com.antiaction.dns;

/**
 * DNS Type, defines the various record type constants.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSType {

	/** HostAddress. */
	public static final int A = 1;			// A     HostAddress
	/** Authoritative name server. */
	public static final int NS = 2;			// NS    Authoritative name server
	/** MailDestination, obsolete, use Mail Exchange. */
	public static final int MD = 3;			// MD    MailDestination, obsolete, use Mail Exchange
	/** MailForwarder, obsolete, use Mail Exchange. */
	public static final int MF = 4;			// MF    MailForwarder, obsolete, use Mail Exchange
	/** CanonicalName. */
	public static final int CNAME = 5;		// CNAME CanonicalName
	/** Start of a Zone of Authority. */
	public static final int SOA = 6;		// SOA   Start of a Zone of Authority
	/** MailBox, experimental. */
	public static final int MB = 7;			// MB    MailBox, experimental
	/** MailGroup, experimental. */
	public static final int MG = 8;			// MG    MailGroup, experimental
	/** MailRename, experimental. */
	public static final int MR = 9;			// MR    MailRename, experimental
	/** Experimental. */
	public static final int NULL = 10;		// NULL  Experimental
	/** Well Known Service Description. */
	public static final int WKS = 11;		// WKS   Well Known Service Description
	/** Domain Name Pointer.*/
	public static final int PTR = 12;		// PTR   Domain Name Pointer
	/** Host Information. */
	public static final int HINFO = 13;		// HINFO Host Information
	/** Mailbox information. */
	public static final int MINFO = 14;		// MINFO Mailbox information
	/** Mail Exchange. */
	public static final int MX = 15;		// MX    Mail Exchange
	/** Text Strings. */
	public static final int TXT = 16;		// TXT   Text Strings

	/** Used internally to represent unsupported record types. */
	public static final int GENERIC = 65535;// Internal

	/**
	 * Only the static methods are meant for public use.
	 */
	protected DNSType() {
	}

	/**
	 * Given a record type returns a boolean indicating validity.
	 * @param i record type.
	 * @return record type validity.
	 * @see #toString(int)
	 */
	public static boolean validType(int i) {
		switch ( i ) {
			case A:
			case NS:
			case MD:
			case MF:
			case CNAME:
			case SOA:
			case MB:
			case MG:
			case MR:
			case NULL:
			case WKS:
			case PTR:
			case HINFO:
			case MINFO:
			case MX:
			case TXT:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Given a record type returns a string representation.
	 * @param i record type.
	 * @return record type string.
	 * @see #validType(int)
	 */
	public static String toString(int i) {
		String tmpstr = null;
		switch ( i ) {
			case A:
				tmpstr = "A - HostAddress";
				break;
			case NS:
				tmpstr = "NS - Authoritative name server";
				break;
			case MD:
				tmpstr = "MD - MailDestination, obsolete, use Mail Exchange";
				break;
			case MF:
				tmpstr = "MF - MailForwarder, obsolete, use Mail Exchange";
				break;
			case CNAME:
				tmpstr = "CNAME - CanonicalName";
				break;
			case SOA:
				tmpstr = "SOA - Start of a Zone of Authority";
				break;
			case MB:
				tmpstr = "MB - MailBox, experimental";
				break;
			case MG:
				tmpstr = "MG - MailGroup, experimental";
				break;
			case MR:
				tmpstr = "MR - MailRename, experimental";
				break;
			case NULL:
				tmpstr = "NULL - Experimental";
				break;
			case WKS:
				tmpstr = "WKS - Well Known Service Description";
				break;
			case PTR:
				tmpstr = "PTR - Domain Name Pointer";
				break;
			case HINFO:
				tmpstr = "HINFO - Host Information";
				break;
			case MINFO:
				tmpstr = "MINFO - Mailbox information";
				break;
			case MX:
				tmpstr = "MX - Mail Exchange";
				break;
			case TXT:
				tmpstr = "TXT - Text Strings";
				break;
			default:
				tmpstr = "Unknown";
				break;
		}
		return tmpstr;
	}

}
