/*
 * DNS QClass, defines the various qclass constants.
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
 * 07-Oct-2001 : QClass constants moved to this separate class.
 *
 */

package com.antiaction.common.net.dns;

/**
 * DNS QClass, defines the various qclass constants.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSQClass extends DNSClass {

	/** Any class. */
	public static final int ALL = 255;

	/**
	 * Only the static methods are meant for public use.
	 */
	private DNSQClass() {
	}

	/**
	 * Given a qclass returns a boolean indicating validity.
	 * @param i qclass id.
	 * @return qclass id validity.
	 * @see #toString(int)
	 */
	public static boolean validQClass(int i) {
		switch ( i ) {
			case ALL:
				return true;
			default:
				return DNSClass.validClass(i);
		}
	}

	/**
	 * Given a record class returns a string representation.
	 * @param i record class.
	 * @return record class string identifier.
	 * @see #validQClass(int)
	 */
	public static String toString(int i) {
		String tmpstr = null;
		switch ( i ) {
			case ALL:
				tmpstr = "Any class";
				break;
			default:
				tmpstr = DNSClass.toString(i);
				break;
		}
		return tmpstr;
	}

}
