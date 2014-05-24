/*
 * DNS Class, defines the various DNS Network domains.
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
 * 07-Oct-2001 : Moved QClass constants to separate class.
 *
 */

package com.antiaction.common.net.dns;

/**
 * DNS Class, defines the various DNS Network domains.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSClass {

	/** The internet. */
	public static final int IN = 1;
	/** The CSNET class (obsolete, used only for examples). */
	public static final int CS = 2;
	/** The CHAOS class. */
	public static final int CH = 3;
	/** Hesiod name service. */
	public static final int HS = 4;

	/**
	 * Only the static methods are meant for public use.
	 */
	protected DNSClass() {
	}

	/**
	 * Given a class returns a boolean indicating validity.
	 * @param i class id.
	 * @return class id validity.
	 * @see #toString(int)
	 */
	public static boolean validClass(int i) {
		switch ( i ) {
			case IN:
			case CS:
			case CH:
			case HS:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Given a class returns a string representation.
	 * @param i class.
	 * @return class string identifier.
	 * @see #validClass(int)
	 */
	public static String toString(int i) {
		String tmpstr = null;
		switch ( i ) {
			case IN:
				tmpstr = "The internet";
				break;
			case CS:
				tmpstr = "The CSNET class (obsolete, used only for examples";
				break;
			case CH:
				tmpstr = "The CHAOS class";
				break;
			case HS:
				tmpstr = "Hesiod name service";
				break;
			default:
				tmpstr = "Unknown";
				break;
		}
		return tmpstr;
	}

}
