/*
 * DNS Section Type, defines types used to retrieve records stored by their type.
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

package com.antiaction.common.net.dns;

/**
 * DNS Section Type, defines types used to retrieve records stored by their type.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSSectionType {

	/** Answer. */
	public static final int ANSWER = 0;
	/** Authority. */
	public static final int AUTHORITY = 1;
	/** Additional. */
	public static final int ADDITIONAL = 2;
	/** All. */
	public static final int ALL = 255;

	/**
	 * Only the static methods are meant for public use.
	 */
	private DNSSectionType() {
	}

	/**
	 * Given a section type returns a boolean indicating validity.
	 * @param i section type.
	 * @return sectopn type validity.
	 * @see #toString(int)
	 */
	public static boolean validSectionType(int i) {
		switch ( i ) {
			case ANSWER:
			case AUTHORITY:
			case ADDITIONAL:
			case ALL:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Given a section type returns a string representation.
	 * @param i section type.
	 * @return section type string.
	 * @see #validSectionType(int)
	 */
	public static String toString(int i) {
		String tmpstr = null;
		switch ( i ) {
			case ANSWER:
				tmpstr = "Answer";
				break;
			case AUTHORITY:
				tmpstr = "Authority";
				break;
			case ADDITIONAL:
				tmpstr = "Additional";
				break;
			case ALL:
				tmpstr = "Any";
				break;
			default:
				tmpstr = "Unknown";
				break;
		}
		return tmpstr;
	}

}
