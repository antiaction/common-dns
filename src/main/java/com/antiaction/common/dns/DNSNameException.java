/*
 * DNS domainname exception, in case of corrupt data.
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
 * 22-Jul-2001 : First implemenation, Javadoc.
 * 11-Aug-2001 : Javadoc fix.
 *
 */

package com.antiaction.common.dns;

/**
 * DNS domainname exception, in case of corrupt domainname data.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSNameException extends java.lang.Exception {

	/**
	 * UID.
	 */
	private static final long serialVersionUID = 851573993408609804L;

	/**
	 * Overriding constructor.
	 * @param text error message.
	 */
	public DNSNameException(String text){
		super(text);
	}

}
