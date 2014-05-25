/*
 * DNS Record container, contains a header object and a data object.
 * Copyright (C) 2000, 2001, 2005  Nicholas Clarke
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
 * 18-Jul-2001 : First implemenation.
 * 25-Aug-2001 : Added debug method.
 *             : Javadoc.
 * 09-Oct-2001 : Cloneable.
 * 04-Mar-2005 : Fixed javadoc.
 *
 */

package com.antiaction.common.dns;

import com.antiaction.common.dns.record.DNSRDataInterface;

/**
 * DNS Record container, contains a header object and a data object.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRecord implements Cloneable {

	/** DNS record header object. */
	protected DNSRecordHeader dnsrecordheader = null;

	/** DNS record data object. */
	protected DNSRDataInterface dnsrdata = null;

	/**
	 * Instantiate and initialize a dns record.
	 */
	public DNSRecord(DNSRecordHeader header, DNSRDataInterface rdata) {
		dnsrecordheader = (DNSRecordHeader)header.clone();
		dnsrdata = (DNSRDataInterface)rdata.clone();
	}

	/**
	 * Overrides Cloneable.
	 * @return a clone of this instance.
	 * @exception OutOfMemoryError if there is not enough memory.
	 * @see java.lang.Cloneable
	 */
	public Object clone() {
		DNSRecord obj = new DNSRecord(dnsrecordheader, dnsrdata);
		return obj;
	}

	/**
	 * Toggle debug status.
	 * @param debug debug boolean.
	 */
	public void setDebug(boolean debug) {
		dnsrecordheader.setDebug(debug);
		dnsrdata.setDebug(debug);
	}

	/**
	 * Get the record header object.
	 * @return record header object.
	 */
	public DNSRecordHeader getHeader() {
		return (DNSRecordHeader)dnsrecordheader.clone();
	}

	/**
	 * Get the rdata object.
	 * @return rdata object.
	 */
	public DNSRDataInterface getRData() {
		return (DNSRDataInterface)dnsrdata.clone();
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "\n";
		tmpStr += "Record\n";
		tmpStr += "------\n";
		tmpStr += dnsrecordheader.toString();
		tmpStr += "RData\n";
		tmpStr += "-----\n";
		tmpStr += dnsrdata.toString();
		return tmpStr;
	}

}
