/*
 * DNS RData, main entry point for disassembling record data according to type.
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
 * 06-Aug-2001 : Cleanup, rearranged, javadoc.
 * 26-Aug-2001 : Added disassemblePacket call which made the dns package work.
 * 27-Aug-2001 : Added debug method.
 * 27-Aug-2001 : Removed ALL case.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.common.net.dns.record;

import com.antiaction.common.net.dns.DNSRecordHeader;
import com.antiaction.common.net.dns.DNSType;
import com.antiaction.common.net.dns.DNSName;
import com.antiaction.common.net.dns.DNSNameException;

/**
 * DNS RData, main entry point for disassembling record data according to type.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRData {

	/** Debug on/off. */
	private boolean debug = false;

	/**
	 * Instantiate and initialize an empty RData object.
	 */
	public DNSRData() {
	}

	/**
	 * Toggle debug status.
	 * @param b boolean.
	 */
	public void setDebug(boolean b) {
		debug = b;
	}

	/*
	 * Parses the rdata part of a record.
	 * @param dnsname used for domain name compression in the same message.
	 * @param pDat array containing the complete packet.
	 * @param pIdx index to where in the array the rdata part begins.
	 * @param pLen length of the whole packet.
	 * @param rheader Record Header.
	 * @throws DNSNameException if the domain name is invalid.
	 * @throws DNSRDataException if the packet is corrupted.
	 */
	public DNSRDataInterface disassemblePacket(DNSName dnsname, byte[] pDat, int pIdx, int pLen, DNSRecordHeader rheader) throws DNSNameException, DNSRDataException {
		DNSRDataInterface rdata = null;
		int rtype;

		rtype = rheader.getRType();

		switch ( rtype ) {
			case DNSType.A:
				rdata = new DNSRDataA();
				break;
			case DNSType.NS:
				rdata = new DNSRDataNS();
				break;
			case DNSType.MD:
				rdata = new DNSRDataMD();
				break;
			case DNSType.MF:
				rdata = new DNSRDataMF();
				break;
			case DNSType.CNAME:
				rdata = new DNSRDataCName();
				break;
			case DNSType.SOA:
				rdata = new DNSRDataSOA();
				break;
			case DNSType.MB:
				rdata = new DNSRDataMB();
				break;
			case DNSType.MG:
				rdata = new DNSRDataMG();
				break;
			case DNSType.MR:
				rdata = new DNSRDataMR();
				break;
			case DNSType.NULL:
				rdata = new DNSRDataNULL();
				break;
			case DNSType.WKS:
				rdata = new DNSRDataWKS();
				break;
			case DNSType.PTR:
				rdata = new DNSRDataPTR();
				break;
			case DNSType.HINFO:
				rdata = new DNSRDataHINFO();
				break;
			case DNSType.MINFO:
				rdata = new DNSRDataMINFO();
				break;
			case DNSType.MX:
				rdata = new DNSRDataMX();
				break;
			case DNSType.TXT:
				rdata = new DNSRDataTXT();
				break;
			default:
				rdata = new DNSRDataGeneric(rtype);
				break;
		}

		if ( rdata != null ) {
			rdata.setDebug(debug);
			rdata.disassemblePacket(dnsname, pDat, pIdx, pLen);
		}

		return rdata;
	}

}
