/*
 * DNS Record Header, contains the header portion of a resource record.
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
 * 01-Aug-2001 : Cleanup, Javadoc.
 * 02-Aug-2001 : Implemented buildPacket routine. Removed rData and rLen structures and code.
 *             : Recoded disassembly routine.
 *             : Renamed from DNSRecord to DNSRecordHeader. Added Set/Get TTL.
 * 03-Aug-2001 : Bug fix in disassembly routine conversion. Changed defaults.
 * 05-Aug-2001 : Fixed some javadoc.
 *             : Renamed disassembly method.
 *             : Added index check in disassembly, including new throws.
 * 10-Aug-2001 : Removed arrayToString method.
 * 25-Aug-2001 : Added debug method.
 *             : Expanded debug info.
 * 09-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.common.net.dns;

import com.antiaction.common.net.dns.DNSType;
import com.antiaction.common.net.dns.DNSClass;

/**
 * DNS Record Header, contains the header portion of a resource record.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRecordHeader implements Cloneable {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Domain name associated. */
	protected String rname;
	/** Record type. */
	protected int rtype;
	/** Record class. */
	protected int rclass;
	/** Record Time To Live. */
	protected int rttl;

	/**
	 * Instantiate and initialize a default question object.
	 */
	public DNSRecordHeader() {
		rname = "";
		rtype = DNSType.GENERIC;
		rclass = DNSClass.IN;
		rttl = 0;
	}

	/**
	 * Overrides Cloneable.
	 * @return a clone of this instance.
	 * @exception OutOfMemoryError if there is not enough memory.
	 * @see java.lang.Cloneable
	 */
	public Object clone() {
		DNSRecordHeader obj = new DNSRecordHeader();
		obj.rname = rname;
		obj.rtype = rtype;
		obj.rclass = rclass;
		obj.rttl = rttl;
		return obj;
	}

	/**
	 * Toggle debug status.
	 * @param b boolean.
	 */
	public void setDebug(boolean b) {
		debug = b;
	}

	/**
	 * Build and return the record header based on the internal state.
	 * @param dnsname used for domain name compression in the same message.
	 * @param globalIdx current index of the message being assembled. (Domain name compression)
	 * @return the record header part of a record as a byte array.
	 * @throws DNSNameException if the domain name is invalid.
	 */
	public byte[] buildPacket(DNSName dnsname, int globalIdx) throws DNSNameException {
		byte[] dnsnamepkt;
		byte[] packetData;
		int packetLen;

		if ( debug ) {
			System.out.println("-> DNSRecordHeader.buildPacket()");
			System.out.println("    rname: " + rname);
			System.out.println("    rtype: " + DNSType.toString(rtype));
			System.out.println("    rclass: " + DNSClass.toString(rclass));
			System.out.println("    rttl: " + rttl);
		}

	// RName

		dnsname.setDebug(debug);
		dnsnamepkt = dnsname.buildPacket(globalIdx, rname, true, true);

		packetLen = dnsnamepkt.length;
		packetData = new byte[packetLen + 8];

		System.arraycopy(dnsnamepkt, 0, packetData, 0, packetLen);

	// RType

		packetData[packetLen++] = (byte)(rtype >> 8);
		packetData[packetLen++] = (byte)(rtype & 255);

	// RClass

		packetData[packetLen++] = (byte)(rclass >> 8);
		packetData[packetLen++] = (byte)(rclass & 255);

	// RTTL

		packetData[packetLen++] = (byte)(rttl >> 24);
		packetData[packetLen++] = (byte)(rttl >> 16);
		packetData[packetLen++] = (byte)(rttl >> 8);
		packetData[packetLen++] = (byte)(rttl & 255);

		if ( debug ) {
			System.out.println("<- DNSRecordHeader.buildPacket()");
		}

		return packetData;
	}

	/**
	 * Returns the length of the previously disassembled record header.
	 * @return length of previously disassembled record header.
	 * @see #disassemblePacket(DNSName, byte[], int, int)
	 */
	public int getDisassembledLen() {
		return disLen;
	}

	/**
	 * Parses the record header part of a packet.
	 * @param dnsname used for domain name compression in the same message.
	 * @param pDat array containing the complete packet.
	 * @param pIdx index to where in the array the record header begins.
	 * @param pLen length of the whole packet.
	 * @throws DNSException if the packet is corrupted.
	 * @throws DNSNameException if the domain name is invalid.
	 * @see #getDisassembledLen()
	 */
	public void disassemblePacket(DNSName dnsname, byte[] pDat, int pIdx, int pLen) throws DNSException, DNSNameException {

		if ( debug ) {
			System.out.println("-> DNSRecordHeader.disassemblePacket() - idx=" + pIdx);
		}

	// RName

		dnsname.setDebug(debug);
		rname = dnsname.disassemblePacket(pDat, pIdx, pLen);
		disLen = dnsname.getDisassembledLen();
		pIdx += disLen;

	// Index

		if ( (pIdx + 8) > pLen ) {
			throw new DNSException("IndexOutOfBounds.");
		}

	// RType

		rtype = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);
		disLen += 2;

	// RClass

		rclass = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);
		disLen += 2;

	// RTTL

		rttl = ((pDat[pIdx++] & 255) << 24) | ((pDat[pIdx++] & 255) << 16) | ((pDat[pIdx++] & 255) << 8) | (pDat[pIdx++] & 255);
		disLen += 4;

		if ( debug ) {
			System.out.println("    rname: " + rname);
			System.out.println("    rtype: " + DNSType.toString(rtype));
			System.out.println("    rclass: " + DNSClass.toString(rclass));
			System.out.println("    rttl: " + rttl);
			System.out.println("<- DNSRecordHeader.disassemblePacket() - Len=" + disLen);
		}
	}

	/**
	 * Set the record name.
	 * @param s domain name.
	 */
	public void setRName(String s) {
		rname = s;
	}

	/**
	 * Get the record name.
	 * @return domain name.
	 */
	public String getRName() {
		return rname;
	}

	/**
	 * Set the record type.
	 * @param rt record type.
	 * @see com.antiaction.common.net.dns.DNSType
	 */
	public void setRType(int rt) {
		rtype = rt;
	}

	/**
	 * Get the record type.
	 * @return record type.
	 * @see com.antiaction.common.net.dns.DNSType
	 */
	public int getRType() {
		return rtype;
	}

	/**
	 * Set the record class.
	 * @param rc record class.
	 * @see com.antiaction.common.net.dns.DNSClass
	 */
	public void setRClass(int rc) {
		rclass = rc;
	}

	/**
	 * Get the record class.
	 * @return record class.
	 * @see com.antiaction.common.net.dns.DNSClass
	 */
	public int getRClass() {
		return rclass;
	}

	/**
	 * Set the record ttl.
	 * @param rt record ttl.
	 */
	public void setRTTL(int rt) {
		rttl = rt;
	}

	/**
	 * Get the record ttl.
	 * @return record ttl.
	 */
	public int getRTTL() {
		return rttl;
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpstr = "";
		tmpstr = tmpstr + "RNAME: " + rname + "\n";
		tmpstr = tmpstr + "RTYPE: " + DNSType.toString(rtype) + "\n";
		tmpstr = tmpstr + "RCLASS: " + DNSClass.toString(rclass) + "\n";
		tmpstr = tmpstr + "RTTL: " + rttl + "\n";
		return tmpstr;
	}

}
