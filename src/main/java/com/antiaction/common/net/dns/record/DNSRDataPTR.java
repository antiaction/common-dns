/*
 * DNS PTR Record container.
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
 * 14-Sep-2001 : Reimplementation.
 * 09-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 * 22-Nov-2001 : buildPacket() RDLen +2 offset error.
 *
 */

package com.antiaction.dns.record;

import com.antiaction.dns.DNSType;
import com.antiaction.dns.DNSName;
import com.antiaction.dns.DNSException;
import com.antiaction.dns.DNSNameException;

/**
 * DNS PTR Record container.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRDataPTR implements DNSRDataInterface {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Record of type PTR. */
	protected static int rtype = DNSType.PTR;
	/** Domain Name Pointer. */
	protected String name;

	/**
	 * Instantiate and initialize a default PTR record object.
	 */
	public DNSRDataPTR() {
		name = "";
	}

 	/**
 	 * Overrides Cloneable.
 	 * @return a clone of this instance.
 	 * @exception OutOfMemoryError if there is not enough memory.
 	 * @see java.lang.Cloneable
 	 */
 	public Object clone() {
 		DNSRDataPTR obj = new DNSRDataPTR();
		obj.name = name;
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
	 * Build and return the rdata packet on the internal state.
	 * @param dnsname used for domain name compression in the same message.
	 * @param globalIdx current index of the message being assembled. (Domain name compression)
	 * @return the rdata part of the message as a byte array.
	 * @throws DNSNameException if the domain name is invalid.
	 */
	public byte[] buildPacket(DNSName dnsname, int globalIdx) throws DNSNameException {
		byte[] namepkt;
		byte[] packetData;
		int packetLen;
		int RDLen;

		if ( debug ) {
			System.out.println("-> DNSRDataPTR.buildPacket()");
			System.out.println("    ptr: " + name);
		}

		packetLen = 0;

	// Domain Name Pointer

		dnsname.setDebug(debug);
		namepkt = dnsname.buildPacket(globalIdx + 2, name, true, true);

	// RDLen

		RDLen = namepkt.length;
		packetData = new byte[2 + RDLen];

		packetData[packetLen++] = (byte)(RDLen >> 8);
		packetData[packetLen++] = (byte)(RDLen & 255);

	// Domain Name Pointer

		System.arraycopy(namepkt, 0, packetData, packetLen, namepkt.length);

		if ( debug ) {
			System.out.println("<- DNSRDataPTR.buildPacket()");
		}

		return packetData;
	}

	/**
	 * Returns the length of the previously disassembled rdata part.
	 * @return length of previously disassembled record data.
	 * @see #disassemblePacket(DNSName, byte[], int, int)
	 */
	public int getDisassembledLen() {
		return disLen;
	}

	/**
	 * Parses the rdata part of a record.
	 * @param dnsname used for domain name compression in the same message.
	 * @param pDat array containing the complete packet.
	 * @param pIdx index to where in the array the rdata part begins.
	 * @param pLen length of the whole packet.
	 * @throws DNSNameException if the domain name is invalid.
	 * @throws DNSRDataException if the packet is corrupted.
	 * @see #getDisassembledLen()
	 */
	public void disassemblePacket(DNSName dnsname, byte[] pDat, int pIdx, int pLen) throws DNSNameException, DNSRDataException {
		int RDLen;
		int sIdx;

		if ( debug ) {
			System.out.println("-> DNSRDataPTR.disassemblePacket() - idx=" + pIdx);
		}

		sIdx = pIdx;

	// RDLen

		if ( pIdx + 2 > pLen ) {
			throw new DNSRDataException("RecordOutOfBounds.");
		}

		RDLen = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);
		disLen = 2 + RDLen;

		if ( (pIdx + RDLen) > pLen ) {
			throw new DNSRDataException("RecordOutOfBounds.");
		}

	// Domain Name Pointer

		try {
			dnsname.setDebug(debug);
			name = dnsname.disassemblePacket(pDat, pIdx, pLen);
		}
		catch(DNSException e) {
			throw new DNSRDataException("Invalid domain name.");
		}

		pIdx += dnsname.getDisassembledLen();

		if ( (pIdx - sIdx) != disLen ) {
			throw new DNSRDataException("RDLen mismatch.");
		}

		if ( debug ) {
			System.out.println("    ptr: " + name);
			System.out.println("<- DNSRDataPTR.disassemblePacket() - Len=" + disLen);
		}
	}

	/**
	 * Get the record type.
	 * @return record type.
	 * @see com.antiaction.dns.DNSType
	 */
	public int getRType() {
		return rtype;
	}

	/**
	 * Set the domain name pointer of this record.
	 * @param name domain name.
	 */
	public void setPTR(String name) {
		this.name = name;
	}

	/**
	 * Get the domain name pointer of this record.
	 * @return domain name.
	 */
	public String getPTR() {
		return name;
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "PTR record.\n";
		tmpStr += name + "\n";
		return tmpStr;
	}

}
