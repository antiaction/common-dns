/*
 * DNS NULL record container.
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
 * 07-Sep-2001 : First implementation.
 * 09-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.dns.record;

import com.antiaction.dns.DNSType;
import com.antiaction.dns.DNSName;
import com.antiaction.dns.DNSNameException;

/**
 * DNS NULL record container.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRDataNULL implements DNSRDataInterface {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Record of type NULL. */
	protected static int rtype = DNSType.NULL;
	/** Array of data. */
	protected byte[] genericData;

	/**
	 * Instantiate and initialize a default NULL record object.
	 */
	public DNSRDataNULL() {
		genericData = new byte[0];
	}

 	/**
 	 * Overrides Cloneable.
 	 * @return a clone of this instance.
 	 * @exception OutOfMemoryError if there is not enough memory.
 	 * @see java.lang.Cloneable
 	 */
 	public Object clone() {
 		DNSRDataNULL obj = new DNSRDataNULL();
		obj.genericData = (byte[])genericData.clone();
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
		byte[] packetData;
		int packetLen;
		int RDLen;

		if ( debug ) {
			System.out.println("-> DNSRDataNULL.buildPacket()");
		}

		packetLen = 0;
		RDLen = genericData.length;

		packetData = new byte[2+RDLen];

	// RDLen

		packetData[packetLen++] = (byte)(RDLen >> 8);
		packetData[packetLen++] = (byte)(RDLen & 255);

	// RData(GENERIC)

		System.arraycopy(genericData, 0, packetData, packetLen, genericData.length);

		if ( debug ) {
			System.out.println("<- DNSRDataNULL.buildPacket()");
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

		if ( debug ) {
			System.out.println("-> DNSRDataNULL.disassemblePacket() - idx=" + pIdx);
		}

	// RDLen

		if ( pIdx + 2 > pLen ) {
			throw new DNSRDataException("RecordOutOfBounds.");
		}

		RDLen = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);
		disLen = 2 + RDLen;

		if ( (pIdx + RDLen) > pLen ) {
			throw new DNSRDataException("RecordOutOfBounds.");
		}

	// RData(GENERIC)

		genericData = new byte[RDLen];
		System.arraycopy(pDat, pIdx, genericData, 0, RDLen);

		if ( debug ) {
			System.out.println("<- DNSRDataNULL.disassemblePacket() - Len=" + disLen);
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
	 * Set the generic data of this record.
	 * @param data raw byte array.
	 */
	public void setData(byte[] data) {
		genericData = new byte[data.length];
		System.arraycopy(data, 0, genericData, 0, data.length);
	}

	/**
	 * Get the generic data of this record.
	 * @return raw byte array.
	 */
	public byte[] getData() {
		byte[] data;
		data = new byte[genericData.length];
		System.arraycopy(genericData, 0, data, 0, genericData.length);
		return data;
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "NULL record.\n";
		if ( genericData == null ) {
			tmpStr += "Null pointer.\n";
		}
		else {
			for(int i=0; i<genericData.length; i++) {
				tmpStr += ((int)genericData[i]&255) + " - " + (char)((int)genericData[i]&255) + "\n";
			}
		}
		return tmpStr;
	}

}
