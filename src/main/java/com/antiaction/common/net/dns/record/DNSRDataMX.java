/*
 * DNS MX Record container.
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
 * 05-Aug-2001 : Cleanup, javadoc.
 *             : Implemented buildPacket routine.
 *             : Recoded disassembly routine.
 * 25-Aug-2001 : Added debug method.
 * 27-Aug-2001 : Expanded debug info.
 * 09-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.dns.record;

import com.antiaction.dns.DNSType;
import com.antiaction.dns.DNSName;
import com.antiaction.dns.DNSException;
import com.antiaction.dns.DNSNameException;

/**
 * DNS MX Record container.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRDataMX implements DNSRDataInterface {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Record of type MX. */
	protected static int rtype = DNSType.MX;
	/** Preference. */
	protected int prefs;
	/** Exchange. */
	protected String exchange;

	/**
	 * Instantiate and initialize a default MX record object.
	 */
	public DNSRDataMX() {
		prefs = 0;
		exchange = "";
	}

 	/**
 	 * Overrides Cloneable.
 	 * @return a clone of this instance.
 	 * @exception OutOfMemoryError if there is not enough memory.
 	 * @see java.lang.Cloneable
 	 */
 	public Object clone() {
 		DNSRDataMX obj = new DNSRDataMX();
		obj.prefs = prefs;
		obj.exchange = exchange;
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
		byte[] exchangepkt;
		byte[] packetData;
		int packetLen;
		int RDLen;

		if ( debug ) {
			System.out.println("-> DNSRDataMX.buildPacket()");
			System.out.println("    prefs: " + prefs);
			System.out.println("    exchange: " + exchange);
		}

		packetLen = 0;

	// Exchange

		dnsname.setDebug(debug);
		exchangepkt = dnsname.buildPacket(globalIdx + 2, exchange, true, true);

	// RDLen

		RDLen = 2 + exchangepkt.length;
		packetData = new byte[2 + RDLen];

		packetData[packetLen++] = (byte)(RDLen >> 8);
		packetData[packetLen++] = (byte)(RDLen & 255);

	// Preference

		packetData[packetLen++] = (byte)(prefs >> 8);
		packetData[packetLen++] = (byte)(prefs & 255);

	// Exchange

		System.arraycopy(exchangepkt, 0, packetData, packetLen, exchangepkt.length);

		if ( debug ) {
			System.out.println("<- DNSRDataMX.buildPacket()");
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
			System.out.println("-> DNSRDataMX.disassemblePacket() - idx=" + pIdx);
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

	// Preference

		prefs = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);

	// Exchange

		try {
			dnsname.setDebug(debug);
			exchange = dnsname.disassemblePacket(pDat, pIdx, pLen);
		}
		catch(DNSException e) {
			throw new DNSRDataException("Invalid domain name.");
		}

		pIdx += dnsname.getDisassembledLen();

		if ( (pIdx - sIdx) != disLen ) {
			throw new DNSRDataException("RDLen mismatch.");
		}

		if ( debug ) {
			System.out.println("    prefs: " + prefs);
			System.out.println("    exchange: " + exchange);
			System.out.println("<- DNSRDataMX.disassemblePacket() - Len=" + disLen);
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
	 * Set the mx preference value.
	 * @param p mx preference
	 */
	public void setPrefs(int p) {
		prefs = p;
	}

	/**
	 * Get the mx preference value.
	 * @return mx preference.
	 */
	public int getPrefs() {
		return prefs;
	}

	/**
	 * Set the mx exchange domain name.
	 * @param ex mx exchange.
	 */
	public void setExchange(String ex) {
		exchange = ex;
	}

	/**
	 * Get the mx exchange domain name.
	 * @return mx exchange.
	 */
	public String getExchange() {
		return exchange;
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "MX record.\n";
		tmpStr += prefs + " - " + exchange + "\n";
		return tmpStr;
	}

}
