/*
 * DNS MINFO Record container.
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
 * 28-Aug-2001 : First implemenation.
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
 * DNS MINFO Record container.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRDataMINFO implements DNSRDataInterface {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Record of type MINFO. */
	protected static int rtype = DNSType.MINFO;
	/** Responsible mailbox. */
	protected String rMailBX;
	/** Error mailbox. */
	protected String eMailBX;

	/**
	 * Instantiate and initialize a default MINFO record object.
	 */
	public DNSRDataMINFO() {
		rMailBX = "";
		eMailBX = "";
	}

 	/**
 	 * Overrides Cloneable.
 	 * @return a clone of this instance.
 	 * @exception OutOfMemoryError if there is not enough memory.
 	 * @see java.lang.Cloneable
 	 */
 	public Object clone() {
 		DNSRDataMINFO obj = new DNSRDataMINFO();
		obj.rMailBX =  rMailBX;
		obj.eMailBX = eMailBX;
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
		byte[] rmailbxpkt;
		byte[] emailbxpkt;
		byte[] packetData;
		int packetLen;
		int RDLen;

		if ( debug ) {
			System.out.println("-> DNSRDataMINFO.buildPacket()");
			System.out.println("    rmailbx: " + rMailBX);
			System.out.println("    emailbx: " + eMailBX);
		}

		packetLen = 0;

	// Responsible - Error

		dnsname.setDebug(debug);
		rmailbxpkt = dnsname.buildPacket(globalIdx + 2, rMailBX, true, true);
		emailbxpkt = dnsname.buildPacket(globalIdx + 2 + rmailbxpkt.length, eMailBX, true, true);

	// RDLen

		RDLen = rmailbxpkt.length + emailbxpkt.length;
		packetData = new byte[2 + RDLen];

		packetData[packetLen++] = (byte)(RDLen >> 8);
		packetData[packetLen++] = (byte)(RDLen & 255);

	// Responsible - Error

		System.arraycopy(rmailbxpkt, 0, packetData, packetLen, rmailbxpkt.length);
		packetLen += rmailbxpkt.length;

		System.arraycopy(emailbxpkt, 0, packetData, packetLen, emailbxpkt.length);
		//packetLen += emailbxpkt.length;

		if ( debug ) {
			System.out.println("<- DNSRDataMINFO.buildPacket()");
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
			System.out.println("-> DNSRDataMINFO.disassemblePacket() - idx=" + pIdx);
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

	// Responsible

		try {
			dnsname.setDebug(debug);
			rMailBX = dnsname.disassemblePacket(pDat, pIdx, pLen);
		}
		catch(DNSException e) {
			throw new DNSRDataException("Invalid domain name.");
		}

		pIdx += dnsname.getDisassembledLen();

	// Error

		try {
			dnsname.setDebug(debug);
			eMailBX = dnsname.disassemblePacket(pDat, pIdx, pLen);
		}
		catch(DNSException e) {
			throw new DNSRDataException("Invalid domain name.");
		}

		pIdx += dnsname.getDisassembledLen();

		if ( (pIdx - sIdx) != disLen ) {
			throw new DNSRDataException("RDLen mismatch.");
		}

		if ( debug ) {
			System.out.println("    rmailbx: " + rMailBX);
			System.out.println("    emailbx: " + eMailBX);
			System.out.println("<- DNSRDataMINFO.disassemblePacket() - Len=" + disLen);
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
	 * Set the responsible mailbox.
	 * @param mbx domainname.
	 */
	public void setResponsibleMX(String mbx) {
		rMailBX = mbx;
	}

	/**
	 * Get the responsible mailbox.
	 * @return domainname.
	 */
	public String getResponsibleMX() {
		return rMailBX;
	}

	/**
	 * Set the error mailbox.
	 * @param mbx domainname.
	 */
	public void setErrorMX(String mbx) {
		eMailBX = mbx;
	}

	/**
	 * Get the error mailbox.
	 * @return domainname.
	 */
	public String getErrorMX() {
		return eMailBX;
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "MINFO record.\n";
		tmpStr += "rmailbx: " + rMailBX + "\n";
		tmpStr += "emailbx: " + eMailBX + "\n";
		return tmpStr;
	}

}
