/*
 * DNS HINFO Record container.
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
 * 26-Aug-2001 : First implementation {
 * 27-Aug-2001 : }
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
 * DNS HINFO Record container.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRDataHINFO implements DNSRDataInterface {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Record of type HINFO. */
	protected static int rtype = DNSType.HINFO;
	/** CPU. */
	protected String cpu;
	/** OS. */
	protected String os;

	/**
	 * Instantiate and initialize a default HINFO record object.
	 */
	public DNSRDataHINFO() {
		cpu = "";
		os = "";
	}

 	/**
 	 * Overrides Cloneable.
 	 * @return a clone of this instance.
 	 * @exception OutOfMemoryError if there is not enough memory.
 	 * @see java.lang.Cloneable
 	 */
 	public Object clone() {
 		DNSRDataHINFO obj = new DNSRDataHINFO();
		obj.cpu = cpu;
		obj.os = os;
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
			System.out.println("-> DNSRDataHINFO.buildPacket()");
			System.out.println("    CPU: " + cpu);
			System.out.println("    OS: " + os);
		}

		packetLen = 0;

	// RDLen

		RDLen = 2 + cpu.length() + os.length();
		packetData = new byte[2 + RDLen];

		packetData[packetLen++] = (byte)(RDLen >> 8);
		packetData[packetLen++] = (byte)(RDLen & 255);

	// CPU

		packetData[packetLen++] = (byte)(cpu.length() & 255);
		for(int i=0; i<cpu.length(); i++) {
			packetData[packetLen++] = (byte)(cpu.charAt(i) & 255);
		}


	// OS

		packetData[packetLen++] = (byte)(os.length() & 255);
		for(int i=0; i<os.length(); i++) {
			packetData[packetLen++] = (byte)(os.charAt(i) & 255);
		}

		if ( debug ) {
			System.out.println("<- DNSRDataHINFO.buildPacket()");
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
		int len;

		if ( debug ) {
			System.out.println("-> DNSRDataHINFO.disassemblePacket() - idx=" + pIdx);
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

	// CPU

		if ( pIdx + 1 > pLen ) {
			throw new DNSRDataException("RecordOutOfBounds.");
		}

		len = (pDat[pIdx++] & 255);

		if ( pIdx + len > pLen ) {
			throw new DNSRDataException("RecordOutOfBounds.");
		}

		cpu = new String(pDat, pIdx, len);
		pIdx += len;

	// OS

		if ( pIdx + 1 > pLen ) {
			throw new DNSRDataException("RecordOutOfBounds.");
		}

		len = (pDat[pIdx++] & 255);

		if ( pIdx + len > pLen ) {
			throw new DNSRDataException("RecordOutOfBounds.");
		}

		os = new String(pDat, pIdx, len);
		pIdx += len;

	// RDLen

		if ( (pIdx - sIdx) != disLen ) {
			throw new DNSRDataException("RDLen mismatch.");
		}

		if ( debug ) {
			System.out.println("    CPU: " + cpu);
			System.out.println("    OS: " + os);
			System.out.println("<- DNSRDataHINFO.disassemblePacket() - Len=" + disLen);
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
	 * Set the CPU string.
	 * @param cpu CPU string.
	 */
	public void setCPU(String cpu) throws DNSRDataException {
		if ( cpu.length() > 255 ) {
			throw new DNSRDataException("CPU string too long.");
		}
		this.cpu = cpu;
	}

	/**
	 * Get the CPU string.
	 * @return CPU string.
	 */
	public String getCPU() {
		return cpu;
	}

	/**
	 * Set the OS string.
	 * @param os OS string.
	 */
	public void setOS(String os) throws DNSRDataException {
		if ( os.length() > 255 ) {
			throw new DNSRDataException("OS string too long.");
		}
		this.os = os;
	}

	/**
	 * Get the OS string.
	 * @return OS string.
	 */
	public String getOS() {
		return os;
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "HINFO record.\n";
		tmpStr += "cpu: " + cpu + "\n";
		tmpStr += "os: " + os + "\n";
		return tmpStr;
	}

}
