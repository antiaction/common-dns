/*
 * DNS A Record container.
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
 * 04-Aug-2001 : Cleanup, javadoc, Split(String, String) from AString.
 *             : Implemented buildPacket routine.
 *             : Recoded disassembly routine.
 * 05-Aug-2001 : Rearrange some methods.
 *             : Fixed some javadoc.
 * 06-Aug-2001 : Interface.
 * 25-Aug-2001 : Added debug method.
 * 27-Aug-2001 : Expanded debug info.
 * 09-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.common.net.dns.record;

import com.antiaction.common.net.dns.DNSType;
import com.antiaction.common.net.dns.DNSName;
import com.antiaction.common.net.dns.DNSNameException;

import java.util.ArrayList;

/**
 * DNS A Record container.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRDataA implements DNSRDataInterface {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Record of type A. */
	protected static int rtype = DNSType.A;
	/** IP record. */
	protected byte[] ipAddrArr;
	/** IP address. */
	protected String ipAddr;

	/**
	 * Instantiate and initialize a default A record object.
	 */
	public DNSRDataA() {
		ipAddrArr = new byte[4];
		ipAddr = "0.0.0.0";
	}

 	/**
 	 * Overrides Cloneable.
 	 * @return a clone of this instance.
 	 * @exception OutOfMemoryError if there is not enough memory.
 	 * @see java.lang.Cloneable
 	 */
 	public Object clone() {
 		DNSRDataA obj = new DNSRDataA();
		obj.ipAddrArr = (byte[])ipAddrArr.clone();
		obj.ipAddr = ipAddr;
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
			System.out.println("-> DNSRDataA.buildPacket()");
			System.out.println("    ipAddr: " + ipAddr);
		}

		packetLen = 0;
		RDLen = ipAddrArr.length;

		packetData = new byte[2 + RDLen];

	// RDLen

		packetData[packetLen++] = (byte)(RDLen >> 8);
		packetData[packetLen++] = (byte)(RDLen & 255);

	// RData(A)

		System.arraycopy(ipAddrArr, 0, packetData, packetLen, ipAddrArr.length);

		if ( debug ) {
			System.out.println("<- DNSRDataA.buildPacket()");
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
	 * @throws DNSRDataException if the packet is corrupted.
	 * @throws DNSNameException if the domain name is invalid.
	 * @see #getDisassembledLen()
	 */
	public void disassemblePacket(DNSName dnsname, byte[] pDat, int pIdx, int pLen) throws DNSNameException, DNSRDataException {
		int RDLen;

		if ( debug ) {
			System.out.println("-> DNSRDataA.disassemblePacket() - idx=" + pIdx);
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

		if ( RDLen != 4 ) {
			throw new DNSRDataException("Invalid A Record.");
		}

	// RData(A)

		ipAddr = "";
		for(int i=0; i<RDLen; i++) {
			ipAddrArr[i] = pDat[pIdx++];
			if ( ipAddr.length() > 0 ) {
				ipAddr += ".";
			}
			ipAddr += ipAddrArr[i]&255;
		}

		if ( debug ) {
			System.out.println("    ipAddr: " + ipAddr);
			System.out.println("<- DNSRDataA.disassemblePacket() - Len=" + disLen);
		}
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
	 * Validate and set the IP address of this record.
	 * @param ip ip address.
	 * @throws DNSRDataException if the ip address is not valid.
	 */
	public void setIPAddr(String ip) throws DNSRDataException {
		ArrayList strArr;
		strArr = Split(ip, ".");

		if ( (strArr == null) || (strArr.size() != 4) ) {
			throw new DNSRDataException("Invalid IP Address.");
		}

		for(int i=0; i<strArr.size(); i++) {
			try {
				ipAddrArr[i] = (byte)(Integer.parseInt((String)strArr.get(i)) & 255);
			}
			catch(NumberFormatException e) {
				throw new DNSRDataException("Invalid IP Address.");
			}
		}

		ipAddr = ip;
	}

	/**
	 * Get the IP address of this record.
	 * @return the IP address.
	 */
	public String getIPAddr() {
		return ipAddr;
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "A record.\n";
		tmpStr += ipAddr + "\n";
		return tmpStr;
	}

	/**
	 * Splits a string according to a substring and returns an arraylist where each
	 * item represents a string delimited by the substring.
	 * @param str string to split.
	 * @param dstr substring used to split the string.
	 * @return arraylist where each entry represents a string delimited by the subitem.
	 */
	public static ArrayList Split(String str, String dstr) {
		ArrayList tmpArr = null;
		String tmpStr = null;
		int prevIndex = 0;
		int currIndex = 0;
		if ( (str == null) || (dstr == null) ) {
			return null;
		}
		else {
			tmpArr = new ArrayList(16);
			if ( (str.length() == 0) || (dstr.length() == 0) ) {
				tmpArr.add(str);
			}
			else {
				while ( prevIndex != -1 ) {
					currIndex = str.indexOf(dstr, prevIndex);
					if ( currIndex == -1 ) {
						tmpArr.add( str.substring(prevIndex, str.length()) );
					}
					else {
						tmpArr.add( str.substring(prevIndex, currIndex) );
						currIndex += dstr.length();
					}
					prevIndex = currIndex;
				}
			}
		}
		return tmpArr;
	}

}
