/*
 * DNS WKS Record container.
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
 * 29-Aug-2001 : Cloned DNSRDataA.
 * 31-Aug-2001 : Expanded buildPacket(), toString().
 * 02-Sep-2001 : Expanded disassemblePacket().
 * 09-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 * 22-Nov-2001 : Fixed buildPacket() ipaddr overwrite.
 *
 * Todo:
 *
 *   Bitset seems to align to 64bit.. not a bug just annoying.
 *
 */

package com.antiaction.common.dns.record;

import java.util.ArrayList;
import java.util.BitSet;

import com.antiaction.common.dns.DNSName;
import com.antiaction.common.dns.DNSNameException;
import com.antiaction.common.dns.DNSType;

/**
 * DNS WKS Record container.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRDataWKS implements DNSRDataInterface {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Record of type WKS. */
	protected static int rtype = DNSType.WKS;
	/** IP record. */
	protected byte[] ipAddrArr;
	/** IP address. */
	protected String ipAddr;
	/** Protocol. */
	protected byte protocol;
	/** Bitmap. */
	protected BitSet bitmap;

	/**
	 * Instantiate and initialize a default WKS record object.
	 */
	public DNSRDataWKS() {
		ipAddrArr = new byte[4];
		ipAddr = "0.0.0.0";
		protocol = 0;
		bitmap = new BitSet(0);
	}

 	/**
 	 * Overrides Cloneable.
 	 * @return a clone of this instance.
 	 * @exception OutOfMemoryError if there is not enough memory.
 	 * @see java.lang.Cloneable
 	 */
 	public Object clone() {
 		DNSRDataWKS obj = new DNSRDataWKS();
		obj.ipAddrArr = (byte[])ipAddrArr.clone();
		obj.ipAddr = ipAddr;
		obj.protocol = protocol;
		obj.bitmap = (BitSet)bitmap.clone();
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
		int mapBytes;
		int count;
		int shift;

		if ( debug ) {
			System.out.println("-> DNSRDataWKS.buildPacket()");
			System.out.println("    ipAddr: " + ipAddr);
			System.out.println("    protocol: " + protocol);
			for (int i=0; i<bitmap.size(); i++) {
				if ( bitmap.get(i) ) {
					System.out.println("     " + i);
				}
			}
		}

		mapBytes = (bitmap.size() + 7) / 8;

		packetLen = 0;
		RDLen = ipAddrArr.length + 1 + mapBytes;

		packetData = new byte[2 + RDLen];

	// RDLen

		packetData[packetLen++] = (byte)(RDLen >> 8);
		packetData[packetLen++] = (byte)(RDLen & 255);

	// IP

		System.arraycopy(ipAddrArr, 0, packetData, packetLen, ipAddrArr.length);
		packetLen += ipAddrArr.length;

	// Protocol

		packetData[packetLen++] = (byte)(protocol & 255);

	// Bit Map

		count = 0;
		for(int i=0; i<mapBytes; i++) {
			packetData[packetLen] = 0;
			shift = 128;
			for(int j=0; j<8; j++) {
				if ( count < bitmap.size() ) {
					if ( bitmap.get(count++) ) {
						packetData[packetLen] |= shift;
					}
					shift >>= 1;
				}
			}
			packetLen++;
		}

		if ( debug ) {
			System.out.println("<- DNSRDataWKS.buildPacket()");
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
		int mapBytes;
		int tmp;
		int count;
		int shift;

		if ( debug ) {
			System.out.println("-> DNSRDataWKS.disassemblePacket() - idx=" + pIdx);
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

		if ( RDLen < 5 ) {
			throw new DNSRDataException("Invalid WKS Record.");
		}

	// IP

		ipAddr = "";
		for(int i=0; i<4; i++) {
			ipAddrArr[i] = pDat[pIdx++];
			if ( ipAddr.length() > 0 ) {
				ipAddr += ".";
			}
			ipAddr += ipAddrArr[i]&255;
		}

	// Protocol

		protocol = (byte)(pDat[pIdx++] & 255);

	// Bit Map

		mapBytes = RDLen - 5;
		bitmap = new BitSet(mapBytes * 8);

		count = 0;
		for(int i=0; i<mapBytes; i++) {
			tmp = pDat[pIdx++];
			shift = 128;
			for(int j=0; j<8; j++) {
				if ( (tmp & shift) != 0 ) {
					bitmap.set(count);
				}
				shift >>= 1;
				count++;
			}
		}

		if ( debug ) {
			System.out.println("    ipAddr: " + ipAddr);
			System.out.println("    protocol: " + protocol);
			for (int i=0; i<bitmap.size(); i++) {
				if ( bitmap.get(i) ) {
					System.out.println("     " + i);
				}
			}
			System.out.println("<- DNSRDataWKS.disassemblePacket() - Len=" + disLen);
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
	 * Set the protocol type of this record.
	 * @param pr protocol type number.
	 */
	public void setProtocol(byte pr) {
		protocol = pr;
	}

	/**
	 * Get the protocol type of this record.
	 * @return the protocol type number.
	 */
	public byte getProtocol() {
		return protocol;
	}

	/**
	 * Set the bitmap of this record.
	 * @param bs service bitmap.
	 */
	public void setBitMap(BitSet bs) {
		bitmap = (BitSet)bs.clone();
	}

	/**
	 * Get the bitmap of this record.
	 * @return service bitmap.
	 */
	public BitSet getBitMap() {
		return (BitSet)bitmap.clone();
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "WKS record.\n";
		tmpStr += "ip: " + ipAddr + "\n";
		tmpStr += "protocol: " + protocol + "\n";
		for (int i=0; i<bitmap.size(); i++) {
			if ( bitmap.get(i) ) {
				tmpStr += " " + i + "\n";
			}
		}
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
