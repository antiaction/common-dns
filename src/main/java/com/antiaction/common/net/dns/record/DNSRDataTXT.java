/*
 * DNS TXT Record container.
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
 * 29-Aug-2001 : First implementation. {
 *             : }
 * 09-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 * 22-Nov-2001 : buildPacket() RDLen +2 offset error.
 *
 */

package com.antiaction.dns.record;

import com.antiaction.dns.DNSType;
import com.antiaction.dns.DNSName;
import com.antiaction.dns.DNSNameException;

import java.util.ArrayList;

/**
 * DNS TXT Record container.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRDataTXT implements DNSRDataInterface {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Record of type TXT. */
	protected static int rtype = DNSType.TXT;
	/** Text array. */
	protected ArrayList txt;

	/**
	 * Instantiate and initialize a default TXT record object.
	 */
	public DNSRDataTXT() {
		txt = new ArrayList();
	}

 	/**
 	 * Overrides Cloneable.
 	 * @return a clone of this instance.
 	 * @exception OutOfMemoryError if there is not enough memory.
 	 * @see java.lang.Cloneable
 	 */
 	public Object clone() {
 		DNSRDataTXT obj = new DNSRDataTXT();
		obj.txt = (ArrayList)txt.clone();
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
		String tmpStr;
		byte[] tmpArr;

		if ( debug ) {
			System.out.println("-> DNSRDataTXT.buildPacket()");
			for(int i=0; i<txt.size(); i++) {
				System.out.println("    txt: " + (String)txt.get(i));
			}
		}

		packetLen = 0;
		RDLen = 0;

		for(int i=0; i<txt.size(); i++) {
			RDLen += 1 + ((String)txt.get(i)).length();
		}

		packetData = new byte[2+RDLen];

	// RDLen

		packetData[packetLen++] = (byte)(RDLen >> 8);
		packetData[packetLen++] = (byte)(RDLen & 255);

	// RData(TXT)

		for(int i=0; i<txt.size(); i++) {
			tmpStr = (String)txt.get(i);
			tmpArr = tmpStr.getBytes();
			packetData[packetLen++] = (byte)(tmpArr.length & 255);
			System.arraycopy(tmpArr, 0, packetData, packetLen, tmpArr.length);
			packetLen += tmpArr.length;
		}

		if ( debug ) {
			for(int i=0; i<txt.size(); i++) {
				System.out.println("    txt: " + (String)txt.get(i));
			}
			System.out.println("<- DNSRDataTXT.buildPacket()");
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
		boolean b;
		int len;

		txt = new ArrayList();

		if ( debug ) {
			System.out.println("-> DNSRDataTXT.disassemblePacket() - idx=" + pIdx);
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

	// RData(TXT)

		sIdx = pIdx;
		b = true;

		while ( b ) {
			if ( (pIdx - sIdx) == RDLen ) {
				b = false;
			}
			else {
				len = (pDat[pIdx++] & 255);
				if ( ((pIdx - sIdx) + len) > RDLen ) {
					throw new DNSRDataException("RecordOutOfBounds.");
				}
				txt.add(new String(pDat, pIdx, len));
				pIdx += len;
			}
		}

		if ( debug ) {
			for(int i=0; i<txt.size(); i++) {
				System.out.println("    txt: " + (String)txt.get(i));
			}
			System.out.println("<- DNSRDataTXT.disassemblePacket() - Len=" + disLen);
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
	 * Set the text as an array of strings.
	 * @param txt array of text lines.
	 * @throws DNSRDataException if a text line is too long.
	 */
	public void setTXT(ArrayList txt) throws DNSRDataException {
		for(int i=0; i<txt.size(); i++) {
			if ( ((String)txt.get(i)).length() > 255 ) {
				throw new DNSRDataException("Text line too long.");
			}
		}
		this.txt = (ArrayList)txt.clone();
	}

	/**
	 * Get the text as an array of strings.
	 * @return array of strings.
	 */
	public ArrayList getTXT() {
		return (ArrayList)txt.clone();
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "TXT record.\n";
			for(int i=0; i<txt.size(); i++) {
				tmpStr += " txt: " + (String)txt.get(i) + "\n";
			}
		return tmpStr;
	}

}
