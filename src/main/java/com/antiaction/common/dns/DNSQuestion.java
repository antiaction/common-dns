/*
 * DNS Question, dis/assembles question portions of a DNS packet.
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
 * 31-Jul-2001 : Recoded buildPacket routines. Included arrayToString debug function.
 * 01-Aug-2001 : Cleanup. Recoded disassemble routines. Javadoc.
 * 02-Aug-2001 : Renamed disassemble method, fixed javadoc.
 * 04-Aug-2001 : Fixed some javadoc. Rearranged some methods.
 *             : Renamed disassembly method.
 * 05-Aug-2001 : Added index check in disassembly, including new throws.
 * 10-Aug-2001 : Removed arrayToString method.
 * 25-Aug-2001 : Added debug method.
 *             : Expanded debug info.
 * 08-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.common.net.dns;

import com.antiaction.common.net.dns.DNSQType;
import com.antiaction.common.net.dns.DNSQClass;

/**
 * DNS Question, dis/assembles question portions of a DNS packet.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSQuestion implements Cloneable {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Question name. */
	protected String qname;
	/** Question type. */
	protected int qtype;
	/** Question class. */
	protected int qclass;

	/**
	 * Instantiate and initialize a default question object.
	 */
	public DNSQuestion() {
		qname = "";
		qtype = DNSQType.ALL;
		qclass = DNSQClass.IN;
	}

	/**
	 * Overrides Cloneable.
	 * @return a clone of this instance.
	 * @exception OutOfMemoryError if there is not enough memory.
	 * @see java.lang.Cloneable
	 */
	public Object clone() {
		DNSQuestion obj = new DNSQuestion();
		obj.qname = qname;
		obj.qtype = qtype;
		obj.qclass = qclass;
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
	 * Build and return the question based on the internal state.
	 * @param dnsname used for domain name compression in the same message.
	 * @param globalIdx current index of the message being assembled. (Domain name compression)
	 * @return the question part of the message as a byte array.
	 * @throws DNSNameException if the domain name is invalid.
	 */
	public byte[] buildPacket(DNSName dnsname, int globalIdx) throws DNSNameException {
		byte[] dnsnamepkt;
		byte[] packetData;
		int packetLen;

		if ( debug ) {
			System.out.println("-> DNSQuestion.buildPacket()");
			System.out.println("    qname: " + qname);
			System.out.println("    qtype: " + DNSQType.toString(qtype));
			System.out.println("    qclass: " + DNSQClass.toString(qclass));
		}

	// QName

		dnsname.setDebug(debug);
		dnsnamepkt = dnsname.buildPacket(globalIdx, qname, true, true);

		packetLen = dnsnamepkt.length;
		packetData = new byte[packetLen + 4];

		System.arraycopy(dnsnamepkt, 0, packetData, 0, packetLen);

	// QType

		packetData[packetLen++] = (byte)(qtype >> 8);
		packetData[packetLen++] = (byte)(qtype & 255);

	// QClass

		packetData[packetLen++] = (byte)(qclass >> 8);
		packetData[packetLen++] = (byte)(qclass & 255);

		if ( debug ) {
			System.out.println("<- DNSQuestion.buildPacket()");
		}

		return packetData;
	}

	/**
	 * Returns the length of the previously disassembled question.
	 * @return length of previously disassembled question.
	 * @see #disassemblePacket(DNSName, byte[], int, int)
	 */
	public int getDisassembledLen() {
		return disLen;
	}

	/**
	 * Parses the question part of a packet.
	 * @param dnsname used for domain name compression in the same message.
	 * @param pDat array containing the complete packet.
	 * @param pIdx index to where in the array the question begins.
	 * @param pLen length of the whole packet.
	 * @throws DNSException if the packet is corrupted.
	 * @throws DNSNameException if the domain name is invalid.
	 * @see #getDisassembledLen()
	 */
	public void disassemblePacket(DNSName dnsname, byte[] pDat, int pIdx, int pLen) throws DNSException, DNSNameException {

		if ( debug ) {
			System.out.println("-> DNSQuestion.disassemblePacket() - idx=" + pIdx);
		}

	// QName

		dnsname.setDebug(debug);
		qname = dnsname.disassemblePacket(pDat, pIdx, pLen);
		disLen = dnsname.getDisassembledLen();
		pIdx += disLen;

	// Index

		if ( (pIdx + 4) > pLen ) {
			throw new DNSException("IndexOutOfBounds.");
		}

	// QType

		qtype = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);
		disLen += 2;

	// QClass

		qclass = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);
		disLen += 2;

		if ( debug ) {
			System.out.println("    qname: " + qname);
			System.out.println("    qtype: " + DNSQType.toString(qtype));
			System.out.println("    qclass: " + DNSQClass.toString(qclass));
			System.out.println("<- DNSQuestion.disassemblePacket() - Len=" + disLen);
		}
	}

	/**
	 * Set the question domain name.
	 * @param s domain name.
	 */
	public void setQName(String s) {
		qname = s;
	}

	/**
	 * Get the question domain name.
	 * @return domain name.
	 */
	public String getQName() {
		return qname;
	}

	/**
	 * Set the question type.
	 * @param qt question type.
	 * @see com.antiaction.common.net.dns.DNSType
	 * @see com.antiaction.common.net.dns.DNSQType
	 */
	public void setQType(int qt) {
		qtype = qt;
	}

	/**
	 * Get the question type.
	 * @return question type.
	 * @see com.antiaction.common.net.dns.DNSType
	 * @see com.antiaction.common.net.dns.DNSQType
	 */
	public int getQType() {
		return qtype;
	}

	/**
	 * Set the question class.
	 * @param qc question class.
	 * @see com.antiaction.common.net.dns.DNSClass
	 * @see com.antiaction.common.net.dns.DNSQClass
	 */
	public void setQClass(int qc) {
		qclass = qc;
	}

	/**
	 * Get the question class
	 * @return question class.
	 * @see com.antiaction.common.net.dns.DNSClass
	 * @see com.antiaction.common.net.dns.DNSQClass
	 */
	public int getQClass() {
		return qclass;
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpstr = "";
		tmpstr = tmpstr + "QNAME: " + qname + "\n";
		tmpstr = tmpstr + "QTYPE: " + DNSQType.toString(qtype) + "\n";
		tmpstr = tmpstr + "QCLASS: " + DNSQClass.toString(qclass) + "\n";
		return tmpstr;
	}

}
