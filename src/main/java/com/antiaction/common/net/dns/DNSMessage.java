/*
 * DNS Message, main entry point for dis/assembling DNS packets.
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
 * 08-Aug-2001 : Minor cleanup, uncommented most of the code, get/set javadoc. Init.
 * 09-Aug-2001 : Question get/set, fields javadoc.
 *             : Recoded buildPacket routine. Removed old code.
 *             : Implemented assemblePacket.
 * 10-Aug-2001 : Recoded disassemblePacket routine.
 *             : Recoded toString().
 *             : Moved arrayToString method to this class.
 *             : NullPointer check if header object missing.
 * 11-Aug-2001 : Set header count fields. Javadoc fix.
 * 24-Aug-2001 : Fixed null dnsheader in disassemblePacket.
 * 25-Aug-2001 : Added debug method.
 *             : Expanded debug info.
 * 27-Aug-2001 : Changed RData disAsm to non static, changed dependencies.
 * 13-Sep-2001 : Changed arrayToString methods to not print non ascii characters.
 * 09-Oct-2001 : Get/Set clones the Header objects.
 *             : Add/Get/Set clones Question objects and lists.
 *             : Add/Get/Set clones Record objects and lists.
 * 10-Oct-2001 : Recoded getQuestions, merged the two versions into one, and it now clones the objects.
 * 10-Oct-2001 : Recoded getRecords, merged the two versions into one, and it now clones the objects.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.common.net.dns;

import com.antiaction.common.net.dns.record.DNSRDataInterface;
import com.antiaction.common.net.dns.record.DNSRData;
import com.antiaction.common.net.dns.record.DNSRDataException;

import java.util.ArrayList;
import java.util.Iterator;

/**
 * DNS Message, main entry point for dis/assembling DNS packets.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSMessage {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** DNS Header object. */
	protected DNSHeader dnsheader;

	/** DNS RData builder. */
	protected DNSRData dnsrdatabuilder;

	/** DNS Name object used for domain name de/encoding. */
	protected DNSName dnsname;

	/** Array of DNS Question objects. */
	protected ArrayList qd_array;
	/** Array of answer DNS Record objects. */
	protected ArrayList an_array;
	/** Array of authority DNS Record objects. */
	protected ArrayList ns_array;
	/** Array of additional DNS Record objects. */
	protected ArrayList ar_array;

	/** Array of partial packet byte arrays. */
	protected ArrayList arrPackets;

	/**
	 * Instantiate a new message object.
	 */
	public DNSMessage() {
		dnsheader = new DNSHeader();
		dnsrdatabuilder = new DNSRData();
		dnsname = new DNSName();
		reset();
	}

	/**
	 * Reset the objects internal state.
	 */
	public void reset() {
		qd_array = new ArrayList();
		an_array = new ArrayList();
		ns_array = new ArrayList();
		ar_array = new ArrayList();
		dnsname.reset();
	}

	/**
	 * Toggle debug status.
	 * @param b boolean.
	 */
	public void setDebug(boolean b) {
		debug = b;
	}

	/**
	 * Builds the packet internally, use assemblePacket to return a fully built packet.
	 * @throws DNSNameException if the domain name is invalid.
	 * @see #assemblePacket()
	 */
	public void buildPacket() throws DNSNameException {
		byte[] pDat;
		int pIdx;
		DNSQuestion dnsquestion;
		DNSRecord dnsrecord;

		if ( debug ) {
			System.out.println("-> DNSMessage.buildPacket()");
		}

		arrPackets = new ArrayList();

		pIdx = DNSHeader.HEADER_SIZE;

	// Questions

		for(int i=0; i<qd_array.size(); i++) {
			dnsquestion = (DNSQuestion)qd_array.get(i);
			dnsquestion.setDebug(debug);
			pDat = dnsquestion.buildPacket(dnsname, pIdx);
			arrPackets.add(pDat);
			pIdx += pDat.length;
		}

	// Answers

		for(int i=0; i<an_array.size(); i++) {
			dnsrecord = (DNSRecord)an_array.get(i);
			dnsrecord.setDebug(debug);
			pDat = dnsrecord.getHeader().buildPacket(dnsname, pIdx);
			arrPackets.add(pDat);
			pIdx += pDat.length;
			pDat = dnsrecord.getRData().buildPacket(dnsname, pIdx);
			arrPackets.add(pDat);
			pIdx += pDat.length;
		}

	// Authorities

		for(int i=0; i<ns_array.size(); i++) {
			dnsrecord = (DNSRecord)ns_array.get(i);
			dnsrecord.setDebug(debug);
			pDat = dnsrecord.getHeader().buildPacket(dnsname, pIdx);
			arrPackets.add(pDat);
			pIdx += pDat.length;
			pDat = dnsrecord.getRData().buildPacket(dnsname, pIdx);
			arrPackets.add(pDat);
			pIdx += pDat.length;
		}

	// Additionals

		for(int i=0; i<ar_array.size(); i++) {
			dnsrecord = (DNSRecord)ar_array.get(i);
			dnsrecord.setDebug(debug);
			pDat = dnsrecord.getHeader().buildPacket(dnsname, pIdx);
			arrPackets.add(pDat);
			pIdx += pDat.length;
			pDat = dnsrecord.getRData().buildPacket(dnsname, pIdx);
			arrPackets.add(pDat);
			pIdx += pDat.length;
		}

		if ( debug ) {
			System.out.println("<- DNSMessage.buildPacket()");
		}
	}

	/**
	 * Returns a fully assembled message packet.
	 * @return message packet.
	 * @see #buildPacket()
	 */
	public byte[] assemblePacket() throws DNSException {
		byte[] packetData;
		byte[] pDat;
		int pIdx;
		int pLen;

		if ( debug ) {
			System.out.println("-> DNSMessage.assemblePacket()");
		}

		if ( dnsheader == null ) {
			throw new DNSException("No header assigned.");
		}

		dnsheader.setQuestionCount( qd_array.size() );
		dnsheader.setAnswerCount( an_array.size() );
		dnsheader.setAuthorityCount( ns_array.size() );
		dnsheader.setAdditionalCount( ar_array.size() );

		pIdx = 0;
		pLen = DNSHeader.HEADER_SIZE;

		for(int i=0; i<arrPackets.size(); i++) {
			pDat = (byte[])arrPackets.get(i);
			pLen += pDat.length;
		}

		packetData = new byte[pLen];

		dnsheader.setDebug(debug);
		pDat = dnsheader.buildPacket();
		System.arraycopy(pDat, 0, packetData, pIdx, pDat.length);
		pIdx += pDat.length;

		for(int i=0; i<arrPackets.size(); i++) {
			pDat = (byte[])arrPackets.get(i);
			System.arraycopy(pDat, 0, packetData, pIdx, pDat.length);
			pIdx += pDat.length;
		}

		if ( debug ) {
			System.out.println("<- DNSMessage.assemblePacket()");
		}

		return packetData;
	}

	/**
	 * Returns the length of the previously disassembled record header.
	 * @return length of previously disassembled message.
	 * @see #disassemblePacket(byte[])
	 */
	public int getDisassembledLen() {
		return disLen;
	}

	/**
	 * Parses the record header part of a packet.
	 * @param pDat array containing the complete packet.
	 * @throws DNSException if the packet is corrupted.
	 * @throws DNSNameException if the domain name is invalid.
	 * @throws DNSRDataException if the rdata packet is corrupted.
	 * @see #getDisassembledLen()
	 */
	public void disassemblePacket(byte[] pDat) throws DNSException, DNSNameException, DNSRDataException {
		DNSQuestion dnsquestion;
		DNSRecordHeader dnsrecordheader;
		DNSRDataInterface dnsrdata;
		DNSRecord dnsrecord;

		int count;

		int pIdx;
		int pLen;

		pIdx = 0;
		pLen = pDat.length;

		if ( debug ) {
			System.out.println("-> DNSMessage.disassemblePacket() - idx=" + pIdx);
		}

	// Reset

		reset();

	// Header

		dnsheader.setDebug(debug);
		dnsheader.disassemblePacket(pDat, pIdx, pLen);
		pIdx += dnsheader.getDisassembledLen();

		dnsrdatabuilder.setDebug(debug);

	// Questions

		count = dnsheader.getQuestionCount();

		for(int i=0; i<count; i++) {
			dnsquestion = new DNSQuestion();
			dnsquestion.setDebug(debug);
			dnsquestion.disassemblePacket(dnsname, pDat, pIdx, pLen);
			pIdx += dnsquestion.getDisassembledLen();

			qd_array.add(dnsquestion);
		}

	// Answers

		count = dnsheader.getAnswerCount();

		for(int i=0; i<count; i++) {
			dnsrecordheader = new DNSRecordHeader();
			dnsrecordheader.setDebug(debug);
			dnsrecordheader.disassemblePacket(dnsname, pDat, pIdx, pLen);
			pIdx += dnsrecordheader.getDisassembledLen();

			dnsrdata = dnsrdatabuilder.disassemblePacket(dnsname, pDat, pIdx, pLen, dnsrecordheader);
			pIdx += dnsrdata.getDisassembledLen();

			dnsrecord = new DNSRecord(dnsrecordheader, dnsrdata);
			an_array.add(dnsrecord);
		}

	// Authority

		count = dnsheader.getAuthorityCount();

		for(int i=0; i<count; i++) {
			dnsrecordheader = new DNSRecordHeader();
			dnsrecordheader.setDebug(debug);
			dnsrecordheader.disassemblePacket(dnsname, pDat, pIdx, pLen);
			pIdx += dnsrecordheader.getDisassembledLen();

			dnsrdata = dnsrdatabuilder.disassemblePacket(dnsname, pDat, pIdx, pLen, dnsrecordheader);
			pIdx += dnsrdata.getDisassembledLen();

			dnsrecord = new DNSRecord(dnsrecordheader, dnsrdata);
			ns_array.add(dnsrecord);
		}

	// Additional

		count = dnsheader.getAdditionalCount();

		for(int i=0; i<count; i++) {
			dnsrecordheader = new DNSRecordHeader();
			dnsrecordheader.setDebug(debug);
			dnsrecordheader.disassemblePacket(dnsname, pDat, pIdx, pLen);
			pIdx += dnsrecordheader.getDisassembledLen();

			dnsrdata = dnsrdatabuilder.disassemblePacket(dnsname, pDat, pIdx, pLen, dnsrecordheader);
			pIdx += dnsrdata.getDisassembledLen();

			dnsrecord = new DNSRecord(dnsrecordheader, dnsrdata);
			ar_array.add(dnsrecord);
		}

		disLen = pIdx;

		if ( debug ) {
			System.out.println("<- DNSMessage.disassemblePacket() - Len=" + disLen);
		}
	}

	/**
	 * Set a copy of the message header object.
	 * @param header header object.
	 */
	public void setHeader(DNSHeader header) {
		dnsheader = (DNSHeader)header.clone();
	}

	/**
	 * Get a copy of the message header object.
	 * @return header object.
	 */
	public DNSHeader getHeader() {
		return (DNSHeader)dnsheader.clone();
	}

	/**
	 * Add a copy of the question to the list of questions.
	 * @param qst question object.
	 */
	public void addQuestion(DNSQuestion qst) {
		qd_array.add( (DNSQuestion)qst.clone() );
	}

	/**
	 * Get a copy of the list of question objects.
	 * @return list of question objects.
	 */
	public ArrayList getQuestions() {
		ArrayList tmpArr = new ArrayList();
		Iterator iter = qd_array.iterator();
		DNSQuestion tmpQst;

		while ( iter.hasNext() ) {
			tmpQst = (DNSQuestion)iter.next();
			tmpArr.add( (DNSQuestion)tmpQst.clone() );
		}
		return tmpArr;
	}

	/**
	 * Set a copy of the list of question objects.
	 * @param qArr list of question objects.
	 */
	public void setQuestions(ArrayList qArr) {
		qd_array = new ArrayList();
		Iterator iter = qArr.iterator();
		DNSQuestion tmpQst;

		while ( iter.hasNext() ) {
			tmpQst = (DNSQuestion)iter.next();
			qd_array.add( (DNSQuestion)tmpQst.clone() );
		}
	}

	/**
	 * Add an answer record to the message.
	 * @param rec record container object.
	 */
	public void addAnswer(DNSRecord rec) {
		an_array.add( (DNSRecord)rec.clone() );
	}

	/**
	 * Get a copy of the list of answer record objects.
	 * @return list of answer record objects.
	 */
	public ArrayList getAnswers() {
		ArrayList tmpArr = new ArrayList();
		Iterator iter = an_array.iterator();
		DNSRecord tmpRec;

		while ( iter.hasNext() ) {
			tmpRec = (DNSRecord)iter.next();
			tmpArr.add( (DNSRecord)tmpRec.clone() );
		}
		return tmpArr;
	}

	/**
	 * Set a copy of the list of answer record objects.
	 * @param qArr list of answer record objects.
	 */
	public void setAnswers(ArrayList qArr) {
		an_array = new ArrayList();
		Iterator iter = qArr.iterator();
		DNSRecord tmpRec;

		while ( iter.hasNext() ) {
			tmpRec = (DNSRecord)iter.next();
			an_array.add( (DNSRecord)tmpRec.clone() );
		}
	}

	/**
	 * Add an authority record to the message.
	 * @param rec record container object.
	 */
	public void addAuthority(DNSRecord rec) {
		ns_array.add( (DNSRecord)rec.clone() );
	}

	/**
	 * Get a copy of the list of authority record objects.
	 * @return list of authority record objects.
	 */
	public ArrayList getAuthorities() {
		ArrayList tmpArr = new ArrayList();
		Iterator iter = ns_array.iterator();
		DNSRecord tmpRec;

		while ( iter.hasNext() ) {
			tmpRec = (DNSRecord)iter.next();
			tmpArr.add( (DNSRecord)tmpRec.clone() );
		}
		return tmpArr;
	}

	/**
	 * Set a copy of the list of authority record objects.
	 * @param qArr list of authority record objects.
	 */
	public void setAuthorities(ArrayList qArr) {
		ns_array = new ArrayList();
		Iterator iter = qArr.iterator();
		DNSRecord tmpRec;

		while ( iter.hasNext() ) {
			tmpRec = (DNSRecord)iter.next();
			ns_array.add( (DNSRecord)tmpRec.clone() );
		}
	}

	/**
	 * Add an additional record to the message.
	 * @param rec record container object.
	 */
	public void addAdditional(DNSRecord rec) {
		ar_array.add( (DNSRecord)rec.clone() );
	}

	/**
	 * Get a copy of the list of additional record objects.
	 * @return list of additional record objects.
	 */
	public ArrayList getAdditionals() {
		ArrayList tmpArr = new ArrayList();
		Iterator iter = ar_array.iterator();
		DNSRecord tmpRec;

		while ( iter.hasNext() ) {
			tmpRec = (DNSRecord)iter.next();
			tmpArr.add( (DNSRecord)tmpRec.clone() );
		}
		return tmpArr;
	}

	/**
	 * Set a copy of the list of authority record objects.
	 * @param qArr list of authority record objects.
	 */
	public void setAdditionals(ArrayList qArr) {
		ar_array = new ArrayList();
		Iterator iter = qArr.iterator();
		DNSRecord tmpRec;

		while ( iter.hasNext() ) {
			tmpRec = (DNSRecord)iter.next();
			ar_array.add( (DNSRecord)tmpRec.clone() );
		}
	}

	/**
	 * Get a copy of the Question objects that match the given arguments.
	 * @param qname Question hostname. (* equals all hostnames)
	 * @param qtype Query Type.
	 * @param qclass Query Class.
	 * @return a list of Question objects.
	 * @see com.antiaction.common.net.dns.DNSType
	 * @see com.antiaction.common.net.dns.DNSQType
	 * @see com.antiaction.common.net.dns.DNSClass
	 * @see com.antiaction.common.net.dns.DNSQClass
	 */
	public ArrayList getQuestions(String qname, int qtype, int qclass) {
		ArrayList tmpArr = new ArrayList();
		DNSQuestion tmpQst;
		int tmptype;
		int tmpclass;

		if ( !qd_array.isEmpty() ) {
			for(int i=0; i<qd_array.size(); i++) {
				tmpQst = (DNSQuestion)qd_array.get(i);
				if ( (qname.equalsIgnoreCase( tmpQst.getQName() )) || (qname.equalsIgnoreCase("*")) ) {
					if ( (qtype == tmpQst.getQType()) || (qtype == DNSQType.ALL) ) {
						if ( (qclass == tmpQst.getQClass()) || (qclass == DNSQClass.ALL) ) {
							tmpArr.add( (DNSQuestion)tmpQst.clone() );
						}
					}
				}
			}
		}
		return tmpArr;
	}

	/**
	 * Get a copy of the Record objects that match the given arguments.
	 * @param qname Question hostname. (* equals all hostnames)
	 * @param rtype Section Type
	 * @param qtype Query Type.
	 * @param qclass Query Class.
	 * @return a list of Record objects.
	 * @see com.antiaction.common.net.dns.DNSSectionType
	 * @see com.antiaction.common.net.dns.DNSType
	 * @see com.antiaction.common.net.dns.DNSQType
	 * @see com.antiaction.common.net.dns.DNSClass
	 * @see com.antiaction.common.net.dns.DNSQClass
	 */
	public ArrayList getRecords(String qname, int stype, int qtype, int qclass) {
		ArrayList tmpArr = new ArrayList();
		DNSRecord tmpRec;
		DNSRecordHeader tmpHeader;

		if ( (stype == DNSSectionType.ANSWER) || (stype == DNSSectionType.ALL) ) {
			if ( !an_array.isEmpty() ) {
				for(int i=0; i<an_array.size(); i++) {
					tmpRec = (DNSRecord)an_array.get(i);
					tmpHeader = tmpRec.getHeader();
					if ( (qname.equalsIgnoreCase( tmpHeader.getRName() )) || (qname.equalsIgnoreCase("*")) ) {
						if ( (qtype == tmpHeader.getRType()) || (qtype == DNSQType.ALL) ) {
							if ( (qclass == tmpHeader.getRClass()) || (qclass == DNSQClass.ALL) ) {
								tmpArr.add( (DNSRecord)tmpRec.clone() );
							}
						}
					}
				}
			}
		}

		if ( (stype == DNSSectionType.AUTHORITY) || (stype == DNSSectionType.ALL) ) {
			if ( !ns_array.isEmpty() ) {
				for(int i=0; i<ns_array.size(); i++) {
					tmpRec = (DNSRecord)ns_array.get(i);
					tmpHeader = tmpRec.getHeader();
					if ( (qname.equalsIgnoreCase( tmpHeader.getRName() )) || (qname.equalsIgnoreCase("*")) ) {
						if ( (qtype == tmpHeader.getRType()) || (qtype == DNSQType.ALL) ) {
							if ( (qclass == tmpHeader.getRClass()) || (qclass == DNSQClass.ALL) ) {
								tmpArr.add( (DNSRecord)tmpRec.clone() );
							}
						}
					}
				}
			}
		}

		if ( (stype == DNSSectionType.ADDITIONAL) || (stype == DNSSectionType.ALL) ) {
			if ( !ar_array.isEmpty() ) {
				for(int i=0; i<ar_array.size(); i++) {
					tmpRec = (DNSRecord)ar_array.get(i);
					tmpHeader = tmpRec.getHeader();
					if ( (qname.equalsIgnoreCase( tmpHeader.getRName() )) || (qname.equalsIgnoreCase("*")) ) {
						if ( (qtype == tmpHeader.getRType()) || (qtype == DNSQType.ALL) ) {
							if ( (qclass == tmpHeader.getRClass()) || (qclass == DNSQClass.ALL) ) {
								tmpArr.add( (DNSRecord)tmpRec.clone() );
							}
						}
					}
				}
			}
		}

		return tmpArr;
	}

	/**
	 * Returns the upper byte of the 16 bit portion of the integer.
	 * @param i integer.
	 * @return upper byte.
	 */
	private byte upperByte(int i) {
		return (byte)(i >> 8);
	}

	/**
	 * Returns the lower byte of the 16 bit portion of the integer.
	 * @param i integer.
	 * @return lower byte.
	 */
	private byte lowerByte(int i) {
		return (byte)(i & 255);
	}

	/**
	 * Converts a boolean to an interger.
	 * @param b boolean.
	 * @return <CODE>0</CODE> or <CODE>1</CODE>.
	 */
	private int b2i(boolean b) {
		if (b)
			return 1;
		else
			return 0;
	}

	/**
	 * Converts an integer to a boolean, zero returns <CODE>false</CODE>, everything else returns <CODE>true</CODE>.
	 * @param i integer.
	 * @return boolean.
	 */
	private boolean i2b(int i) {
		return ( (i & 1) != 0);
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		DNSRecord dnsrecord;

		String tmpStr = "";
		tmpStr += "Message\n";

	// Header

		tmpStr += dnsheader.toString();

	// Question

		tmpStr += "qd_Array\n";
		tmpStr += "--------\n";
		for(int i=0;i<qd_array.size(); i++) {
			tmpStr += ((DNSQuestion)qd_array.get(i)).toString();
		}

	// Answer

		tmpStr += "an_Array\n";
		tmpStr += "--------\n";
		for(int i=0; i<an_array.size(); i++) {
			dnsrecord = (DNSRecord)an_array.get(i);
			tmpStr += dnsrecord.getHeader().toString();
			tmpStr += dnsrecord.getRData().toString();
		}

	// Authority

		tmpStr += "ns_Array\n";
		tmpStr += "--------\n";
		for(int i=0; i<ns_array.size(); i++) {
			dnsrecord = (DNSRecord)ns_array.get(i);
			tmpStr += dnsrecord.getHeader().toString();
			tmpStr += dnsrecord.getRData().toString();
		}

	// Additional

		tmpStr += "ar_Array\n";
		tmpStr += "--------\n";
		for(int i=0; i<ar_array.size(); i++) {
			dnsrecord = (DNSRecord)ar_array.get(i);
			tmpStr += dnsrecord.getHeader().toString();
			tmpStr += dnsrecord.getRData().toString();
		}

		return tmpStr;
	}

	/**
	 * Returns a string representation of the array, for debugging purposes.
	 * @param pDat byte array.
	 * @return debug string.
	 * @see #arrayToString(byte[], int, int)
	 */
	public static String arrayToString(byte[] pDat) {
		String tmpStr;
		if ( pDat == null )
			return "Null pointer.\n";

		tmpStr = "";
		for(int i=0; i<pDat.length; i++) {
			tmpStr += ((int)pDat[i]&255) + " - ";
			if ( Character.isLetter( (char)((int)pDat[i]&255) ) ) {
				tmpStr += (char)((int)pDat[i]&255);
			}
			tmpStr += "\n";
		}
		return tmpStr;
	}

	/**
	 * Returns a string representation of the array, for debugging purposes.
	 * @param pDat byte array.
	 * @param pIdx index to where in the array to begin displaying from.
	 * @param pLen bytes to display.
	 * @return debug string.
	 * @see #arrayToString(byte[])
	 */
	public static String arrayToString(byte[] pDat, int pIdx, int pLen) {
		String tmpStr;
		if ( pDat == null )
			return "Null pointer.\n";

		tmpStr = "";
		for(int i=0; i<pLen; i++) {
			tmpStr += ((int)pDat[pIdx]&255) + " - ";
			if ( Character.isLetter( (char)((int)pDat[i]&255) ) ) {
				tmpStr += (char)((int)pDat[pIdx]&255);
			}
			tmpStr += "\n";
			pIdx++;
		}
		return tmpStr;
	}

	/**
	 * Returns a string representation of the array, for debugging purposes.
	 * @param pDat byte array.
	 * @return debug string.
	 * @see #arrayToString(byte[], int, int)
	 */
	public static String arrayToStringIndex(byte[] pDat) {
		String tmpStr;
		int index = 0;
		if ( pDat == null )
			return "Null pointer.\n";

		tmpStr = "";
		for(int i=0; i<pDat.length; i++) {
			tmpStr += index + ": " + ((int)pDat[i]&255) + " - ";
			if ( Character.isLetter( (char)((int)pDat[i]&255) ) ) {
				tmpStr += (char)((int)pDat[i]&255);
			}
			tmpStr += "\n";
			index++;
		}
		return tmpStr;
	}

}
