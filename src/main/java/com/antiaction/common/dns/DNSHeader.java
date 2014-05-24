/*
 * DNS header container, contains the header portion of a DNS message.
 * Copyright (C) 2000, 2001, 2005  Nicholas Clarke
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
 * 18-Jul-2001 : First implemenation.
 * 20-Jul-2001 : Javadoc.
 * 21-Jul-2001 : Added some debug functions to convert byte arrays to strings.
 * 22-Jul-2001 : Moved packedData to build method.
 * 04-Aug-2001 : Fixed some javadoc.
 *             : Renamed disassembly method.
 * 05-Aug-2001 : Index check changed to DNSException throws.
 * 10-Aug-2001 : Removed arrayToString methods.
 * 25-Aug-2001 : Expanded debug info.
 * 06-Oct-2001 : Minor renames.
 * 09-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 * 04-Mar-2005 : Fixed javadoc.
 *
 */

package com.antiaction.common.net.dns;

import com.antiaction.common.net.dns.DNSOpcode;
import com.antiaction.common.net.dns.DNSResponseCode;

/**
 * DNS header container, contains the header portion of a DNS message.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSHeader implements Cloneable {

	/** Header size. */
	public static final int HEADER_SIZE = 6*2;

	/** Message identifier. */
	private int identifier;
	/** Query or Response message. */
	private int queryResponse;
	/** Opcode. */
	private int opcode;
	/** Is answer authoritative. */
	private boolean authoritativeAnswer;
	/** Was message truncated. */
	private boolean trunCation;
	/** Is recursion desired. */
	private boolean recursionDesired;
	/** Is recursion available. */
	private boolean recursionAvailable;
	/** Response code. */
	private int responseCode;

	/** Number of questions. */
	private int questionCount;
	/** Number of answer resource records. */
	private int answerCount;
	/** Number of authority resource records. */
	private int authorityCount;
	/** Number of additional resource records. */
	private int additionalCount;

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Query header type. */
	public static final int Query = 0;
	/** Response header type. */
	public static final int Response = 1;

	/**
	 * Instantiate and initialize a default header object.
	 */
	public DNSHeader() {
		identifier = 1;
		queryResponse = 0;
		opcode = DNSOpcode.QUERY;
		authoritativeAnswer = false;
		trunCation = false;
		recursionDesired = true;
		recursionAvailable = false;
		responseCode = DNSResponseCode.NOERROR;

		questionCount = 0;
		answerCount = 0;
		authorityCount = 0;
		additionalCount = 0;
	}

	/**
	 * Overrides Cloneable.
	 * @return a clone of this instance.
	 * @exception OutOfMemoryError if there is not enough memory.
	 * @see java.lang.Cloneable
	 */
	public Object clone() {
		DNSHeader obj = new DNSHeader();
		obj.identifier = identifier;
		obj.queryResponse = queryResponse;
		obj.opcode = opcode;
		obj.authoritativeAnswer = authoritativeAnswer;
		obj.trunCation = trunCation;
		obj.recursionDesired = recursionDesired;
		obj.recursionAvailable = recursionAvailable;
		obj.responseCode = responseCode;

		obj.questionCount = questionCount;
		obj.answerCount = answerCount;
		obj.authorityCount = authorityCount;
		obj.additionalCount = additionalCount;

		obj.disLen = disLen;
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
	 * Build and return the header based on the internal state.
	 * @return the header part of the message as a byte array.
	 */
	public byte[] buildPacket() {
		byte[] packetData;
		int packetLen;
		int field;

		if ( debug ) {
			System.out.println("-> DNSHeader.buildPacket()");
		}

		packetData = new byte[HEADER_SIZE];
		packetLen = 0;

		// Fields

		field = 0;
		field = field | ((queryResponse & 1) << 15);
		field = field | (opcode << 11);
		field = field | (b2i(authoritativeAnswer) << 10);
		field = field | (b2i(trunCation) << 9);
		field = field | (b2i(recursionDesired) << 8);
		field = field | (b2i(recursionAvailable) << 7);
		field = field | (responseCode << 0);

		// Id

		packetData[packetLen++] = (byte)(identifier >> 8);
		packetData[packetLen++] = (byte)(identifier & 255);

		// Fields

		packetData[packetLen++] = (byte)(field >> 8);
		packetData[packetLen++] = (byte)(field & 255);

		// QDCount

		packetData[packetLen++] = (byte)(questionCount >> 8);
		packetData[packetLen++] = (byte)(questionCount & 255);

		// ANCount

		packetData[packetLen++] = (byte)(answerCount >> 8);
		packetData[packetLen++] = (byte)(answerCount & 255);

		// NSCount

		packetData[packetLen++] = (byte)(authorityCount >> 8);
		packetData[packetLen++] = (byte)(authorityCount & 255);

		// ARCount

		packetData[packetLen++] = (byte)(additionalCount >> 8);
		packetData[packetLen++] = (byte)(additionalCount & 255);

		// Packet

		if ( debug ) {
			System.out.println("<- DNSHeader.buildPacket()");
		}

		return packetData;
	}

	/**
	 * Returns the length of the previously disassembled header.
	 * @return length of previously disassembled header.
	 * @see #disassemblePacket(byte[], int, int)
	 */
	public int getDisassembledLen() {
		return disLen;
	}

	/**
	 * Parses the header part of a message and sets the internal state accordingly.
	 * @param pDat array containing the complete message.
	 * @param pIdx index to where in the array the header begins.
	 * @param pLen length of the whole message.
	 * @throws DNSException if the packet is corrupted.
	 * @see #getDisassembledLen()
	 */
	public void disassemblePacket(byte[] pDat, int pIdx, int pLen) throws DNSException {
		int field;
		disLen = 0;

		if ( debug ) {
			System.out.println("-> DNSHeader.disassemblePacket() - idx=" + pIdx);
		}

		if ( (pLen - pIdx) < HEADER_SIZE ) {
			throw new DNSException("IndexOutOfBounds.");
		}

		/*
		if ( debug ) {
			for(int i=0; i<HEADER_SIZE; i++)
				System.out.println( ((int)pDat[i]&255) + " - " + (char)((int)pDat[i]&255) + "\n" );
		}
		*/

		// Id

		identifier = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);

		// Header

		field = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);

		// Fields

		queryResponse = (field >> 15) & 1;
		opcode = (field >> 11) & 15;
		authoritativeAnswer = i2b(field >> 10);
		trunCation = i2b(field >> 9);
		recursionDesired = i2b(field >> 8);
		recursionAvailable = i2b(field >> 7);
		responseCode = (field >> 0) & 15;

		// QDCount / ANCount / NSCount / ARCount

		questionCount = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);
		answerCount = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);
		authorityCount = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);
		additionalCount = (pDat[pIdx++] & 255) << 8 | (pDat[pIdx++] & 255);

		disLen = HEADER_SIZE;

		if ( debug ) {
			System.out.println("<- DNSHeader.disassemblePacket() - Len=" + disLen);
		}
	}

	/**
	 * Set the message identification.
	 * @param id message identification.
	 */
	public void setID(int id) {
		identifier = id;
	}

	/**
	 * Get the message identification.
	 * @return message identification.
	 */
	public int getID() {
		return identifier;
	}

	/**
	 * Set the header to either <CODE>Query</CODE> or <CODE>Response</CODE>.
	 * @param qr <CODE>Query</CODE> or <CODE>Response</CODE>.
	 */
	public void setQueryResponse(int qr) {
		queryResponse = qr;
	}

	/**
	 * Get the type of message, <CODE>Query</CODE> or <CODE>Response</CODE>.
	 * @return message type.
	 */
	public int getQueryResponse() {
		return queryResponse;
	}

	/**
	 * Set message opcode.
	 * @param i opcode.
	 */
	public void setOpcode (int i) {
		opcode = i;
	}

	/**
	 * Get message opcode.
	 * @return message opcode.
	 */
	public int getOpcode () {
		return opcode;
	}

	/**
	 * Set Authoritative Answer flag.
	 * @param aa boolean.
	 */
	public void setAuthoritativeAnswer(boolean aa) {
		authoritativeAnswer = aa;
	}

	/**
	 * Get Authoritative Answer flag.
	 * @return boolean.
	 */
	public boolean getAuthoritativeAnswer() {
		return authoritativeAnswer;
	}

	/**
	 * Set Truncation flag.
	 * @param tc boolean.
	 */
	public void setTrunCation(boolean tc) {
		trunCation = tc;
	}

	/**
	 * Get Truncation flag.
	 * @return boolean.
	 */
	public boolean getTrunCation() {
		return trunCation;
	}

	/**
	 * Set Recursion Desired flag.
	 * @param rd boolean.
	 */
	public void setRecursionDesired(boolean rd) {
		recursionDesired = rd;
	}

	/**
	 * Get Recursion Desired flag.
	 * @return boolean.
	 */
	public boolean getRecursionDesired() {
		return recursionDesired;
	}

	/**
	 * Set Recursion Available flag.
	 * @param ra boolean.
	 */
	public void setRecursionAvailable(boolean ra) {
		recursionAvailable = ra;
	}

	/**
	 * Get Recursion Available flag.
	 * @return boolean.
	 */
	public boolean getRecursionAvailable() {
		return recursionAvailable;
	}

	/**
	 * Set Response Code flag.
	 * @param rc Response Code.
	 */
	public void setResponseCode(int rc) {
		responseCode = rc;
	}

	/**
	 * Get Response Code flag.
	 * @return Response Code.
	 */
	public int getResponseCode() {
		return responseCode;
	}

	/**
	 * Set Question count.
	 * @param c count.
	 */
	public void setQuestionCount(int c) {
		questionCount = c;
	}

	/**
	 * Get Question count.
	 * @return c count.
	 */
	public int getQuestionCount() {
		return questionCount;
	}

	/**
	 * Set Answer resource record count.
	 * @param c count.
	 */
	public void setAnswerCount(int c) {
		answerCount = c;
	}

	/**
	 * Get Answer resource record count.
	 * @return count.
	 */
	public int getAnswerCount() {
		return answerCount;
	}

	/**
	 * Set Authority resource record count.
	 * @param c count.
	 */
	public void setAuthorityCount(int c) {
		authorityCount = c;
	}

	/**
	 * Get Authority resource record count.
	 * @return count.
	 */
	public int getAuthorityCount() {
		return authorityCount;
	}

	/**
	 * Set Additional resource record count.
	 * @param c count.
	 */
	public void setAdditionalCount(int c) {
		additionalCount = c;
	}

	/**
	 * Get Additional resource record count.
	 * @return count.
	 */
	public int getAdditionalCount() {
		return additionalCount;
	}

	/**
	 * Returns the upper byte of the 16 bit portion of the integer.
	 * @param i integer.
	 * @return upper byte.
	 */
	private static byte upperByte(int i) {
		return (byte)(i >> 8);
	}

	/**
	 * Returns the lower byte of the 16 bit portion of the integer.
	 * @param i integer.
	 * @return lower byte.
	 */
	private static byte lowerByte(int i) {
		return (byte)(i & 255);
	}

	/**
	 * Converts a boolean to an interger.
	 * @param b boolean.
	 * @return <CODE>0</CODE> or <CODE>1</CODE>.
	 */
	private static int b2i(boolean b) {
		if ( b )
			return 1;
		else
			return 0;
	}

	/**
	 * Converts an integer to a boolean, zero returns <CODE>false</CODE>, everything else returns <CODE>true</CODE>.
	 * @param i integer.
	 * @return boolean.
	 */
	private static boolean i2b(int i) {
		return ( (i & 1) != 0 );
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "\n";
		tmpStr += "Packet Header\n";
		tmpStr += "-------------\n";
		tmpStr += "Id: " + identifier + "\n";
		tmpStr += "queryResponse: " + queryResponse + "\n";
		tmpStr += "opcode: " + opcode + "\n";
		tmpStr += "authoritativeAnswer: " + authoritativeAnswer + "\n";
		tmpStr += "trunCation: " + trunCation + "\n";
		tmpStr += "recursionDesired: " + recursionDesired + "\n";
		tmpStr += "recursionAvailable: " + recursionAvailable + "\n";
		tmpStr += "responseCode: " + responseCode + "\n";
		tmpStr += "questionCount: " + questionCount + "\n";
		tmpStr += "answerCount: " + answerCount + "\n";
		tmpStr += "authorityCount: " + authorityCount + "\n";
		tmpStr += "additionalCount: " + additionalCount + "\n";
		return tmpStr;
	}

}
