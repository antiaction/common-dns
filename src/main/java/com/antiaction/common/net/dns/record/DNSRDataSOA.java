/*
 * DNS SOA Record container.
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
 * 03-Sep-2001 : First implemenation.
 * 04-Sep-2001 : buildPacket/disassemblePacket expanded from MINFO.
 * 05-Sep-2001 : Javadoc'ed some fields.
 * 06-Sep-2001 : Minor alterations to disassemblePacket().
 *             : Added set/get methods.
 * 09-Oct-2001 : Cloneable.
 * 18-Nov-2001 : Javadoc fix.
 * 20-Nov-2001 : Fixed buildPacket() invalid alloc size.
 *
 */

package com.antiaction.common.net.dns.record;

import com.antiaction.common.net.dns.DNSType;
import com.antiaction.common.net.dns.DNSName;
import com.antiaction.common.net.dns.DNSException;
import com.antiaction.common.net.dns.DNSNameException;

/**
 * DNS SOA Record container.
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSRDataSOA implements DNSRDataInterface {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Record of type SOA. */
	protected static int rtype = DNSType.SOA;
	/** Name server that was the original or primary source of data for this zone. */
	protected String mname;
	/** Mailbox of the person responsible for this zone. */
	protected String rname;
	/** The unsigned 32 bit version number of the original copy of the zone. */
	protected int serial;
	/** A 32 bit time interval before the zone should be refreshed. */
	protected int refresh;
	/** A 32 bit time interval that should elapse before a failed refresh should be retried. */
	protected int retry;
	/** A 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative. */
	protected int expire;
	/** The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone. */
	protected int minimum;

	/**
	 * Instantiate and initialize a default SOA record object.
	 */
	public DNSRDataSOA() {
		mname = "";
		rname = "";
		serial = 0;
		refresh = 0;
		retry = 0;
		expire = 0;
		minimum = 0;
	}

 	/**
 	 * Overrides Cloneable.
 	 * @return a clone of this instance.
 	 * @exception OutOfMemoryError if there is not enough memory.
 	 * @see java.lang.Cloneable
 	 */
 	public Object clone() {
 		DNSRDataSOA obj = new DNSRDataSOA();
		obj.mname = mname;
		obj.rname = rname;
		obj.serial = serial;
		obj.refresh = refresh;
		obj.retry = retry;
		obj.expire = expire;
		obj.minimum = minimum;
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
		byte[] mnamepkt;
		byte[] rnamepkt;
		byte[] packetData;
		int packetLen;
		int RDLen;

		if ( debug ) {
			System.out.println("-> DNSRDataSOA.buildPacket()");
			System.out.println("    mname: " + mname);
			System.out.println("    rname: " + rname);
			System.out.println("    serial: " + serial);
			System.out.println("    refresh: " + refresh);
			System.out.println("    retry: " + retry);
			System.out.println("    expire: " + expire);
			System.out.println("    minimum: " + minimum);
		}

		packetLen = 0;

	// Nameserver / Mailbox

		dnsname.setDebug(debug);
		mnamepkt = dnsname.buildPacket(globalIdx + 2, mname, true, true);
		rnamepkt = dnsname.buildPacket(globalIdx + 2 + mnamepkt.length, rname, true, true);

	// RDLen

		RDLen = mnamepkt.length + rnamepkt.length + 20;
		packetData = new byte[2 + RDLen];

		packetData[packetLen++] = (byte)(RDLen >> 8);
		packetData[packetLen++] = (byte)(RDLen & 255);

	// Nameserver / Mailbox

		System.arraycopy(mnamepkt, 0, packetData, packetLen, mnamepkt.length);
		packetLen += mnamepkt.length;

		System.arraycopy(rnamepkt, 0, packetData, packetLen, rnamepkt.length);
		packetLen += rnamepkt.length;

	// Serial

		packetData[packetLen++] = (byte)(serial >> 24);
		packetData[packetLen++] = (byte)(serial >> 16);
		packetData[packetLen++] = (byte)(serial >> 8);
		packetData[packetLen++] = (byte)(serial & 255);

	// Refresh

		packetData[packetLen++] = (byte)(refresh >> 24);
		packetData[packetLen++] = (byte)(refresh >> 16);
		packetData[packetLen++] = (byte)(refresh >> 8);
		packetData[packetLen++] = (byte)(refresh & 255);

	// Retry

		packetData[packetLen++] = (byte)(retry >> 24);
		packetData[packetLen++] = (byte)(retry >> 16);
		packetData[packetLen++] = (byte)(retry >> 8);
		packetData[packetLen++] = (byte)(retry & 255);

	// Expire

		packetData[packetLen++] = (byte)(expire >> 24);
		packetData[packetLen++] = (byte)(expire >> 16);
		packetData[packetLen++] = (byte)(expire >> 8);
		packetData[packetLen++] = (byte)(expire & 255);

	// Minimum

		packetData[packetLen++] = (byte)(minimum >> 24);
		packetData[packetLen++] = (byte)(minimum >> 16);
		packetData[packetLen++] = (byte)(minimum >> 8);
		packetData[packetLen++] = (byte)(minimum & 255);

		if ( debug ) {
			System.out.println("<- DNSRDataSOA.buildPacket()");
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
			System.out.println("-> DNSRDataSOA.disassemblePacket() - idx=" + pIdx);
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

	// Nameserver

		try {
			dnsname.setDebug(debug);
			mname = dnsname.disassemblePacket(pDat, pIdx, pLen);
		}
		catch(DNSException e) {
			throw new DNSRDataException("Invalid domain name.");
		}

		pIdx += dnsname.getDisassembledLen();

	// Mailbox

		try {
			dnsname.setDebug(debug);
			rname = dnsname.disassemblePacket(pDat, pIdx, pLen);
		}
		catch(DNSException e) {
			throw new DNSRDataException("Invalid domain name.");
		}

		pIdx += dnsname.getDisassembledLen();

		if ( (pIdx + 20) > pLen ) {
			throw new DNSRDataException("RecordOutOfBounds.");
		}

	// Serial

		serial = ((pDat[pIdx++] & 255) << 24) | ((pDat[pIdx++] & 255) << 16) | ((pDat[pIdx++] & 255) << 8) | (pDat[pIdx++] & 255);

	// Refresh

		refresh = ((pDat[pIdx++] & 255) << 24) | ((pDat[pIdx++] & 255) << 16) | ((pDat[pIdx++] & 255) << 8) | (pDat[pIdx++] & 255);

	// Retry

		retry = ((pDat[pIdx++] & 255) << 24) | ((pDat[pIdx++] & 255) << 16) | ((pDat[pIdx++] & 255) << 8) | (pDat[pIdx++] & 255);

	// Expire

		expire = ((pDat[pIdx++] & 255) << 24) | ((pDat[pIdx++] & 255) << 16) | ((pDat[pIdx++] & 255) << 8) | (pDat[pIdx++] & 255);

	// Minimum

		minimum = ((pDat[pIdx++] & 255) << 24) | ((pDat[pIdx++] & 255) << 16) | ((pDat[pIdx++] & 255) << 8) | (pDat[pIdx++] & 255);

		if ( (pIdx - sIdx) != disLen ) {
			throw new DNSRDataException("RDLen mismatch.");
		}

		if ( debug ) {
			System.out.println("    mname: " + mname);
			System.out.println("    rname: " + rname);
			System.out.println("    serial: " + serial);
			System.out.println("    refresh: " + refresh);
			System.out.println("    retry: " + retry);
			System.out.println("    expire: " + expire);
			System.out.println("    minimum: " + minimum);
			System.out.println("<- DNSRDataSOA.disassemblePacket() - Len=" + disLen);
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
	 * Set the Name server that was the original or primary source of data for this zone.
	 * @param mn nameserver.
	 */
	public void setMName(String mn) {
		mname = mn;
	}

	/**
	 * Get the Name server that was the original or primary source of data for this zone.
	 * @return nameserver.
	 */
	public String getMName() {
		return mname;
	}

	/**
	 * Set the mailbox of the person responsible for this zone.
	 * @param rn mailbox.
	 */
	public void setRName(String rn) {
		rname = rn;
	}

	/**
	 * Get the mailbox of the person responsible for this zone.
	 * @return mailbox.
	 */
	public String getRName() {
		return rname;
	}

	/**
	 * Set the unsigned 32 bit version number of the original copy of the zone.
	 * @param s serial number.
	 */
	public void setSerial(int s) {
		serial = s;
	}

	/**
	 * Get the unsigned 32 bit version number of the original copy of the zone.
	 * @return serial number.
	 */
	public int getSerial() {
		return serial;
	}

	/**
	 * Set the 32 bit time interval before the zone should be refreshed.
	 * @param r time interval.
	 */
	public void setRefresh(int r) {
		refresh = r;
	}

	/**
	 * Get the 32 bit time interval before the zone should be refreshed.
	 * @return time interval.
	 */
	public int getRefresh() {
		return refresh;
	}

	/**
	 * Set the 32 bit time interval that should elapse before a failed refresh should be retried.
	 * @param r time interval.
	 */
	public void setRetry(int r) {
		retry = r;
	}

	/**
	 * Get the 32 bit time interval that should elapse before a failed refresh should be retried.
	 * @return time interval.
	 */
	public int getRetry() {
		return retry;
	}

	/**
	 * Set the 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative.
	 * @param e time interval.
	 */
	public void setExpire(int e) {
		expire = e;
	}

	/**
	 * Get the 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative.
	 * @return time interval.
	 */
	public int getExpire() {
		return expire;
	}

	/**
	 * Set the unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.
	 * @param ttl Time To Live.
	 */
	public void setMinimum(int ttl) {
		minimum = ttl;
	}

	/**
	 * Get the unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.
	 * @return Time To Live.
	 */
	public int getMinimum() {
		return minimum;
	}

	/**
	 * Returns a string representation of the internal state, mostly for debugging purposes.
	 * @return debug string.
	 */
	public String toString() {
		String tmpStr = "SOA record.\n";
		tmpStr += "mname: " + mname + "\n";
		tmpStr += "rname: " + rname + "\n";
		tmpStr += "serial: " + serial + "\n";
		tmpStr += "refresh: " + refresh + "\n";
		tmpStr += "retry: " + retry + "\n";
		tmpStr += "expire: " + expire + "\n";
		tmpStr += "minimum: " + minimum + "\n";
		return tmpStr;
	}

}
