/*
 * DNS Name, handles domainname dis/assembling (including de/compression).
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
 * 22-Jul-2001 : New bugfixed buildPacket code. arrayToString debug functions.
 * 23-Jul-2001 : Minor encoding compression updates {
 * 27-Jul-2001 : }
 * 28-Jul-2001 : Completed the remaining code in the name assembly routine. (Compression and all)
 *             : Removed some old code.
 *             : Javadoc'ed.
 * 29-Jul-2001 : Recoded routine for disassembling a name. Javadoc.
 *             : Fixed "." assembly bug.
 * 04-Aug-2001 : Fixed some javadoc. Rearranged some methods.
 *             : Renamed disassembly method.
 * 05-Aug-2001 : Changed some throws to DNSException in disassembly routine.
 * 10-Aug-2001 : Removed arrayToString methods.
 * 25-Aug-2001 : Expanded debug info.
 * 27-Aug-2001 : Expanded debug info.
 * 18-Nov-2001 : Javadoc fix.
 *
 */

package com.antiaction.common.net.dns;

import com.antiaction.common.net.dns.DNSNameException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

/**
 * DNS Name, handles domainname dis/assembling (including de/compression).
 * As defined in rfc1035.
 *
 * @version 2.00
 * @author Nicholas Clarke <nclarke@diku.dk>
 */
public class DNSName {

	/** Return packet length. */
	private int disLen = 0;

	/** Debug on/off. */
	private boolean debug = false;

	/** Root node from compression tree. */
	private Node rootNode;

	/**
	 * Construct a name object and initialize internal compression structures.
	 */
	public DNSName() {
		rootNode = new Node(0, ".");
	}

	/**
	 * Toggle debug status.
	 * @param b boolean.
	 */
	public void setDebug(boolean b) {
		debug = b;
	}

	/**
	 * Reset internal compression structures.
	 */
	public void reset() {
		rootNode = new Node(0, ".");
	}

	/**
	 * Build a sub packet containing the name with no, partial or full compresssion used.
	 * @param globalIdx used to index labels across names.
	 * @param name domain name.
	 * @param useComp use compression to build the name.
	 * @param updComp update the compression tree structure with new labels.
	 * @return array of bytes containing the name packet.
	 * @throws DNSNameException if the domain name is invalid.
	 */
	public byte[] buildPacket(int globalIdx, String name, boolean useComp, boolean updComp) throws DNSNameException {
		byte[] packetData;
		int packetLen;
		int packetIdx;

		ArrayList labels;
		StringBuffer label;

		String tmpStr;
		int pidx;
		int idx;
		int len;
		char c;
		boolean b;

		Node tmpNode;
		ArrayList insertList;
		int compIdx;
		int subBuilds;

		if ( debug ) {
			System.out.println("-> DNSName.buildPacket()");
			System.out.println("    name: " + name);
		}

		labels = new ArrayList();
		label = new StringBuffer(64);

	// Sanity check.

		if ( (name == null) || (name.length() > 255) )	{
			throw new DNSNameException("Invalid Parameter.");
		}
		else {
			idx = 0;
			len = 0;
			b = true;

		// root

			if ( name.equals(".") ) {
				name = "";
			}

		// Build subdomain ArrayList.

			while ( b ) {
				if ( idx < name.length() ) {
					c = name.charAt(idx);
					if ( c == '.' ) {
						if ( (len == 0) || (len > 63) ) {
							throw new DNSNameException("Invalid domain name.");
						}
						labels.add( label.toString() );
						label = new StringBuffer(64);
						len = 0;
					}
					else {
						if ( len > 63 ) {
							throw new DNSNameException("Invalid domain name.");
						}
						label.append(c);
						len++;
					}
					idx++;
				}
				else {
					labels.add( label.toString() );
					if ( label.length() > 0 ) {
						labels.add("");
					}
					b = false;
				}
			}
		}

		if ( labels.size() == 1 ) {

	// .

			packetData = new byte[1];
			packetData[0] = (byte)0;
		}
		else {

	// Incl. subDomains.

			int topIdx;
			int lastIdx;
			Node lastNode;
			Node currNode;

			topIdx = labels.size() - 1;
			lastIdx = topIdx;

			tmpStr = (String)labels.get(lastIdx - 1);
			//System.out.println("comprLookup: " + tmpStr);
			currNode = (Node)rootNode.get( tmpStr );
			lastNode = currNode;

			if ( currNode != null ) {
				lastNode = currNode;
				lastIdx -= 1;

				b = true;
				while ( b ) {
					if ( lastIdx > 0 ) {
						tmpStr = (String)labels.get(lastIdx - 1);
						//System.out.println("comprLookup: " + tmpStr);
						currNode = (Node)currNode.get( tmpStr );
						if ( currNode != null ) {
							lastNode = currNode;
							lastIdx -= 1;
						}
						else {
							b = false;
						}
					}
					else {
						b = false;
					}
				}
			}

			//System.out.println("topidx: " + topIdx + " lastIdx: " + lastIdx);

			subBuilds = labels.size();
			if ( topIdx != lastIdx ) {
				subBuilds = lastIdx;
			}

			//System.out.println("subBuilds: " + subBuilds);

		// Validate/Length uncompressed part.

			packetLen = 0;
			for(int i=0, l; i<subBuilds; i++) {							// labels.size()
				l = ((String)labels.get(i)).length();
				packetLen += (1 + l);
				if ( ( i != ( labels.size() - 1 ) ) && ( l == 0 ) ) {
					throw new DNSNameException("Invalid domain name.");
				}
				else if ( ( i == ( labels.size() - 1 ) ) && ( l != 0 ) ) {
					throw new DNSNameException("Invalid internal state.");
				}
			}

		// Compress possible trailing part?

			if ( useComp ) {

		// Compression

				if ( topIdx != lastIdx ) {
					packetLen += 2;
				}
			}
			else {

		// No compression

				for(int i=subBuilds, l; i<labels.size(); i++) {			// labels.size()
					l = ((String)labels.get(i)).length();
					packetLen += (1 + l);
					if ( ( i != ( labels.size() - 1 ) ) && ( l == 0 ) ) {
						throw new DNSNameException("Invalid domain name.");
					}
					else if ( ( i == ( labels.size() - 1 ) ) && ( l != 0 ) ) {
						throw new DNSNameException("Invalid internal state.");
					}
				}
			}

		// Valid Length?

			if ( packetLen == 0 ) {
				throw new DNSNameException("Invalid internal state.");
			}

		// Build packet.

			insertList = new ArrayList();

			packetData = new byte[packetLen];
			idx = 0;

			for(int i=0; i<subBuilds; i++) {
				tmpStr = (String)labels.get(i);
				if ( i < topIdx ) {
					tmpNode = new Node(globalIdx, tmpStr);
					insertList.add(0, tmpNode);
				}
				packetData[idx++] = (byte)tmpStr.length();
				globalIdx++;
				for(int j=0; j<tmpStr.length(); j++) {
					packetData[idx++] = (byte)tmpStr.charAt(j);
					globalIdx++;
				}
			}

		// Compress possible trailing part?

			if ( useComp ) {

		// Compression

				if ( topIdx != lastIdx ) {
					compIdx = (3 << 14) | lastNode.getIdx();
					packetData[idx++] = (byte)(compIdx >> 8);
					packetData[idx++] = (byte)(compIdx & 255);
				}
			}
			else {

		// No compression

				for(int i=subBuilds; i<labels.size(); i++) {
					tmpStr = (String)labels.get(i);
					packetData[idx++] = (byte)tmpStr.length();
					for(int j=0; j<tmpStr.length(); j++) {
						packetData[idx++] = (byte)tmpStr.charAt(j);
					}
				}
			}

		// Update compression HashMaps?

			if ( updComp ) {
				currNode = lastNode;
				if ( currNode == null ) {
					currNode = rootNode;
					//System.out.println("currNode = rootNode");
				}

				for(int i=0; i<insertList.size(); i++) {
					tmpNode = (Node)insertList.get(i);
					//System.out.println("comprUpdate: " + tmpNode.getName() + "(" + tmpNode.getIdx() + ")");
					currNode.put(tmpNode.getName(), tmpNode);
					currNode = tmpNode;
				}
			}
		}

		if ( debug ) {
			System.out.println("<- DNSName.buildPacket()");
		}

		return packetData;
	}

	/**
	 * Returns the length of the previously disassembled name.
	 * @return length of previously disassembled name.
	 * @see #disassemblePacket(byte[], int, int)
	 */
	public int getDisassembledLen() {
		return disLen;
	}

	/**
	 * Parses the name part of a packet and returns a string.
	 * @param pDat array containing the complete packet.
	 * @param pIdx index to where in the array the name begins.
	 * @param pLen length of the whole packet.
	 * @return domain name in string form.
	 * @throws DNSException if the packet is corrupted.
	 * @throws DNSNameException if the domain name is invalid.
	 * @see #getDisassembledLen()
	 */
	public String disassemblePacket(byte[] pDat, int pIdx, int pLen) throws DNSException, DNSNameException {
		StringBuffer name = new StringBuffer(256);
		disLen = 0;

		if ( debug ) {
			System.out.println("-> DNSName.disassemblePacket() - idx=" + pIdx);
		}

		disassemblePointer(name, pDat, pIdx, pLen, 0);

		if ( debug ) {
			System.out.println("    name: " + name.toString());
			System.out.println("<- DNSName.disassemblePacket() - Len=" + disLen);
		}

		return name.toString();
	}

	/**
	 * Recursively disassembles part of a name from a pointer.
	 * @param name domain name buffer passed as reference.
	 * @param pDat array containing the complete packet.
	 * @param pIdx index to where in the array the name begins.
	 * @param pLen length of the whole packet.
	 * @param level used internally to calculate the lenght of the current subdomain not including pointers.
	 * @return domain name in string form.
	 * @throws DNSException if the packet is corrupted.
	 * @throws DNSNameException if the domain name is invalid.
	 * @see #disassembleName(byte[], int, int)
	 */
	private void disassemblePointer(StringBuffer name, byte[] pDat, int pIdx, int pLen, int level) throws DNSException, DNSNameException {
		if ( pIdx > pLen ) {
			throw new DNSException("IndexOutOfBounds.");
		}

		try {
			int fIdx;
			int elems;
			int elen;
			int ptrIdx;
			char c;
			boolean b;

			fIdx = pIdx;
			elems = 0;
			b = true;
			while ( b ) {
				elen = (int)(pDat[pIdx++]&255);
				if ( level == 0 ) {
					disLen++;
				}
				if ( elen == 0 ) {
					name.append(".");
					b = false;
				}
				else if ( ((elen >> 6) & 3) == 0 ) {
					if ( elems != 0) {
						name.append(".");
					}
					for(int i=0; i<elen; i++) {
						c = (char)(pDat[pIdx++]&255);
						if ( level == 0 ) {
							disLen++;
						}
						name.append(c);
					}
					elems++;
				}
				else if ( ((elen >> 6) & 3) == 3 ) {
					ptrIdx = ( (elen & 63) << 8) | (pDat[pIdx++]&255);
					if ( level == 0 ) {
						disLen++;
					}
					if ( ptrIdx < fIdx ) {
						if ( elems != 0) {
							name.append(".");
						}
						disassemblePointer(name, pDat, ptrIdx, pLen, ++level);
					}
					else {
						throw new DNSException("IndexOutOfBounds.");
					}
					b = false;
				}
				else {
					throw new DNSNameException("Invalid encoding.");
				}
			}
		}
		catch(IndexOutOfBoundsException e) {
			throw new DNSException("IndexOutOfBoundsException.");
		}
	}

	/**
	 * Display the hashmap tree structure used for name compression, for debugging purposes only.
	 */
	public void printTree() {
		Iterator iter = rootNode.iterator();
		Node tmpNode;
		while ( iter.hasNext() ) {
			tmpNode = (Node)iter.next();
			System.out.println( tmpNode.getName() );
			printLevel(tmpNode, " ");
		}
	}

	/**
	 * Displays one tree level.
	 * @param node tree node to process.
	 * @param post indentation string.
	 * @see #printTree()
	 */
	private void printLevel(Node node, String post) {
		Iterator iter = node.iterator();
		Node tmpNode;
		while ( iter.hasNext() ) {
			tmpNode = (Node)iter.next();
			System.out.println( post + tmpNode.getName() );
			printLevel(tmpNode, post + " ");
		}
	}

	/**
	 * Inner class to contain the domainname label tree, used for name compression.
	 */
	class Node {

		/** Packet index. */
		int idx;
		/** Labels. */
		String name;
		/** Sub labels. */
		HashMap subMap;

		/**
		 * Construct a Node object.
		 * @param idx packet index.
		 * @param name labels.
		 */
		Node(int idx, String name) {
			this.idx = idx;
			this.name = name;
			subMap = new HashMap();
		}

		/**
		 * Returns the sub labels via an iterator.
		 * @return collection iterator.
		 */
		Iterator iterator() {
			return subMap.values().iterator();
		}

		/**
		 * Update (key, item) pair.
		 * @param key hashmap key.
		 * @param item hashmap item.
		 */
		void put(Object key, Object item) {
			subMap.put(key, item);
		}

		/**
		 * Returns the item associated with the supplied key.
		 * @param key hashmap key.
		 * @return associated item.
		 */
		Object get(Object key) {
			return subMap.get(key);
		}

		/**
		 * Returns packet index.
		 * @return packet index.
		 */
		int getIdx() {
			return idx;
		}

		/**
		 * Returns the label.
		 * @return label.
		 */
		String getName() {
			return name;
		}
	}

}
