package prog.cipher.crypto;

public class MathAlgo {
    public static byte[] makeKey(String charKey, int size) {
        byte[] key = new byte[size];
        int i, j;
        for (j = 0; j < key.length; ++j) {
            key[j] = 0;
        }
        for (i = 0, j = 0; i < charKey.length(); i++, j = (j + 1) % key.length) {
            key[j] ^= (byte) charKey.charAt(i);
        }
        return key;
    }

    public static void xor(byte[] a, int pos, byte[] b, int blockSize) {
        for (int p = 0; p < blockSize; p++) {
            a[pos + p] ^= b[p];
        }
    }

    public static int glue2Bytes(int byte1, int byte2) {
        byte1 = (byte1 & 0xFF) << 8;  // xxxxxxxx00000000
        byte2 = byte2 & 0xFF;         // 00000000xxxxxxxx
        return (byte1 | byte2);       // xxxxxxxxxxxxxxxx
    }

    public static byte[] glue2Bytes(byte[] byte1, byte[] byte2) {
        byte[] out = new byte[byte1.length + byte2.length];
        int i = 0;
        for (byte aB1 : byte1) {
            out[i++] = aB1;
        }
        for (byte aB2 : byte2) {
            out[i++] = aB2;
        }
        return out;
    }
}
