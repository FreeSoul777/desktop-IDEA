package prog.cipher.crypto;

import static prog.cipher.Cipher.*;
import static prog.cipher.crypto.MathAlgo.glue2Bytes;

public class Idea extends BlockCipher {

    private final boolean encrypt;
    private int[] subKey;

    public Idea(String charKey, boolean encrypt) {
        super(KEY_SIZE, BLOCK_SIZE);
        this.encrypt = encrypt;
        setKey(charKey);
    }

    protected void setKey(byte[] key) {
        int[] tempSubKey = generateSubKeys(key);
        if (encrypt) {
            subKey = tempSubKey;
        } else {
            subKey = invertSubKeys(tempSubKey);
        }
    }

    public void crypt(byte[] data, int i) {

        int d1 = glue2Bytes(data[i], data[i + 1]);
        int d2 = glue2Bytes(data[i + 2], data[i + 3]);
        int d3 = glue2Bytes(data[i + 4], data[i + 5]);
        int d4 = glue2Bytes(data[i + 6], data[i + 7]);

        int j = 0;
        for (int round = 0; round < ROUNDS; round++) {
            int a = mul(d1, subKey[j++]);
            int b = add(d2, subKey[j++]);
            int c = add(d3, subKey[j++]);
            int d = mul(d4, subKey[j++]);
            int e = a ^ c;
            int f = b ^ d;

            int g = mul(e, subKey[j++]);
            int s = add(f, g);
            int h = mul(s, subKey[j++]);
            int k = add(g, h);

            d1 = a ^ h;
            d2 = c ^ h;
            d3 = b ^ k;
            d4 = d ^ k;
        }

        int r0 = mul(d1, subKey[j++]);
        int r1 = add(d3, subKey[j++]);
        int r2 = add(d2, subKey[j++]);
        int r3 = mul(d4, subKey[j]);

        data[i] = (byte) (r0 >> 8);
        data[i + 1] = (byte) r0;
        data[i + 2] = (byte) (r1 >> 8);
        data[i + 3] = (byte) r1;
        data[i + 4] = (byte) (r2 >> 8);
        data[i + 5] = (byte) r2;
        data[i + 6] = (byte) (r3 >> 8);
        data[i + 7] = (byte) r3;
    }

    private int[] generateSubKeys(byte[] userKey) {
        if (userKey.length != 16) {
            throw new IllegalArgumentException();
        }
        int[] key = new int[ROUNDS * 6 + 4];

        int b1, b2;
        for (int i = 0; i < userKey.length / 2; i++) {
            key[i] = glue2Bytes(userKey[2 * i], userKey[2 * i + 1]);
        }

        for (int i = userKey.length / 2; i < key.length; i++) {
            b1 = key[(i + 1) % 8 != 0 ? i - 7 : i - 15] << 9;
            b2 = key[(i + 2) % 8 < 2 ? i - 14 : i - 6] >>> 7;
            key[i] = (b1 | b2) & 0xFFFF;
        }
        return key;
    }

    private int[] invertSubKeys(int[] subkey) {
        int[] reversSubKey = new int[subkey.length];
        int p = 0;
        int i = ROUNDS * 6;

        reversSubKey[i]     = mulReversKey(subkey[p++]);
        reversSubKey[i + 1] = addReversKey(subkey[p++]);
        reversSubKey[i + 2] = addReversKey(subkey[p++]);
        reversSubKey[i + 3] = mulReversKey(subkey[p++]);

        for (int r = ROUNDS - 1; r > 0; r--) {
            i = r * 6;
            reversSubKey[i + 4] = subkey[p++];
            reversSubKey[i + 5] = subkey[p++];
            reversSubKey[i]     = mulReversKey(subkey[p++]);
            reversSubKey[i + 2] = addReversKey(subkey[p++]);
            reversSubKey[i + 1] = addReversKey(subkey[p++]);
            reversSubKey[i + 3] = mulReversKey(subkey[p++]);
        }

        reversSubKey[4] = subkey[p++];
        reversSubKey[5] = subkey[p++];
        reversSubKey[0] = mulReversKey(subkey[p++]);
        reversSubKey[1] = addReversKey(subkey[p++]);
        reversSubKey[2] = addReversKey(subkey[p++]);
        reversSubKey[3] = mulReversKey(subkey[p]);
        return reversSubKey;
    }

    private int add(int x, int y) {
        return (x + y) & 0xFFFF;
    }

    private int addReversKey(int x) {
        return (0x10000 - x) & 0xFFFF;
    }

    private int mul(int x, int y) {
        long m = (long) x * y;
        if (m != 0) {
            return (int) (m % 0x10001) & 0xFFFF;
        } else {
            if (x != 0 || y != 0) {
                return (1 - x - y) & 0xFFFF;
            }
            return 1;
        }
    }

    private int mulReversKey(int x) {
        if (x <= 1) {
            return x;
        }
        try {
            int y = 0x10001;
            int t0 = 1;
            int t1 = 0;
            while (true) {
                t1 += y / x * t0;
                y %= x;
                if (y == 1) {
                    return (1 - t1) & 0xffff;
                }
                t0 += x / y * t1;
                x %= y;
                if (x == 1) {
                    return t0;
                }
            }
        } catch (ArithmeticException e) {
            return 0;
        }
    }
}
