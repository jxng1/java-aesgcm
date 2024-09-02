package uk.ac.nottingham.cryptography.galois;

import uk.ac.nottingham.cryptography.aes.AES128EncryptorImpl;

import java.lang.reflect.Array;
import java.util.Arrays;

/**
 * Unfinished implementation of a multiplier in GF(2^128).
 * <p>
 * This class could be used to implement a more efficient
 * multiplier in GF(2^128). Coding in this class is not
 * necessary unless you wish to tackle this challenge.
 * <p>
 * This class is used by the FastGFTests class within
 * the test suite, which is disabled by default.
 */
public class GF128FastImpl implements GF128Multiplier {
    private final byte[][][] M = new byte[16][256][16]; // 16 * 256 * 16 = 65536
    private final int[][][] M8 = new int[32][16][]; // P^8i, 32 nibbles(16 bytes) * 16 * 16 = ~8192(less due to variable array size)
    private byte[] H = null;

    @Override
    public void init(byte[] H) {
        // Add your code here
        this.H = H;

        computeM();
        computeM8();
    }

    @Override
    public void multiplyByH(byte[] X) {
        // Add your code here
        int[] Z = new int[4];

        for (int i = 15; i >= 0; --i)
        {
            // first half by using mask of bits: 0000 1111
            int[] m = M8[i + i][X[i] & 0x0F];
            Z[0] ^= m[0];
            Z[1] ^= m[1];
            Z[2] ^= m[2];
            Z[3] ^= m[3];

            // second half by using mask of bits: & 1111 0000
            m = M8[i + i + 1][(X[i] & 0xF0) >>> 4];
            Z[0] ^= m[0];
            Z[1] ^= m[1];
            Z[2] ^= m[2];
            Z[3] ^= m[3];
        }

        byte[] ret = new byte[16];
        // pack as big endian
        intToBigEndian(Z[0], ret, 0);
        intToBigEndian(Z[1], ret, 4);
        intToBigEndian(Z[2], ret, 8);
        intToBigEndian(Z[3], ret, 12);

        System.arraycopy(ret, 0, X, 0, ret.length);

        // non-optimised version
//        byte[] Z = new byte[16];
//        for (int i = 0; i < 16; i++)
//        {
//            int idx = X[i] & 0xFF;
//            xor(Z, M[i][idx]);
//        }
//        System.arraycopy(Z, 0, X, 0, Z.length);
    }

    @Override
    public void multiply(byte[] X, byte[] Y) {
        // Add your code here
        byte[] c = new byte[16];

        for (int i = 0; i < 16; ++i) {
            byte bits = Y[i];
            for (int j = 7; j >= 0; --j) {
                if ((bits & (1 << j)) != 0) {
                    xor(c, X);
                }

                boolean lsb = (X[15] & 1) != 0;
                rightShift(X);
                if (lsb) {
                    X[0] ^= (byte) 0xe1;
                }
            }
        }

        System.arraycopy(c, 0, X, 0, 16);
    }

    @Override
    public byte[] getH() {
        // Add your code here
        return this.H;
    }

    private void computeM() {
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 256; j++) {
                byte b = (byte) j;

                byte[] A = new byte[16];
                A[i] = b;

                multiply(A, H);

                M[i][j] = A;
            }
        }
    }

    private void computeM8() {
        int[][][] table = new int[32][16][];

        // init with empty array for use later
        table[0][0] = new int[4];
        table[1][0] = new int[4];

        // init table[1][8] to H for initial calculations, we need to pack as big endian
        int[] number = new int[4];
        number[0] = bigEndianToInt(H, 0);
        number[1] = bigEndianToInt(H, 4);
        number[2] = bigEndianToInt(H, 8);
        number[3] = bigEndianToInt(H, 12);
        table[1][8] = number;

        // starts at j = 8(j + j), halving each time till 0, multiplying by P
        for (int j = 4; j >= 1; j >>= 1) {
            int[] tmp = new int[4];
            System.arraycopy(table[1][j + j], 0, tmp, 0, 4);

            multiplyP(tmp);
            table[1][j] = tmp;
        }

        // calculate table[0][8] based off table[1][1] and r-shifting required for next calculation loop
        {
            int[] tmp = new int[4];
            System.arraycopy(table[1][1], 0, tmp, 0, 4);
            multiplyP(tmp);
            table[0][8] = tmp;
        }

        // similar to first for loop, except for first table
        for (int j = 4; j >= 1; j >>= 1)
        {
            int[] tmp = new int[4];
            System.arraycopy(table[0][j + j], 0, tmp, 0, 4);

            multiplyP(tmp);
            table[0][j] = tmp;
        }

        // populates rest of tables, at this point the first two tables(table[0] and table[1]) is populated
        // at powers of 2 e.g. table[0][8], table[0][4], table[0][2], table[0][1]...
        // and fills in the missing numbers e.g. 3, 5, 6, 7, 9, ... by building it based on the previous value of
        // table[i][j] and table[i][k] by adding(xor) the two values. aka table[i][3] = table[i][1] + table[i][2]
        int i = 0;
        for (;;)
        {
            // since
            for (int j = 2; j < 16; j += j)
            {
                for (int k = 1; k < j; ++k)
                {
                    int[] tmp = new int[4];
                    System.arraycopy(table[i][j], 0, tmp, 0, 4);

                    xor(tmp, table[i][k]);
                    table[i][j + k] = tmp;
                }
            }

            // break once we reach 32 calculated tables
            if (++i == 32)
            {
                break;
            }

            if (i > 1)
            {
                table[i][0] = new int[4];
                for(int j = 8; j > 0; j >>= 1)
                {
                    int[] tmp = new int[4];
                    System.arraycopy(table[i - 2][j], 0, tmp, 0, 4);

                    // multiplies by each byte from each position that is non-zero
                    multiplyP8(tmp);
                    table[i][j] = tmp;
                }
            }
        }

        System.arraycopy(table, 0, M8, 0, table.length);
    }

    private void rightShift(byte[] a) {
        for (int i = 15; i > 0; i--) {
            a[i] = (byte) (((a[i] & 0xFF) >>> 1) | ((a[i - 1] & 1) << 7));
        }
        a[0] = (byte) ((a[0] & 0xFF) >>> 1);
    }

    private void rightShift(int[] a) {
        int i = 0;
        int bit = 0;

        for (;;)
        {
            int b = a[i];
            a[i] = (b >>> 1) | bit;

            if (++i == 4)
            {
                break;
            }

            bit = b << 31;
        }
    }

    private void xor(byte[] a, byte[] b) {
        for (int i = 0; i < 16; i++) {
            a[i] = (byte) (a[i] & 0xFF ^ b[i] & 0xFF);
        }
    }

    private void xor(int[] a, int[] b) {
        for (int i = 3; i >= 0; --i)
        {
            a[i] ^= b[i];
        }
    }

    private void multiplyP(int[] x)
    {
        boolean lsb = (x[3] & 1) != 0;
        rightShift(x);
        if (lsb)
        {
            x[0] ^= 0xE1000000;
        }
    }

    private void multiplyP8(int[] x)
    {
        for (int i = 8; i != 0; --i)
        {
            multiplyP(x);
        }
    }

    private int bigEndianToInt(byte[] bs, int off) {
        int n = bs[off] << 24;
        n |= (bs[++off] & 0xFF) << 16;
        n |= (bs[++off] & 0xFF) << 8;
        n |= (bs[++off] & 0xFF);

        return n;
    }

    private void intToBigEndian(int n, byte[] bs, int off) {
        bs[off] = (byte)(n >>> 24);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n);
    }
}
