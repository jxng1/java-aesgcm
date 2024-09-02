package uk.ac.nottingham.cryptography;

import uk.ac.nottingham.cryptography.aes.AES128Encryptor;
import uk.ac.nottingham.cryptography.aes.AES128EncryptorImpl;
import uk.ac.nottingham.cryptography.galois.GF128Multiplier;
import uk.ac.nottingham.cryptography.galois.GF128MultiplierImpl;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Implementation of AEADCipher that encrypts using AES and calculates
 * a tag using GCM.
 * <p>
 * This class is the primary code file in which you can complete your
 * solution to the coursework.
 */
public class AESGCM implements AEADCipher {

    private final GF128Multiplier GF;
    private final AES128Encryptor encryptor;
    private CipherMode mode;
    private byte[] Y;
    private byte[] Y0;
    private byte[] AAD;
    private byte[] C;

    private byte[] T;

    public AESGCM() {
        GF = new GF128MultiplierImpl();
        encryptor = new AES128EncryptorImpl();

        // Add your code here
    }

    @Override
    public void init(AEADParams params) {
        // Add your code here
        // C = new byte[0];
        AAD = new byte[0];
        Y = new byte[12];
        T = new byte[0];

        mode = params.getMode();

        encryptor.init(params.getKey()); // init cipher

        byte[] encrypted = new byte[16]; // 0^128
        encryptor.encryptBlock(encrypted, encrypted); // E(K, 0^128)
        GF.init(encrypted); // init hash; H = E(K, 0^128)

        if (params.getIv().length == 12) { // len(IV) == 96
            byte[] temp = Arrays.copyOf(params.getIv(), params.getIv().length + 4); // add 32(4) bits(bytes) for counter
            temp[15] = 0x01; // set last bit of entire sequence to 1

            Y0 = temp; // set for finalise use
            Y = Y0;
        } else { // len(IV) != 96
            Y0 = GHASH(new byte[0], params.getIv()); // calculate ghash using IV
            Y = Y0;
        }
    }

    @Override
    public void updateAAD(byte[] data) {
        // Add your code here
//        byte[] temp = new byte[AAD.length + data.length]; // create new array for concatenated AAD
//        System.arraycopy(AAD, 0, temp, 0, AAD.length); // copy existing AAD to temp
//        System.arraycopy(data, 0, temp, AAD.length, data.length); // copy new data to temp after existing AAD
//        AAD = temp; // assign temp back to AAD

        AAD = data.clone();
    }

    @Override
    public void processBlock(byte[] data) {
        // Add your code here
        Y = incr(Y); // increment counter(Y)

        // encrypt counter(Y)
        byte[] encryptedCounter = Arrays.copyOf(Y, Y.length);
        encryptor.encryptBlock(Y, encryptedCounter);

        if (mode == CipherMode.DECRYPT) {
            // append ciphertext before we XOR it to calculate tag later
            byte[] temp = Arrays.copyOf(C, C.length + data.length);
            System.arraycopy(data, 0, temp, C.length, data.length);
            //C = temp;
        }

        // xor with plaintext
        for (int i = 0; i < data.length; i++) {
            data[i] ^= encryptedCounter[i % encryptedCounter.length];
        }

        if (mode == CipherMode.ENCRYPT) {
            // append to ciphertext
            byte[] temp = Arrays.copyOf(C, C.length + data.length);
            System.arraycopy(data, 0, temp, C.length, data.length);
            // C = temp;
        }

        byte[] Ym = GHASH(AAD, data);

        byte[] encryptedY0 = new byte[Y0.length];
        encryptor.encryptBlock(Y0, encryptedY0);

        T = XOR(Ym, encryptedY0);
    }

    @Override
    public void finalise(byte[] out) {
        // Add your code here
        System.arraycopy(T, 0, out, 0, T.length);
    }

    @Override
    public void verify(byte[] tag) throws InvalidTagException {
        // Add your code here
        byte[] temp = new byte[16];
        finalise(temp);

        if (!HexUtils.bytesToHex(temp).equals(HexUtils.bytesToHex(tag))) {
            throw new InvalidTagException();
        }
    }

    private byte[] incr(byte[] counter) {
        byte[] ret = Arrays.copyOf(counter, counter.length);
        int value = ByteBuffer.wrap(ret, ret.length - 4, 4).getInt();

        // Increment the value modulo 2^32
        value += 1;

        // Convert back to byte array
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(value);

        // Copy the incremented value back to the original counter
        System.arraycopy(buffer.array(), 0, ret, ret.length - 4, 4);

        return ret;
    }

    private byte[] XOR(byte[] a, byte[] b) {
        int retLength = Math.max(a.length, b.length);
        byte[] ret = new byte[retLength]; // create new byte array with biggest length

        for (int i = 0; i < Math.min(a.length, b.length); i++) { // xor each bit in arrays using minimal length
            ret[i] = (byte) (a[i] ^ b[i]);
        }

        return ret;
    }

    private byte[] GHASH(byte[] A, byte[] C) {
        byte[] Y = new byte[16]; // init Y to 16-zero bytes

        byte[] Aprime = zeroPad(A);
        byte[] Cprime = zeroPad(C);

        byte[] input = new byte[Aprime.length + Cprime.length];
        System.arraycopy(Aprime, 0, input, 0, Aprime.length);
        System.arraycopy(Cprime, 0, input, Aprime.length, Cprime.length);

        // process the padded input in 16-byte blocks
        for (int i = 0; i < input.length; i += 16) {
            byte[] block = Arrays.copyOfRange(input, i, i + 16);

            // xor the block with Y
            Y = XOR(Y, block);

            // multiply Y by H in GF(2^128)
            GF.multiplyByH(Y);
        }

        // append the bit lengths of A and C to Y
        byte[] lenConcat = ByteBuffer.allocate(16)
                .putLong(A.length * 8L)
                .putLong(C.length * 8L)
                .array();

        Y = XOR(Y, lenConcat);

        // mult_H(Y) in GF(2^128) one more time
        GF.multiplyByH(Y);

        return Y;
    }

    private byte[] zeroPad(byte[] data) {
        int padLength = 16 - (data.length % 16);
        if (padLength != 16) {
            byte[] padded = new byte[data.length + padLength];
            System.arraycopy(data, 0, padded, 0, data.length);

            return padded;
        }

        return data;
    }
}
