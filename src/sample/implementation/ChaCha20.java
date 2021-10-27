package sample.implementation;

import sample.implementation.utils.HelperUtils;

import java.math.BigDecimal;

public class ChaCha20 {
    private static final String CHA_CHA_CONST = "expand 32-byte k";
    private static final int ROUNDS = 20;
    
    private byte[] key;
    private byte[] nonce;

    private final int[] initialState = new int[16];

    public ChaCha20(final byte[] key, final byte[] nonce) throws Exception {
        if (key.length != 32) {
            throw new Exception("Key must be 256 bits (32 bytes) long.");
        }

        if (nonce.length != 12) {
            throw new Exception("Nonce must be 96 bits (12 bytes) long.");
        }

        this.key = key;
        this.nonce = nonce;
        this.setInitialStateOfChaCha();
    }

    public void setKey(final byte[] key) {
        this.key = key;
    }

    public byte[] getKey() {
        return this.key;
    }

    public String getHexKey() {
        return HelperUtils.bytesToHex(this.key);
    }

    public void setNonce(final byte[] nonce) {
        this.nonce = nonce;
    }

    public byte[] getNonce() {
        return this.nonce;
    }

    public String getHexNonce() {
        return HelperUtils.bytesToHex(this.nonce);
    }

    public byte[] encrypt(byte[] src, int length) {
        long start = System.nanoTime();

        this.initialState[12] = 0;
        byte[] returnBytes = this.chaCha20(src, length);

        long end = System.nanoTime();
        double elapsedTimeInSeconds = (double) (end - start) / 1000000000;

        System.out.println("Encryption took " + BigDecimal.valueOf(elapsedTimeInSeconds) + " seconds.");

        return returnBytes;
    }

    public byte[] decrypt(byte[] src, int length) {
        long start = System.nanoTime();

        this.initialState[12] = 0;
        byte[] returnBytes = this.chaCha20(src, length);

        long end = System.nanoTime();
        double elapsedTimeInSeconds = (double) (end - start) / 1000000000;

        System.out.println("Decryption took " + BigDecimal.valueOf(elapsedTimeInSeconds) + " seconds.");

        return returnBytes;
    }

    public void setInitialStateOfChaCha() {
        int initialStateCounter = 0;
        String[] constArray = HelperUtils.splitToNChar(CHA_CHA_CONST, 4);

        for (int i = 0; i < initialState.length; i++) {
            if (i < 4) {
                // Constant is in 1st row
                initialState[i] = U8TO32_LE(constArray[i].getBytes(), 0);
            }

            if (i >= 4 && i < 12) {
                // Key is in 2nd and 3rd row
                initialState[i] = U8TO32_LE(key, initialStateCounter);
                initialStateCounter += 4;
            }

            if (i == 12) {
                // Counter in 4th row (first value)
                initialState[i] = 0;
                initialStateCounter = 0;
            }

            if (i > 12) {
                // Nonce in 4th column (last three values)
                initialState[i] = U8TO32_LE(nonce, initialStateCounter);
                initialStateCounter += 4;
            }
        }
    }

    private byte[] chaCha20(byte[] src, int length) {
        byte[] returnBytes = new byte[src.length];

        int[] chaChaBlock;
        int[] output = new int[64];
        int destPos = 0, srcPos = 0;

        while (length > 0) {
            chaChaBlock = this.chaChaBlock(this.initialState);

            for (int i = 0; i < 16; i++) {
                U32TO8_LE(output, 4 * i, chaChaBlock[i]);
            }

            this.initialState[12] += 1;

            if (length <= 64) {
                for (int i = 0; i < length; ++i) {
                    returnBytes[i + destPos] = (byte) (src[i + srcPos] ^ output[i]);
                }

                return returnBytes;
            }

            for (int i = 0; i < 64; ++i) {
                returnBytes[i + destPos] = (byte) (src[i + srcPos] ^ output[i]);
            }

            length -= 64;
            srcPos += 64;
            destPos += 64;
        }

        return returnBytes;
    }

    private int[] chaChaBlock(int[] in) {
        int[] x = new int[16];
        int[] out = new int[16];

        System.arraycopy(in, 0, x, 0, 16);

        for (int i = 0; i < ROUNDS; i += 2) {
            // Odd round (columns)
            this.quarterRound(x, 0, 4, 8, 12);
            this.quarterRound(x, 1, 5, 9, 13);
            this.quarterRound(x, 2, 6, 10, 14);
            this.quarterRound(x, 3, 7, 11, 15);

            // Even round (diagonals)
            this.quarterRound(x, 0, 5, 10, 15);
            this.quarterRound(x, 1, 6, 11, 12);
            this.quarterRound(x, 2, 7, 8, 13);
            this.quarterRound(x, 3, 4, 9, 14);
        }

        for (int i = 0; i < 16; ++i) {
            out[i] = x[i] + in[i];
        }

        return out;
    }

    private int rotate(int a, int b) {
        return (a << b) | (a >>> (32 - b));
    }

    private void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = this.rotate(x[d] ^ x[a], 16);

        x[c] += x[d];
        x[b] = this.rotate(x[b] ^ x[c], 12);

        x[a] += x[b];
        x[d] = this.rotate(x[d] ^ x[a], 8);

        x[c] += x[d];
        x[b] = this.rotate(x[b] ^ x[c], 7);
    }

    private static int U8TO32_LE(byte[] bytes, int i) {
        return (bytes[i] & 0xff) | ((bytes[i + 1] & 0xff) << 8) | ((bytes[i + 2] & 0xff) << 16) | ((bytes[i + 3] & 0xff) << 24);
    }

    private static void U32TO8_LE(int[] x, int i, int u) {
        x[i] = u;

        u >>>= 8;
        x[i + 1] = u;

        u >>>= 8;
        x[i + 2] = u;

        u >>>= 8;
        x[i + 3] = u;
    }
}
