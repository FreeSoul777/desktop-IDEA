package prog.cipher.modes;

import prog.cipher.crypto.Idea;
import prog.cipher.crypto.MathAlgo;
import prog.cipher.OperationMode;

import java.util.Arrays;


public class CFB extends OperationMode {
    private final int R = 8;
    private final int blockSize;
    private int partSize;
    private int rounds;
    private byte[] feedback;

    public CFB(boolean encrypt, String key) {
        super(new Idea(key, true), encrypt);
        blockSize = idea.getBlockSize();
        assert blockSize % R == 0 : "R must be divisor of blockSize";
        partSize = R;
        rounds = blockSize / R;
        feedback = MathAlgo.makeKey(key, blockSize);
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        byte[][] block = new byte[rounds][];
        for (int i = 0; i < rounds; i++) {
            block[i] = Arrays.copyOfRange(data, pos + partSize * i, pos + partSize * i + partSize);
        }
        byte[][] crypt = new byte[0][];
        if (!this.isEncrypt()) {
            crypt = new byte[rounds][];
            for (int i = 0; i < rounds; i++) {
                crypt[i] = block[i].clone();
            }
        }
        // Run CFB algorithm
        byte[] feedbackP1, feedbackP2;
        for (int i = 0; i < rounds; i++) {
            idea.crypt(feedback);
            feedbackP1 = Arrays.copyOfRange(feedback, 0, partSize);
            feedbackP2 = Arrays.copyOfRange(feedback, partSize, blockSize);
            MathAlgo.xor(block[i], 0, feedbackP1, partSize);
            if (this.isEncrypt()) {
                feedback = MathAlgo.glue2Bytes(feedbackP2, block[i]);
            } else {
                feedback = MathAlgo.glue2Bytes(feedbackP2, crypt[i]);
            }
        }
        // Merge results
        for (int i = 0; i < rounds; i++) {
            System.arraycopy(block[i], 0, data, pos + partSize * i, partSize);
        }
    }
}