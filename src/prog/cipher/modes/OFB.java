package prog.cipher.modes;

import prog.cipher.crypto.Idea;
import prog.cipher.OperationMode;

import static prog.cipher.crypto.MathAlgo.makeKey;
import static prog.cipher.crypto.MathAlgo.xor;

public class OFB extends OperationMode {

    private final int blockSize;
    private final byte[] feedback;

    public OFB(String key) {
        super(new Idea(key, true), true);
        blockSize = idea.getBlockSize();
        feedback = makeKey(key, blockSize);
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        idea.crypt(feedback);
        xor(data, pos, feedback, blockSize);
    }
}