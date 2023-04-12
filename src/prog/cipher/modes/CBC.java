package prog.cipher.modes;

import prog.cipher.crypto.Idea;
import prog.cipher.OperationMode;

import static prog.cipher.crypto.MathAlgo.makeKey;
import static prog.cipher.crypto.MathAlgo.xor;


public class CBC extends OperationMode {

    private final int blockSize;
    private byte[] prev;
    private final byte[] newPrev;

    public CBC(boolean encrypt, String key) {
        super(new Idea(key, encrypt), encrypt);
        blockSize = idea.getBlockSize();
        prev = makeKey(key, blockSize);
        newPrev = new byte[blockSize];
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        if (encrypt) {
            xor(data, pos, prev, blockSize);
            idea.crypt(data, pos);
            System.arraycopy(data, pos, prev, 0, blockSize);
        } else {
            System.arraycopy(data, pos, newPrev, 0, blockSize);
            idea.crypt(data, pos);
            xor(data, pos, prev, blockSize);
            prev = newPrev.clone();
        }
    }
}
