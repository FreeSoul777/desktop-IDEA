package prog.cipher.modes;

import prog.cipher.crypto.Idea;
import prog.cipher.OperationMode;

public class ECB extends OperationMode {

    public ECB(boolean encrypt, String key) {
        super(new Idea(key, encrypt), encrypt);
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        idea.crypt(data, pos);
    }
}