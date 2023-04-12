package prog.cipher;

import prog.cipher.crypto.Idea;

public abstract class OperationMode {

    public enum Mode {
        ECB, CBC, CFB, OFB
    }

    protected final Idea idea;

    protected final boolean encrypt;

    public OperationMode(Idea idea, boolean encrypt) {
        this.idea = idea;
        this.encrypt = encrypt;
    }

    protected abstract void crypt(byte[] data, int pos);

    void crypt(byte[] data){
        crypt(data, 0);
    }

    public boolean isEncrypt() {
        return encrypt;
    }
}
