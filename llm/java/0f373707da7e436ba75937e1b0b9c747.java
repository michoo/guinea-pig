import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

class ObjectLoader {
    public Object deserialize(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }
}
