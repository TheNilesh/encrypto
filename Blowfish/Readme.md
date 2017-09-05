## Java - Python Compatible Encyption

In java we get "Blowfish/ECB/PKCS5Padding" initializer for encryption. In python we have to specify pkcs5padding on our own.


    python blowfish.py
    cd MyBlowfish
    javac -cp ./lib/commons-codec-1.10.jar:./src ./src/com/github/thenilesh/crypto/MyBlowfish.java
    java -cp ./lib/commons-codec-1.10.jar:./src com.github.thenilesh.crypto.MyBlowfish 

