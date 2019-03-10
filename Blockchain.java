/*

Author: Seifullah ElHaraki

Example utility code for reading data records from a file into an object,
placing the object into an array of such objects,
then translating each record into a string of concatenated XML objects suitable for marshalling as an external data format.

Used web sources + Dr. Clark Elliot's Code:

Reading lines and tokens from a file:
http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html

XML validator:
https://www.w3schools.com/xml/xml_validator.asp

XML / Object conversion:
https://www.mkyong.com/java/jaxb-hello-world-example/
*/

//Java libraries are here
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import java.io.*;

//Other tools used here
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;

//This class is to create our Blocks
class Block {
    private int PreviousHash;
    private String XML_Record;
    private int CurrentHash;

    public Block(int PreviousHash, String XML_Record) {
        this.XML_Record = XML_Record;
        this.PreviousHash = PreviousHash;
        String chash_plus_record = Integer.toString(CurrentHash) + XML_Record;
        this.CurrentHash = chash_plus_record.hashCode();
    }
    public String getXML_Record() {
        return XML_Record;
    }
    public int getPreviousHash() {
        return PreviousHash;
    }
    public int getCurrentHash() {
        return CurrentHash;
    }
}
@XmlRootElement
class BlockRecord{
    /* Examples of block fields: */
    String SHA256String;
    String SignedSHA256;
    String BlockID;
    String VerificationProcessID;
    String CreatingProcess;
    int CurrentHash;
    int PreviousHash;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String Rx;
    int TR;
    byte[] digisig;
    public static int write_leg_tag = 0;
    //This will hold our key pairs
    public static KeyPair key_pair;
    //This will hold our public keys
    public static PublicKey[] public_keys = new PublicKey[3];
    public static int Total = 0;

    public int getTotalRecords() {return TR;}
    @XmlElement
    public void setTotalRecords(int TR){this.TR = TR;}

    public String getASHA256String() {return SHA256String;}
    @XmlElement
    public void setASHA256String(String SH){this.SHA256String = SH;}

    public byte[] getDigitalSignature() {return digisig;}
    @XmlElement
    public void setDigitalSignature(byte[] digisig){this.digisig = digisig;}

    public String getASignedSHA256() {return SignedSHA256;}
    @XmlElement
    public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}

    public String getACreatingProcess() {return CreatingProcess;}
    @XmlElement
    public void setACreatingProcess(String CP){this.CreatingProcess = CP;}

    public String getAVerificationProcessID() {return VerificationProcessID;}
    @XmlElement
    public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

    public String getABlockID() {return BlockID;}
    @XmlElement
    public void setABlockID(String BID){this.BlockID = BID;}

    public String getFSSNum() {return SSNum;}
    @XmlElement
    public void setFSSNum(String SS){this.SSNum = SS;}

    public String getFFname() {return Fname;}
    @XmlElement
    public void setFFname(String FN){this.Fname = FN;}

    public String getFLname() {return Lname;}
    @XmlElement
    public void setFLname(String LN){this.Lname = LN;}

    public String getFDOB() {return DOB;}
    @XmlElement
    public void setFDOB(String DOB){this.DOB = DOB;}

    public String getGDiag() {return Diag;}
    @XmlElement
    public void setGDiag(String D){this.Diag = D;}

    public String getGTreat() {return Treat;}
    @XmlElement
    public void setGTreat(String D){this.Treat = D;}

    public String getGRx() {
        return Rx;
    }

    @XmlElement
    public void setGRx(String D) {
        this.Rx = D;
    }
    public int getCurrentHash() {
        return CurrentHash;
    }

    @XmlElement
    public void setCurrentHash(int chash) {
        this.CurrentHash = chash;
    }

    public int getPreviousHash() {
        return PreviousHash;
    }

    @XmlElement
    public void setPreviousHash(int phash) {
        this.CurrentHash = phash;
    }

}

/*We add one to the port number for each process depending on the process number. For example process1 will have 4711,4821 and 4931 respectively*/
class Ports{
    public static int KeyServerPortBase = 4710;
    public static int UnverifiedBlockServerPortBase = 4820;
    public static int BlockchainServerPortBase = 4930;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts(){
        KeyServerPort = KeyServerPortBase + (bc.PID);
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (bc.PID);
        BlockchainServerPort = BlockchainServerPortBase + (bc.PID);
        System.out.println("This the port: " + KeyServerPort);
    }
}

class PublicKeyWorker extends Thread {
    Socket sock;
    PublicKey publicKey;
    PublicKeyWorker (Socket s) {sock = s;}
    public void run(){
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String data = in.readLine ();
            System.out.println("\n<<Received>> " + data + "\n");
            //This determines which process is sending in the public key
            String pnum_sending = data.substring(16,17);
            String Pub_key = data.substring(22);
            byte[] pbyte = Base64.getDecoder().decode(Pub_key);
            X509EncodedKeySpec ks = new X509EncodedKeySpec(pbyte);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                publicKey = keyFactory.generatePublic(ks);
            }
            catch(NoSuchAlgorithmException e){e.printStackTrace();}
            catch (InvalidKeySpecException e){e.printStackTrace();}
            if (pnum_sending.equals("0")){
                BlockRecord.public_keys[0]=publicKey;
            }
            else if (pnum_sending.equals("1")){
                BlockRecord.public_keys[1]=publicKey;

            }
            else if (pnum_sending.equals("2")){
                BlockRecord.public_keys[2]=publicKey;
            }
            sock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}

class PublicKeyServer implements Runnable {
    //public ProcessBlock[] PBlock = new ProcessBlock[3]; // One block to store info for each process.

    public void run(){
        int q_len = 6;
        Socket sock;
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            System.out.println("Server for public key started at: " + Ports.KeyServerPort);
            while (true) {
                sock = servsock.accept();
                new PublicKeyWorker (sock).start();
            }

        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

class UnverifiedBlockServer implements Runnable {
    BlockingQueue<String> queue;
    UnverifiedBlockServer(BlockingQueue<String> queue){
        this.queue = queue; //This is for the priority queue
    }

    //This class will contain the unverified blocks. The processes will get them and verify them.
    class UnverifiedBlockWorker extends Thread {
        // Class definition
        Socket sock; // Class member, socket, local to Worker.
        UnverifiedBlockWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
        public void run(){
            try{
                //Well read in our block and put it in the priority queue
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                String data = in.readLine ();
                System.out.println("Put in priority queue: " + data);
                //Increment our total counter
                BlockRecord.Total = BlockRecord.Total + 1;
                queue.put(data);
                sock.close();
            } catch (Exception x){x.printStackTrace();}
        }
    }

    public void run(){
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;
        System.out.println("Starting the Unverified Block Server input thread using " +
                Integer.toString(Ports.UnverifiedBlockServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                sock = servsock.accept(); // Got a new unverified block
                new UnverifiedBlockWorker(sock).start(); // So start a thread to process it.
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

/*We have a queue to receive the unverified blocks in. We can add to it using our workers and also remove from it*/
class UnverifiedBlockConsumer implements Runnable {
    BlockingQueue<String> queue;
    UnverifiedBlockConsumer(BlockingQueue<String> queue){
        this.queue = queue;
    }

    public void run(){
        String data;
        PrintStream toServer;
        Socket sock;
        String VerifiedBlock_Printout;
        String VerifiedBlock;
        boolean verified = false;
        String the_blockchain = "";
        System.out.println("Initializing the Unverified Block Priority Queue.........\n");
        try{
            JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();

            while(true){ // Well look at the queue and verify then multicast our new blockchain
                data = queue.take(); //If the queue is empty we will be blocking and or waiting
                System.out.println("Process got unverified: " + data);
                //This will unmarshal our data back to a BlockRecord
                BlockRecord BR = (BlockRecord) jaxbUnmarshaller.unmarshal(new StringReader(data));
                // This code will simulate work being done by the blocks
                int j;
                for(int i=0; i< 100; i++){ // put a limit on the fake work for this example
                    j = ThreadLocalRandom.current().nextInt(0,10);
                    try{Thread.sleep(500);}catch(Exception e){e.printStackTrace();}
                    if (j < 3) break;
                }

                //Dup block filter
                //This will know which process created this block
                String Process_From_Data = (data.substring(data.indexOf("<ACreatingProcess>Process")+25,data.indexOf("</ACreatingProcess>")));
                if(Process_From_Data.equals("0")){
                    verified = bc.verifySig(BR.getASHA256String().getBytes(), BlockRecord.public_keys[0], BR.getDigitalSignature());
                }
                else if(Process_From_Data.equals("1")){
                    verified = bc.verifySig(BR.getASHA256String().getBytes(), BlockRecord.public_keys[1], BR.getDigitalSignature());
                }
                else if(Process_From_Data.equals("2")){
                    verified = bc.verifySig(BR.getASHA256String().getBytes(), BlockRecord.public_keys[2], BR.getDigitalSignature());
                }
                if(verified == true){
                    BR.setAVerificationProcessID(Integer.toString(bc.PID));
                    //Re marshall because, we set our process ID
                    Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                    StringWriter sw = new StringWriter();
                    jaxbMarshaller.marshal(BR, sw);
                    String data_new = sw.toString();
                    VerifiedBlock = data_new+"\n";
                    VerifiedBlock_Printout = "\n[Block ID: " + BR.getABlockID() + " has been verified by P" + bc.PID + " at time "
                            + Integer.toString(ThreadLocalRandom.current().nextInt(100,1000)) + "]\n";
                    System.out.println(VerifiedBlock_Printout);
                    //This will help me find if the block id already existed if so im not including it in my chain
                    if(!bc.blockchain.contains(BR.BlockID)) {
                        the_blockchain = VerifiedBlock + bc.blockchain; // add the verified block to the chain
                        for (int i = 0; i < bc.numProcesses; i++) { // send to each process in group, including us:
                            sock = new Socket(bc.serverName, Ports.BlockchainServerPortBase + (i));
                            toServer = new PrintStream(sock.getOutputStream());
                            toServer.println(the_blockchain);
                            toServer.flush(); // make the multicast
                            sock.close();
                        }
                    }
                }
                Thread.sleep(1500); // For the example, wait for our blockchain to be updated before processing a new block
            }
        }catch (Exception e) {System.out.println(e);}
    }
}

// Incoming proposed replacement blockchains. Compare to existing. Replace if winner:

class BlockchainWorker extends Thread implements Serializable{ // Class definition
    Socket sock; // Class member, socket, local to Worker.
    BlockchainWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
    public void run(){
        try{
            int write_once = 0;
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String data = "";
            String data2;
            while((data2 = in.readLine()) != null){
                data = data + data2;
            }
            //If our process ID is Zero we will write to the ledger
            //This will remove any XML header from the data to avoid dup headers
            data = data.replace("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>", "");
            //This will keep clean and clear spacing from blockrecord to the next record
            data = data.replace("<blockRecord>", "\n<blockRecord>");
            data = data.replace("</blockRecord>", "</blockRecord>\n");
            if(bc.PID == 0) {
                //We will start up a buffered writer to write out data to the BlockchainLedger.xml
                try {
                    BufferedWriter write_to = new BufferedWriter(new FileWriter("BlockchainLedger.xml"));
                    if (write_once == 0){
                        write_to.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<BlockLedger>");
                        write_once++;
                    }
                    write_to.write(data);
                    BlockRecord.write_leg_tag++;
                    System.out.println("This the the leg tab counter " + BlockRecord.write_leg_tag);
                    System.out.println("This the the tot  counter " + BlockRecord.Total);
                    //This is where we will write to the Block Ledger
                    if(BlockRecord.write_leg_tag == BlockRecord.Total){
                        write_to.write("\n</BlockLedger>");
                    }
                    write_to.close();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
            bc.blockchain = data; // Would normally have to check first for winner before replacing.
            System.out.println("\n<-------------------------------New BlockChain--------------------------------->\n\n" + bc.blockchain + "\n\n");

            sock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}

class BlockchainServer implements Runnable {
    public void run(){
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;
        System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new BlockchainWorker (sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

//The BlockChain Class
class bc implements Serializable{
    static String serverName = "localhost";
    static String blockchain = "<blockRecord><ABlockID>32j32-3ge-4622-4hgb-75cb144a8de5</ABlockID><ACreatingProcess>DummyBlock</ACreatingProcess><ASHA256String>DummyBlock</ASHA256String><ASignedSHA256>DummyBlock</ASignedSHA256><AVerificationProcessID>0</AVerificationProcessID><currentHash>0</currentHash><digitalSignature>DummyBlock</digitalSignature><FDOB>DummyBlock</FDOB><FFname>DummyBlock</FFname><FLname>DummyBlock</FLname><FSSNum>DummyBlock</FSSNum><GDiag>DummyBlock</GDiag><GRx>DummyBlock</GRx><GTreat>DummyBlock</GTreat><previousHash>0</previousHash></blockRecord>"; //Our dummy or genesis block
    static int numProcesses = 3; // This depends on the number of processes
    static int PID = 0; // The process ID


    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);

        return (signer.verify(sig));
    }

    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
    }
    public void MultiSend (int Records, BlockRecord[] R, Marshaller jax){ // Multicast some data to each of the processes.
        Socket sock = null;
        PrintStream toServer;
        String SignedSHA256;

        try{
            for(int i=0; i< numProcesses; i++){// Send our key to all servers.
                sock = new Socket(serverName, Ports.KeyServerPortBase + (i));
                toServer = new PrintStream(sock.getOutputStream());
                String pubkey = Base64.getEncoder().encodeToString(BlockRecord.key_pair.getPublic().getEncoded());
                toServer.println("Public key from " + bc.PID + " is: " + pubkey);
                //BlockRecord.public_keys[0] = BlockRecord.key_pair.getPublic();
                toServer.flush();
                sock.close();
            }
            Thread.sleep(1000); // wait for keys to be accepted by the other processes to know they got them
            //System.out.println(P0.getXML_Record());
            for (int h = 0; h < Records; h++) {
                //System.out.println(blockArray[i].BlockID);
                for (int i = 0; i < numProcesses; i++) {
                    // Send a sample unverified block A to each server
                    StringWriter sw = new StringWriter();
                    jax.marshal(R[h], sw);
                    sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + (i));
                    toServer = new PrintStream(sock.getOutputStream());
                    String data_out = sw.toString();
                    //System.out.println("-------------BlockRecord Sent To Process " + i +" -----------------");
                    //System.out.println(data_out);
                    //boolean verified = verifySig(SHA256String.getBytes(), BlockRecord.key_pair.getPublic(), R[h].getDigitalSignature());
                    //System.out.println("Has the signature been verified: " + verified + "\n");
                    //System.out.println("Original SHA256 Hash: " + SHA256String + "\n");
                    toServer.println(data_out);
                    //Well pass the block here
                    toServer.flush();
                    sock.close();
                }
            }

        }catch (Exception x) {x.printStackTrace ();}
    }

}

public class Blockchain {

    private static String FILENAME;
    private static final int iFNAME = 0;
    private static final int iLNAME = 1;
    private static final int iDOB = 2;
    private static final int iSSNUM = 3;
    private static final int iDIAG = 4;
    private static final int iTREAT = 5;
    private static final int iRX = 6;

    public static void main(String[] args) throws Exception {
        int randvalue;
        Random r = new Random();
        randvalue = r.nextInt(100);
        BlockRecord.key_pair = bc.generateKeyPair(randvalue);
        int pnum=0; //This is the process number
        //This is a dummy XML to help define our dummy block.
        String D_XML = "This is a dummy XML blocktext";
        //This is where we are creating our dummy first block
        Block Gen_Block = new Block(0, D_XML);
        //System.out.println(Gen_Block.getCurrentHash());
        if (args.length > 1) System.out.println("Maybe ive done something interesting \n");

        if (args.length < 1) pnum = 0;
        else if (args[0].equals("0")){
            pnum = 0;
        }
        else if (args[0].equals("1")) {
            pnum = 1;
            bc.PID = pnum;
        }
        else if (args[0].equals("2")){
            pnum = 2;
            bc.PID = pnum;
        }
        else pnum = 0; //If no argument was provided

        switch(pnum){
            case 1: FILENAME = "BlockInput1.txt"; break;
            case 2: FILENAME = "BlockInput2.txt"; break;
            default: FILENAME= "BlockInput0.txt"; break;
        }

        System.out.println("Reading in from file: " + FILENAME + "\n");
        try {
            try (BufferedReader br = new BufferedReader(new FileReader(FILENAME))) {
                String[] tokens = new String[10];
                String stringXML;
                String InputLineStr;
                String suuid;
                UUID idA;
                String digi;
                BlockRecord[] blockArray = new BlockRecord[20];

                JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
                Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                StringWriter sw = new StringWriter();

                //jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
                //This is the Block Record well sign
                String Block_Record = sw.toString();
                //Create an SHA-256 Digest of the block
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                //We get the bytes on the block
                md.update (Block_Record.getBytes());
                //a byte data array
                byte byteData[] = md.digest();
                //were gonna convert byte to hex
                StringBuffer sb = new StringBuffer();
                for (int j = 0; j < byteData.length; j++) {
                    sb.append(Integer.toString((byteData[j] & 0xff) + 0x100, 16).substring(1));
                }
                String SHA256String = sb.toString();
                byte[] digitalSignature = bc.signData(SHA256String.getBytes(), BlockRecord.key_pair.getPrivate());
                //Set the digital signature to the block
                int n = 0;
                while ((InputLineStr = br.readLine()) != null) {
                    blockArray[n] = new BlockRecord();

                    blockArray[n].setASHA256String(SHA256String);
                    blockArray[n].setASignedSHA256(digitalSignature.toString());

                    idA = UUID.randomUUID();
                    suuid = new String(UUID.randomUUID().toString());
                    blockArray[n].setABlockID(suuid);
                    blockArray[n].setACreatingProcess("Process" + Integer.toString(pnum));
                    blockArray[n].setAVerificationProcessID(Integer.toString(pnum));
                    tokens = InputLineStr.split(" +"); // Tokenize the input
                    blockArray[n].setFSSNum(tokens[iSSNUM]);
                    blockArray[n].setFFname(tokens[iFNAME]);
                    blockArray[n].setFLname(tokens[iLNAME]);
                    blockArray[n].setFDOB(tokens[iDOB]);
                    blockArray[n].setGDiag(tokens[iDIAG]);
                    blockArray[n].setGTreat(tokens[iTREAT]);
                    blockArray[n].setGRx(tokens[iRX]);
                    blockArray[n].setDigitalSignature(digitalSignature);
                    //Will capture the total records being read in
                    blockArray[n].setTotalRecords(n);
                    n++;
                }
                //Where n represents the number of records
                System.out.println(n + " records read.");
                System.out.println("Names from input:");
                for(int i=0; i < n; i++){
                    System.out.println("  " + blockArray[i].getFFname() + " " +
                            blockArray[i].getFLname());
                }
                System.out.println("\n");

                final BlockingQueue<String> queue = new PriorityBlockingQueue<>(); // Concurrent queue for unverified blocks
                new Ports().setPorts(); // Establish OUR port number scheme, based on PID
                new Thread(new PublicKeyServer()).start(); // New thread to process incoming public keys
                new Thread(new UnverifiedBlockServer(queue)).start(); // New thread to process incoming unverified blocks
                new Thread(new BlockchainServer()).start(); // New thread to process incoming new blockchains
                try{Thread.sleep(3500);}catch(Exception e){} // Wait for servers to start.
                new bc().MultiSend(n, blockArray, jaxbMarshaller); // This will multicast a new xml block out to the other processes
                //String fullBlock = sw.toString();
                //String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
                //String cleanBlock = fullBlock.replace(XMLHeader, "");
                // Show the string of concatenated, individual XML blocks:
                //String XMLBlock = XMLHeader + "\n<BlockLedger>" + cleanBlock + "</BlockLedger>";
                //System.out.println("XML Block Starts Here------");
                //System.out.println(XMLBlock);
                //System.out.println("XML Block Ends Here--------");
                try{Thread.sleep(10000);}catch(Exception e){} // Wait for multicast to fill incoming queue for our example.
                new Thread(new UnverifiedBlockConsumer(queue)).start(); // Start consuming the queued-up unverified blocks
            } catch (IOException e) {e.printStackTrace();}
        } catch (Exception e) {e.printStackTrace();}

    }
}