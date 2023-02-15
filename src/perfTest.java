import java.io.IOException;
import java.security.GeneralSecurityException;

import com.entrust.nshield.ps.pqsdk.HostCommands;
import com.ncipher.jutils.HexFunctions;
import com.ncipher.nfast.NFException;

public class perfTest {
	private HostCommands hc = new HostCommands();
	private int THREAD_CNT = 2;
	private int LOOP_CNT = 10;
	private byte[] data;
	
	void run() throws InterruptedException, NFException, IOException, GeneralSecurityException
	{
		System.out.println("===PQC Test===");
		//System.out.println("Version: " + hc.getVersion().version);
		
		//Generate a signing key for signing test
		HostCommands.generateResponse gResp = hc.generate("mypqcsignkey", HostCommands.algorithm_dilithium_5, true);
		System.out.println("Signing Key Hash: " + HexFunctions.byte2hex(gResp.hash));
		
		HostCommands.getPublicResponse getsignkeypubResp = hc.getPublic("mypqcsignkey");
		System.out.println("Dilithium5 pubkey Len: "+ getsignkeypubResp.publicKey.length);
		
		//Generate a Leaf key to be signed
		HostCommands.generateResponse gResp2 = hc.generate("d2keypair", HostCommands.algorithm_dilithium_2, true);
		HostCommands.getPublicResponse getpubResp = hc.getPublic("d2keypair");
		data = getpubResp.publicKey;
		
		System.out.println("Dilithium2 pubkey: " + HexFunctions.byte2hex(data));
		System.out.println("Dilithium2 pubkey Len: "+ getpubResp.publicKey.length);
	
		Thread[] threadArray = new Thread[THREAD_CNT];
		
		////
		//Start perf testing
		long millis = System.currentTimeMillis();
		
		for (int i = 0; i < THREAD_CNT; i++)	
		{
			//threadArray[i] = new DoGenKeys();
			threadArray[i] = new DoSign();
			threadArray[i].start();
		}

		for (int i = 0; i < THREAD_CNT; i++)	
		{
			threadArray[i].join();
		}
		
		millis = System.currentTimeMillis() - millis;
		//End perf testing
		////
		
		System.out.printf("Elapesed Time: %f sec\n", millis/1000.0);
		//System.out.printf("KeyGen TPS: %f keys/sec", (THREAD_CNT*LOOP_CNT)/(millis/1000.0));
		System.out.printf("Signing TPS: %f TPS", (THREAD_CNT*LOOP_CNT)/(millis/1000.0));
		
		return;
	}
	
	public static void main(String[] args) throws Exception {
		perfTest test = new perfTest();
		test.run();
		
		return ;		
	}
	
	private class DoGenKeys extends Thread
	{
		
		public void run()
		{
			int i = 0;
			for(i=0; i<LOOP_CNT; i++)
			{
				try {
					HostCommands.generateResponse gResp = hc.generate("mypqckey"+Thread.currentThread().getId()+i, HostCommands.algorithm_dilithium_5, true);
					//System.out.println("Hash: " + HexFunctions.byte2hex(gResp.hash));
				} catch (NFException | IOException | GeneralSecurityException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			}
		}
	}
	
	private class DoSign extends Thread
	{
		//String message = "This is a sample text message to be signed.";
		
		public void run()
		{
			int i = 0;
			for(i=0; i<LOOP_CNT; i++)
			{
				try {
					HostCommands.signResponse signResp = hc.sign("mypqcsignkey", data/*message.getBytes("UTF-8")*/);
					System.out.println("Signature: " + HexFunctions.byte2hex(signResp.signature));
					System.out.println("Signature len: " + signResp.signature.length);
				} catch (NFException | IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			}
		}
	}

}
