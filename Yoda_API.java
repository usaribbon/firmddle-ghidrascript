//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.util.HashMap;

import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.script.GhidraScript;
import yoda.ghidra.api.*;

public class Yoda_API extends GhidraScript {

     /**
     * @throws Exception 
     * @see ghidra.app.script.GhidraScript#run()
     */
	private FlatDecompilerAPI decompApi;
    @Override
    public void run() throws Exception {
        monitor.setMessage("Running Script...");
        

        /* MemsetUserInput*/
        
        MemsetUserInputString userinput = new MemsetUserInputString();
        HashMap<String,String> userinputResult = userinput.getVals(decompApi, state, monitor, currentProgram);
        userinputResult.forEach((key, value)-> {
        	// key -> function name
        	// value -> program line
            println(key + " " + value);
        });
        ScanfStrcmp scanf = new ScanfStrcmp();
        HashMap<String,String> userinputScanfResult = scanf.getVals(decompApi, state, monitor, currentProgram);
        userinputScanfResult.forEach((key, value)-> {
            println(key + " " + value);
        });
        
        
        /* StringSearch*/
        
        StringSearch strings = new StringSearch();
        HashMap<String,String> stringsResult = strings.getVals(decompApi, state, monitor, currentProgram);
        stringsResult.forEach((key, value)-> {
        	// key -> function name
        	// value -> program line
            println(key + " " + value);
        });
        
        /* NetWorkFuncion*/
        NetWorkFunction network = new NetWorkFunction();
        HashMap<String,String> networkResult = network.getVals(decompApi, state, monitor, currentProgram, 3);
        networkResult.forEach((key, value)-> {
        	// key -> function name
        	// value -> program line
            println(key + " " + value);
        });
        
        
        
    }
}
