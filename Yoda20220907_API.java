//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.script.GhidraScript;
import yoda.ghidra.api.*;

public class Yoda20220907_API extends GhidraScript {

     /**
     * @throws Exception 
     * @see ghidra.app.script.GhidraScript#run()
     */
	private FlatDecompilerAPI decompApi;
    @Override
    public void run() throws Exception {
        monitor.setMessage("Counting symbols...");
        NetWorkFunction network = new NetWorkFunction();
        network.getVals(decompApi, state, monitor, currentProgram);
        
        MemsetUserInputString userinput = new MemsetUserInputString();
        userinput.getVals(decompApi, state, monitor, currentProgram);
        
        ScanfStrcmp scanf = new ScanfStrcmp();
        scanf.getVals(decompApi, state, monitor, currentProgram);
        
        
    }
}
