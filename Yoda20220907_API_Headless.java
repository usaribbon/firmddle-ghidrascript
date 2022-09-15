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

public class Yoda20220907_API_Headless extends GhidraScript {

     /**
     * @throws Exception 
     * @see ghidra.app.script.GhidraScript#run()
     */
	private FlatDecompilerAPI decompApi;
    @Override
    public void run() throws Exception {
        monitor.setMessage("Running Script...");
        String logPath = "/mnt/raw_firmwares/logs";
        /* NetWorkFuncion*/
        NetWorkFunctionHeadless network = new NetWorkFunctionHeadless();
        network.getVals(decompApi, state, monitor, currentProgram, logPath);

        /* MemsetUserInput*/
        
        MemsetUserInputStringHeadless userinput = new MemsetUserInputStringHeadless();
        userinput.getVals(decompApi, state, monitor, currentProgram, logPath);
        ScanfStrcmpHeadless scanf = new ScanfStrcmpHeadless();
        scanf.getVals(decompApi, state, monitor, currentProgram, logPath);
        
        
        /* StringSearch*/
        StringSearchHeadless strings = new StringSearchHeadless();
        strings.getVals(decompApi, state, monitor, currentProgram, logPath);
        
    }
}
