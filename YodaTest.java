//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import docking.ComponentProvider;
import docking.ComponentPlaceholder;
import ghidra.app.plugin.core.calltree.CallTreeProvider;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CallDepthChangeInfo;

public class YodaTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// TODO Auto-generated method stub
		int depth = 10;
		setDepth(depth);
		goTo(addr("0x5000"));
		ComponentProvider provider = getProvider(CallTreeProvider.class);
		CallTreeProvider initialProvider = provider;
		CallTreeProvider newProvider = showProvider("6000");
		
	}
}
