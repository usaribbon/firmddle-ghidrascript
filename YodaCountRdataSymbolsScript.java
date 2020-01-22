//TODO write a description for this script
//@author 
//@category Symbol
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class YodaCountRdataSymbolsScript extends GhidraScript {

     /**
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() {
        monitor.setMessage("Counting symbols...");
        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        SymbolIterator iter = st.getSymbolIterator(true);
        int count = 0;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
            if (sym != null && sym.getName() == ".rdata") {
                println(sym.getName());
                count++;
            }
        }
        println(count+" symbols");
    }
}



