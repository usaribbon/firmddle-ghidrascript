//TODO write a description for this script
//@author 
//@category Symbol
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.util.exception.CancelledException;

public class YodaGetAllSymbolAddress extends GhidraScript {

    HashMap<String, Integer> searchedList = new HashMap<String, Integer>();
     /**
     * @throws CancelledException 
     * @throws DecompileException 
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() throws CancelledException, DecompileException {
        monitor.setMessage("Counting symbols...");
        
        //measure running time
        long runningTimeStart = System.nanoTime();
        
        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        SymbolIterator iter = st.getSymbolIterator(true);
        //int count = 0;
        
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
            //print all symbol
            //println(sym.getName()); 
            if (sym != null) {
            	Address addr = sym.getAddress();
                //println("addr @ " + addr.toString());
            	Listing listing = state.getCurrentProgram().getListing();
            	Function func = listing.getFunctionContaining(addr);
            	if (func == null) {
            		//println("No Function at address" + currentAddress);
            		try {
            			if(searchedList.containsKey(func.getName())) {
            				addSearchedFunction(func.getName());
            			}
            			continue;
            		} catch (NullPointerException e){
            			continue;
                	}
            	}
            	
            	DecompInterface decomplib = setUpDecompiler(state.getCurrentProgram());
            	
            	try {
            		if (!decomplib.openProgram(state.getCurrentProgram())) {
            			println("Decompile Error:" + decomplib.getLastMessage());
            			continue;
            		}
            		Reference refs[] = sym.getReferences(null);
            		
            		for(int i=0; i<refs.length;i++) {
            			if(monitor.isCancelled()) {
            				break;
            			}
            			// Step A
            			Address refAddr = refs[i].getFromAddress();
            			Function refFunc = state.getCurrentProgram().getFunctionManager()
            					.getFunctionContaining(refAddr);
            			if(refFunc == null) {
            				continue;
            			}
            			//println(refFunc.getName());
            			decompileFunction(refFunc, decomplib);
            			
            			//Step B
            			//printOutgoingCalls(refFunc, decomplib);
            			printIncomingCalls(refFunc, decomplib);
            		}
            	} catch (NullPointerException e){
        			continue;
            	} finally {
            		decomplib.dispose();
            	}

                Function symFunc = getFunctionAt(addr);
                if(symFunc != null) {
                	/*
                	printIncomingCalls(symFunc);
                	println("\n");
                	printOutgoingCalls(symFunc);
                	println("----------------------\n");
                	//decompileFunction(symFunc);
                	println("----------------------\n");
                	*/
                }
                
           }
        }
        println(getCount() +" called");

        //measure running time
        long runningTimeEnd = System.nanoTime();
        long timeElapsed = runningTimeEnd - runningTimeStart;
     
        println( "TIME (nsec) : " + timeElapsed  );
        println( "TIME (msec) : " + timeElapsed / 1000000 );
        println( "TIME (sec) : " +  TimeUnit.NANOSECONDS.toSeconds(timeElapsed));
    }
    
    int count = 0;
    private void addCount() {
    	count += 1;
    }
    
    private int getCount() {
    	return count;
    }

    private void addSearchedFunction(String name) {
    	searchedList.put(name, searchedList.get(name)+1);
    }
    
    HighFunction hfunction = null;
    ClangTokenGroup docroot = null;
    public DecompileResults decompileFunction(Function f, DecompInterface decomplib) {
    	// decomplib.setSimplificationStyle("normalize", null);
        // HighFunction hfunction = decomplib.decompileFunction(f);

    	if (searchedList.containsKey(f.getName())) {
    		// Skip decompile if it is already searched
    		//print("Skipped " + f.getName() + "," + searchedList.get(f.getName()) + "\n");
    		addSearchedFunction(f.getName());
    		return null;
    	}
		addCount();
    	searchedList.put(f.getName(), 1);
        DecompileResults decompRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), monitor);
        //String statusMsg = decomplib.getDecompileMessage();
        if(f.getName().contains("str")) {
    		return decompRes;
    	}

        hfunction = decompRes.getHighFunction();
        docroot = decompRes.getCCodeMarkup();
        Stream<String> resLines = decompRes.getDecompiledFunction().getC().lines();
        List<String> result_strncmp = resLines.filter(line -> line.matches(".*strn?cmp.*"))
        		.collect(Collectors.toList());

        if (result_strncmp.size() > 0) {
    		println("Function Name : " + f.getName());
        	result_strncmp.forEach(r -> println(r.toString()));
        }

        
        if (hfunction == null)
        	return null;

        return decompRes;
    }
    /*
    private void decompileFunction(Function func) throws DecompileException, NullPointerException {
    	DecompileOptions options = new DecompileOptions();
    	DecompInterface ifc = new DecompInterface();
    	ifc.setOptions(options);
    	
    	if (!ifc.openProgram(this.currentProgram)) {
    		throw new DecompileException("Decompiler", "Unable to initialize" + ifc.getLastMessage());	
    	}
    	ifc.setSimplificationStyle("normalize");
    	DecompileResults res = ifc.decompileFunction(func, 10, monitor);
    	hfunction = res.getHighFunction();
    	docroot = res.getCCodeMarkup();
    	try {
        	if (res.decompileCompleted()) {
        		//println("decompleteddddd");
        		print(res.getFunction().getEntryPoint().toString());
        		println(res.getDecompiledFunction().getC());
            	//String decomp = res.getDecompiledFunction().getC();
        	}    		
    	} catch (NullPointerException e){
    		println("error :" + e + " at " + res.getFunction().getName());
    	}
    }
    */
    
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decomplib = new DecompInterface();
        
		DecompileOptions options;
		options = new DecompileOptions(); 
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null,opt,program);    	
		}
        decomplib.setOptions(options);
        
		decomplib.toggleCCode(true);
		decomplib.toggleSyntaxTree(true);
		decomplib.setSimplificationStyle("decompile");
		
		return decomplib;
	}


	private void printIncomingCalls(Function function, DecompInterface decomplib) throws CancelledException, NullPointerException, DecompileException {
		
		Address functionAddress = function.getEntryPoint();
		FunctionSignatureFieldLocation location =
			new FunctionSignatureFieldLocation(function.getProgram(), functionAddress);
		Set<Address> addresses = ReferenceUtils.getReferenceAddresses(location, monitor);
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Set<Function> callingFunctions = new HashSet<>();
		for (Address fromAddress : addresses) {
			Function callerFunction = functionManager.getFunctionContaining(fromAddress);
			if (callerFunction != null) {
				callingFunctions.add(callerFunction);
			}
		}

		// sort them by address
		List<Function> list = new ArrayList<>(callingFunctions);
		Collections.sort(list, (f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()));

		for (Function f : list) {
			//println("Incoming Function Call: " + f.getName() + " @ " + f.getEntryPoint());
	    	decompileFunction(f, decomplib);
	    	// Step C
	    	//printIncomingCalls(f, decomplib);
		}
	}

	private void printOutgoingCalls(Function function, DecompInterface decomplib) throws NullPointerException, DecompileException {
		AddressSetView functionBody = function.getBody();
		Set<Reference> references = getReferencesFrom(currentProgram, functionBody);
		Set<Function> outgoingFunctions = new HashSet<>();
		FunctionManager functionManager = currentProgram.getFunctionManager();
		for (Reference reference : references) {
			Address toAddress = reference.getToAddress();
			Function calledFunction = functionManager.getFunctionAt(toAddress);
			maybeAddIncomingFunction(outgoingFunctions, reference, calledFunction);
		}
		// sort them by address
		List<Function> list = new ArrayList<>(outgoingFunctions);
		Collections.sort(list, (f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()));

		for (Function f : list) {
			//println("Outgoing Function Call: " + f.getName() + " @ " + f.getEntryPoint());
	    	decompileFunction(f, decomplib);
	    	// Step C
	    	printOutgoingCalls(f, decomplib);
		}
	}

	private void maybeAddIncomingFunction(Set<Function> incomingFunctions, Reference reference,
			Function calledFunction) {
		if (calledFunction != null) {
			incomingFunctions.add(calledFunction);
		}
		else if (isCallReference(reference)) {
			// we have a call reference, but no function
			//println("Outgoing function call with no function from " + reference.getFromAddress() +
			//	" to " + reference.getToAddress());
		}
	}

	private boolean isCallReference(Reference reference) {
		RefType type = reference.getReferenceType();
		if (type.isCall()) {
			return true;
		}

		if (type.isIndirect()) {
			Listing listing = currentProgram.getListing();
			Instruction instruction = listing.getInstructionAt(reference.getFromAddress());
			if (instruction != null) {
				FlowType flowType = instruction.getFlowType();
				return flowType.isCall();
			}
		}

		return false;
	}

	private Set<Reference> getReferencesFrom(Program program, AddressSetView addresses) {
		Set<Reference> set = new HashSet<>();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator addressIterator = addresses.getAddresses(true);
		while (addressIterator.hasNext()) {
			Address address = addressIterator.next();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			if (referencesFrom != null) {
				for (Reference reference : referencesFrom) {
					set.add(reference);
				}
			}
		}
		return set;
	}

	private Function getCurrentFunction() {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		return functionManager.getFunctionContaining(currentAddress);
	}
 
}