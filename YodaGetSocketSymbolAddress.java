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
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.concurrent.TimeUnit;

import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.plugin.core.string.*;
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.Settings;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
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
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.string.FoundString;
import ghidra.util.exception.CancelledException;

public class YodaGetSocketSymbolAddress extends GhidraScript {

	private HashMap<String, Integer> searchedList = new HashMap<String, Integer>();
    private int searchedCount = 0;
    private int candidateCount = 0;
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
        int count = 0;


        /*DefinedStringIterator definedStringIterator = new DefinedStringIterator(state.getCurrentProgram(), false);
		while (definedStringIterator.hasNext()) {
			FoundString string = definedStringIterator.next();
			Address address = string.getAddress();

		}*/
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
            
            //FoundString foundString = iter.next();
            //println(sym.getName()); print all symbol
            if (sym != null && sym.getName().matches("socket")) {
            	Address addr = sym.getAddress();
                //println("socket() @ " + addr.toString());
            	Listing listing = state.getCurrentProgram().getListing();
            	Function func = listing.getFunctionContaining(addr);
            	
            	/*Data d = listing.getDataAt(addr(0x404f10));
        		d = listing.getDataAt(addr(0x405d80));
        		dt = d.getBaseDataType();
        		d.ge*/
            	
            	if (func == null) {
            		//println("No Function at address" + currentAddress);
            		continue;
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
            			
            			decompileFunction2(refFunc, decomplib);
            			
            			//Step B
            			try {
            				printOutgoingCalls(refFunc, decomplib, 2);
            			} catch(NullPointerException e){
                        	continue;
                        }
            			try {
            				printIncomingCalls(refFunc, decomplib, 2);
            			} catch(NullPointerException e){
                        	continue;
                        }
            		}
            	}  catch (NullPointerException e){
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
        println(getCondidateCount() +" functions were chosen as candidate");
        println(getSearchedCount() +" functions were searched");

        //measure running time
        long runningTimeEnd = System.nanoTime();
        long timeElapsed = runningTimeEnd - runningTimeStart;
     
        println( "TIME (nsec) : " + timeElapsed  );
        println( "TIME (msec) : " + timeElapsed / 1000000 );
        println( "TIME (sec) : " +  TimeUnit.NANOSECONDS.toSeconds(timeElapsed));
    }
    
    private void addSearchedCount() {
    	searchedCount += 1;
    }
    
    private int getSearchedCount() {
    	return searchedCount;
    }
    
    private void addCondidateCount() {
    	candidateCount += 1;
    }
    
    private int getCondidateCount() {
    	return candidateCount;
    }
    
    HighFunction hfunction = null;
    ClangTokenGroup docroot = null;
    public DecompileResults decompileFunction2(Function f, DecompInterface decomplib) {
    	// decomplib.setSimplificationStyle("normalize", null);
        // HighFunction hfunction = decomplib.decompileFunction(f);
    	if (searchedList.containsKey(f.getName())) {
    		// Skip decompile if it is already searched
    		//print("Skipped " + f.getName() + "," + searchedList.get(f.getName()) + "\n");
    		searchedList.put(f.getName(), searchedList.get(f.getName())+1);
    		return null;
    	}
    	addSearchedCount();
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
        	addCondidateCount();
        }

        
        if (hfunction == null)
        	return null;

        return decompRes;
    }
    
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


	private boolean printIncomingCalls(Function function, DecompInterface decomplib, int depth) throws CancelledException, NullPointerException, DecompileException {
		//println("DEPTH: " + depth);
		if (depth == 0) {
			return false;
		}
		depth -= 1;
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
	    	decompileFunction2(f, decomplib);
	    	// Step C
	    	printIncomingCalls(f, decomplib, depth);
		}
		return true;
	}

	private boolean printOutgoingCalls(Function function, DecompInterface decomplib, int depth) throws NullPointerException, DecompileException {
		//println("DEPTH: " + depth);
		if (depth == 0) {
			return false;
		}
		depth -= 1;
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
	    	decompileFunction2(f, decomplib);
	    	// Step C
	    	printOutgoingCalls(f, decomplib, depth);
		}
		return true;
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
	
	private String getValue(FoundString foundString, Settings settings, Program program,
			ServiceProvider services) throws IllegalArgumentException {

		return (foundString != null && foundString.getLength() > 0)
				? foundString.getDataInstance(
					getCurrentProgram().getMemory()).getStringRepresentation()
				: "";
	}
 
}