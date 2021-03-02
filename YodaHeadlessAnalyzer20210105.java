//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.decompiler.flatapi.*;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.Settings;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.util.*;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.string.FoundString;
import ghidra.util.exception.CancelledException;
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
import ghidra.base.project.*;


public class YodaHeadlessAnalyzer20210105 extends GhidraScript {

    private HashMap<String, Integer> searchedList = new HashMap<String, Integer>();
    private int searchedCount = 0;
    private int candidateCount = 0;
    private int maxDepth = 1;
	//logger
    private Logger logger = Logger.getLogger("MyLog");  
    private FileHandler fh;  

    
     /**
     * @throws CancelledException 
     * @throws DecompileException 
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() throws CancelledException, DecompileException {
        monitor.setMessage("Counting symbols...");

        //enableHeadlessAnalysis(true);  // turn on analysis
        //boolean analysisEnabled = isHeadlessAnalysisEnabled();
        /*DefinedStringIterator definedStringIterator = new DefinedStringIterator(state.getCurrentProgram(), false);
		while (definedStringIterator.hasNext()) {
			FoundString string = definedStringIterator.next();
			Address address = string.getAddress();

		}*/
        LocalDateTime date = LocalDateTime.now();
        DateTimeFormatter formatter_day = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        DateTimeFormatter formatter_time = DateTimeFormatter.ofPattern("HH-mm");
        String homepath = "C:/Users/MinamiYoda/Dropbox/2019/UEC/doc/etc/experiment/"+date.format(formatter_day)+"/";
        String projectName = this.getProgramFile().getName();
        File directory = new File(homepath + projectName);
        if (!directory.exists()){
            boolean dir_made = directory.mkdirs();
            if(dir_made) {
                println(homepath + projectName);
            }else {
            	println("hello");
            }
        }
        
        
    	for (int depth=0; depth<maxDepth;depth++) {
    		println("DEPTH " + (depth+1) + " START");
            //reset 
            searchedList = new HashMap<String, Integer>();
            searchedCount = 0;
            candidateCount = 0;
            
    		//logger
            try {  

                // This block configure the logger with handler and formatter  append true
                fh = new FileHandler( homepath + projectName + "/" + date.format(formatter_time) + ".log", true);
                logger.addHandler(fh);
                SimpleFormatter formatter = new SimpleFormatter();
                fh.setFormatter(formatter); 

            } catch (SecurityException e) {  
                e.printStackTrace();  
            } catch (IOException e) {  
                e.printStackTrace();  
            } 

            //measure running time
            long runningTimeStart = System.nanoTime();

            SymbolTable st = state.getCurrentProgram().getSymbolTable();
            SymbolIterator iter = st.getSymbolIterator(true);
	        while (iter.hasNext() && !monitor.isCancelled()) {
	            Symbol sym = iter.next();
	            //FoundString foundString = iter.next();
	            //println(sym.getName()); print all symbol
	            //if (sym != null && sym.getName().contains("str")) {
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
            			
            			decompileFunction2(refFunc);
            			
            			//Step B
            			/*try {
            				printOutgoingCalls(refFunc, decomplib, depth);
            			} catch(NullPointerException e){
                        	continue;
                        }*/
            			
            			try {
            				printIncomingCallsInit(refFunc, depth);
            			} catch(NullPointerException e){
                        	continue;
                        }
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
                
	            }//end if symbol found         
	        }// end while     
            logger.info(getCondidateCount() +" functions were chosen as candidate");
            logger.info(getSearchedCount() +" functions were searched");

            //measure running time
            long runningTimeEnd = System.nanoTime();
            long timeElapsed = runningTimeEnd - runningTimeStart;
            //measure 
            logger.info( "TIME (nsec) : " + timeElapsed  );
            logger.info( "TIME (msec) : " + timeElapsed / 1000000 );
            logger.info( "TIME (sec) : " +  TimeUnit.NANOSECONDS.toSeconds(timeElapsed));

            //close log
            logger.removeHandler(fh);
            fh.close();
        }//end depth for
        logger.setUseParentHandlers(false);

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
    public DecompileResults decompileFunction2(Function f) {
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

        try {

            Stream<String> resLines = functionDecompile(f).lines();

            List<String> result_strncmp = resLines.filter(line -> line.matches(".*strn?cmp.*"))
            		.collect(Collectors.toList());

            if (result_strncmp.size() > 0) {
            	logger.info("Function Name : " + f.getName());
            	result_strncmp.forEach(r -> logger.info(r.toString()));
            	addCondidateCount();
            }

            
            if (hfunction == null)
            	return null;
            	
        } catch (Exception e){
        	println("error at 265" + e);
        	return null;
        }

        return null;
    }
        
	private String functionDecompile(Function function) throws Exception {
		FlatDecompilerAPI decompApi = new FlatDecompilerAPI(this);
		if(decompApi.getDecompiler() == null) {
			decompApi.initialize();
		}
		
		return decompApi.decompile(function);
	}

    
	private DecompInterface setUpDecompiler(Program program) {
		FlatDecompilerAPI decompApi = new FlatDecompilerAPI(this);
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


	private boolean printIncomingCallsInit(Function function, int depth) throws CancelledException, NullPointerException, DecompileException {
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
	    	decompileFunction2(f);
	    	// Step C
	    	//printIncomingCalls(f, decomplib, depth);
//
	    	// Step C
	    	printOutgoingCalls(f, depth);
		}
		return true;
	}
	
	private boolean printIncomingCalls(Function function, int depth) throws CancelledException, NullPointerException, DecompileException {
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
	    	decompileFunction2(f);
	    	// Step C
	    	//printIncomingCalls(f, decomplib, depth);
//
	    	// Step C
	    	//printOutgoingCalls(f, decomplib, depth);
		}
		return true;
	}

	private boolean printOutgoingCalls(Function function, int depth) throws NullPointerException, DecompileException {
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
	    	decompileFunction2(f);
	    	// Step C
	    	printOutgoingCalls(f, depth);

	    	try {
				printIncomingCalls(f, depth);
			} catch (CancelledException e) {
				continue;
			}

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
