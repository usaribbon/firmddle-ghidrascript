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
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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


public class YodaBackdoorCharactristicResearchSearchParentAndChildren202200305 extends GhidraScript {


    private HashMap<String, Integer> searchedList = new HashMap<String, Integer>();
    private int searchedCount = 0;
    private int candidateCount = 0;
    private FlatDecompilerAPI decompApi;
    private int maxDepth = 999999999;
	//logger
    private Logger logger = Logger.getLogger("MyLog");  
    private FileHandler fh;  
    private String candidateFunction = "FUN_000137d0";
    //private String SearchDirection = "Children";//"Children" or "Parent"
    private String SearchDirection = "Parent";//"Children" or "Parent"

    

     /**
     * @throws CancelledException 
     * @throws DecompileException 
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() throws CancelledException, DecompileException {
        monitor.setMessage("Counting symbols...");

        //ICCE-TW2022
        
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
        String homepath = "C:/Users/MinamiYoda/Documents/Program/firmware/docker/result/files/YodaBackdoorCharactristicResearch202200305/"+date.format(formatter_day)+"/";

        String FirmwareMaker = currentProgram.getExecutablePath();
        if(FirmwareMaker.length() > 80) {
            FirmwareMaker = FirmwareMaker.substring(61).replace("\\", "_").replace(":", "").replace("/", "_").replace(".bin", "");
        }else {
            FirmwareMaker = FirmwareMaker.replace("\\", "_").replace(":", "").replace("/", "_").replace(".bin", "");
        }
        File directory = new File(homepath + FirmwareMaker);
        if (!directory.exists()){
            boolean dir_made = directory.mkdirs();
            if(dir_made) {
                println(directory.toString());
            }
        }
        
        
        //reset 
        searchedList = new HashMap<String, Integer>();
        searchedCount = 0;
        candidateCount = 0;
        String logFilePath = "";
		if(SearchDirection == "Parent") {
	        logFilePath =  directory.toString() + "/" + date.format(formatter_time) + "-parent.log";
		}else if(SearchDirection == "Children"){
	        logFilePath =  directory.toString() + "/" + date.format(formatter_time) + "-children.log";
		}
        
		//logger
        try {  

            // This block configure the logger with handler and formatter  append true
        	fh = new FileHandler(logFilePath, true);
            logger.addHandler(fh);
            fh.setFormatter(new MyCustomFormatter()); 

        } catch (SecurityException e) {  
            e.printStackTrace();  
        } catch (IOException e) {  
            e.printStackTrace();  
        } 

        //measure running time
        long runningTimeStart = System.nanoTime();

        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        SymbolIterator iter = st.getSymbolIterator(true);

        try {
			decompApi = setUpDecompiler();
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
    	
        
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
        	Address addr = sym.getAddress();
        	Listing listing = state.getCurrentProgram().getListing();
        	Function func = listing.getFunctionContaining(addr);

            if (sym != null && sym.getName().matches(candidateFunction)) {//

         		addSearchedCount();
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
        			
        			//decompileFunction2(refFunc);
        			
        			//Step B
        			/*try {
        				printOutgoingCalls(refFunc, decomplib, depth);
        			} catch(NullPointerException e){
                    	continue;
                    }*/

        			println("Find Symbol: "+ sym.getName());
        	        logger.info("Find Symbol: "+ sym.getName());
        			try {
        				if(SearchDirection == "Parent") {
        					printIncomingCallsInit(refFunc, maxDepth, decompApi);
        				}else if(SearchDirection == "Children"){
            				printOutgoingInitCalls(refFunc, maxDepth, decompApi);
        				}
        			} catch(NullPointerException e){
                    	continue;
                    }
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
        logger.setUseParentHandlers(false);
        if(getCondidateCount() == 0) {
        	File logFilePathObj = new File(logFilePath);
            //logFilePathObj.delete();
            //directory.delete();
        }


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
    
	private FlatDecompilerAPI setUpDecompiler() throws Exception {
		decompApi = new FlatDecompilerAPI(this);
		if(decompApi.getDecompiler() == null) {
			decompApi.initialize();
		}
		DecompInterface decomplib = decompApi.getDecompiler();

		DecompileOptions options;
		options = new DecompileOptions(); 
        decomplib.setOptions(options);
        
		decomplib.toggleCCode(true);
		decomplib.toggleSyntaxTree(true);
		decomplib.setSimplificationStyle("decompile");
		
		return decompApi;
	}
    
	private String functionDecompile(Function function, FlatDecompilerAPI flatApi) throws Exception {		
		return flatApi.decompile(function);
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


	private boolean printIncomingCalls(Function function, FlatDecompilerAPI flatApi, int depth) throws CancelledException, NullPointerException, DecompileException {
		if(depth == 0) {
			return false;
		}
		depth-=1;

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
			if (searchedList.get(f.getName()) != null) {
	    		// Skip decompile if it is already searched
	    		//print("Skipped " + f.getName() + "," + searchedList.get(f.getName()) + "\n");
	    		searchedList.put(f.getName(), searchedList.get(f.getName())+1);
	    		continue;
	    	}
	    	searchedList.put(f.getName(), 1);
			println("Incoming Children Function Call: " + f.getName() + " @ " + f.getEntryPoint());
			//decompileFunctionRecursive(f, childFunctionName, paramN, flatApi, depth); String childFunctionName, int paramN
	    	// Step C
			depth -= 1;
	    	printIncomingCalls(f, flatApi, depth);
//
	    	// Step C
	    	//printOutgoingCalls(f, decomplib, depth);
		}
		return true;
	}

	private boolean printIncomingCallsInit(Function function, int depth, FlatDecompilerAPI flatApi) throws CancelledException, NullPointerException, DecompileException {
		
		Address functionAddress = function.getEntryPoint();
		FunctionSignatureFieldLocation location =
			new FunctionSignatureFieldLocation(function.getProgram(), functionAddress);
		Set<Address> addresses = ReferenceUtils.getReferenceAddresses(location, monitor);
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Set<Function> callingFunctions = new HashSet<>();
		for (Address fromAddress : addresses) {
			Function callerFunction = functionManager.getFunctionContaining(fromAddress);

			callingFunctions.add(callerFunction);
			/*
			if (callerFunction != null) {
				callingFunctions.add(callerFunction);
			}*/
		}

		// sort them by address
		List<Function> list = new ArrayList<>(callingFunctions);
		//Collections.sort(list, (f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()));

		for (Function f : list) {	
			//don't start function search if it's already searched as start point
	    	if (searchedList.get(f.getName()) != null) {
	    		// Skip decompile if it is already searched
	    		//print("Skipped " + f.getName() + "," + searchedList.get(f.getName()) + "\n");
	    		searchedList.put(f.getName(), searchedList.get(f.getName())+1);
	    		continue;
	    	}
	    	searchedList.put(f.getName(), 1);
	    	//if(f.getName().contains(candidateFunction)) {
				println("Incoming Init Function Call: " + f.getName() + " @ " + f.getEntryPoint());
				logger.info("Incoming Init Function Call: " + f.getName() + " @ " + f.getEntryPoint());

				depth -= 1;
		    	printIncomingCalls(f, flatApi, depth);//their parent
		    	//printOutgoingCalls(f, depth, flatApi);//their children
	    	//}
		}
		return true;
	}
	
	private boolean printOutgoingInitCalls(Function function, int depth, FlatDecompilerAPI flatApi) throws CancelledException, NullPointerException, DecompileException {

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
			if (searchedList.get(f.getName()) != null) {
	    		// Skip decompile if it is already searched
	    		//print("Skipped " + f.getName() + "," + searchedList.get(f.getName()) + "\n");
	    		searchedList.put(f.getName(), searchedList.get(f.getName())+1);
	    		continue;
	    	}
	    	searchedList.put(f.getName(), 1);
			//if( f.getName().contains(candidateFunction)) {
				println("Outgoing Init Function Call: " + f.getName() + " @ " + f.getEntryPoint());
				logger.info("Outgoing Init Function Call: " + f.getName() + " @ " + f.getEntryPoint());
				addCondidateCount();
				println(getCondidateCount() +"depth");
				logger.info(getCondidateCount() +"depth");
			//}else {
				depth -= 1;
		    	printOutgoingCalls(f, depth, flatApi);
			//}

		}
		return true;
	}

	private boolean printOutgoingCalls(Function function, int depth, FlatDecompilerAPI flatApi) throws CancelledException, NullPointerException, DecompileException {

		//println("DEPTH child: " + depth + ", Function: "+function.getName());
		//logger.info("DEPTH child: " + depth + ", Function: "+function.getName());
		//if (depth == 0) {
		//	System.exit(0);
		//	return false;
		//}
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
			if (searchedList.get(f.getName()) != null) {
	    		// Skip decompile if it is already searched
	    		//print("Skipped " + f.getName() + "," + searchedList.get(f.getName()) + "\n");
	    		searchedList.put(f.getName(), searchedList.get(f.getName())+1);
	    		continue;
	    	}
	    	searchedList.put(f.getName(), 1);
			//if( f.getName().contains(candidateFunction)) {
				println("Outgoing Function Children Call: " + f.getName() + " @ " + f.getEntryPoint());
				logger.info("Outgoing Function Children Call: " + f.getName() + " @ " + f.getEntryPoint());
				addCondidateCount();
				println(getCondidateCount() +"depth");
				logger.info(getCondidateCount() +"depth");
			//}else {
				depth -= 1;
		    	printOutgoingCalls(f, depth, flatApi);
			//}

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

	private static class MyCustomFormatter extends Formatter {
        @Override
        public String format(LogRecord record) {
            StringBuffer sb = new StringBuffer();
            sb.append(record.getMessage());
            sb.append("\n");
            return sb.toString();
        }
         
    }
}
