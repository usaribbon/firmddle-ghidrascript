package yoda.ghidra.api;
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
import ghidra.app.script.GhidraState;
import ghidra.docking.settings.Settings;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.util.*;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.string.FoundString;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
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


public class ScanfStrcmpHeadless extends GhidraScript {


    private HashMap<String, Integer> searchedList = new HashMap<String, Integer>();
    private int searchedCount = 0;
    private int candidateCount = 0;
    private FlatDecompilerAPI decompApi;
    private int maxDepth = 3;
	//logger
    private Logger logger = Logger.getLogger("MyLog");  
    private FileHandler fh;  
    private TaskMonitor monitor;
    private GhidraState state;
    
     /**
     * @throws CancelledException 
     * @throws DecompileException 
     * @see ghidra.app.script.GhidraScript#run()
     */
    public void getVals(FlatDecompilerAPI api, GhidraState s, TaskMonitor m, Program c, String logPath) throws Exception {
		decompApi = api;
		state = s;
		monitor = m;
		currentProgram = c;
        monitor.setMessage("Runnning ScanfStrcmp...");

        //reset 
        searchedList = new HashMap<String, Integer>();
        searchedCount = 0;
        candidateCount = 0;
        
        //enableHeadlessAnalysis(true);  // turn on analysis
        //boolean analysisEnabled = isHeadlessAnalysisEnabled();
        /*DefinedStringIterator definedStringIterator = new DefinedStringIterator(state.getCurrentProgram(), false);
		while (definedStringIterator.hasNext()) {
			FoundString string = definedStringIterator.next();
			Address address = string.getAddress();

		}*/

	    /* FILE LOGGER */
        LocalDateTime date = LocalDateTime.now();
        DateTimeFormatter formatter_day = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        DateTimeFormatter formatter_time = DateTimeFormatter.ofPattern("HH-mm");

        String homepath = logPath+"/ScanfStrcmpHeadless/"+date.format(formatter_day)+"/";
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
                //println(directory.toString());
            }
        }
        
        
        //reset 
        searchedList = new HashMap<String, Integer>();
        searchedCount = 0;
        candidateCount = 0;
        
		//logger
        try {  

            // This block configure the logger with handler and formatter  append true
        	fh = new FileHandler( directory.toString() + "/" + date.format(formatter_time) + "-ScanfStrcmpHeadless.log", true);
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

     		addSearchedCount();

            if (sym != null && (sym.getName().matches("sscanf") ||sym.getName().matches("scanf"))) {//sym.getName().matches("printf") || 
                           	
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
        			
        			try {
        				//println("DEPTH Start: " + maxDepth + ", Function: "+ refFunc.getName());
        				//logger.info("DEPTH Start: " + maxDepth + ", Function: "+ refFunc.getName());
        				printIncomingCallsInit(refFunc, maxDepth, decompApi);

        			} catch(NullPointerException e){
                    	continue;
                    }
        		}

            
            }//end if symbol found         
        }// end while  
        /* FILE LOGGER*/
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
        	File logFilePathObj = new File( directory.toString() + "/" + date.format(formatter_time) + "-ScanfStrcmpHeadless.log");
            logFilePathObj.delete();
            directory.delete();
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
    
    HighFunction hfunction = null;
    ClangTokenGroup docroot = null;
    public DecompileResults decompileFunction2(Function f, FlatDecompilerAPI flatApi) {
    	 try {

             Stream<String> resLines = null;
 			try {
 				resLines = functionDecompile(f, flatApi).lines();
 			} catch (Exception e) {
 				// TODO Auto-generated catch block
 				e.printStackTrace();
 			}

             List<String> decompiled = resLines.collect(Collectors.toList());
             //variables
             List<String> result_strncmp = new ArrayList<String>(); //param, stack, data,local
             List<String> result_strncmp_etc = new ArrayList<String>(); //not abobe
             
             
             
             boolean found = false;
             String matched = "";

             //strcmp("password", Stack) どちらかが埋め込み文字列であること["'].*["'] -> ("password", hogehoge) や(hogehoge,'password')をさがす
             for(String str: decompiled) {
				     //println("matched:"+str);
	             		//logger.info(str);
             	//mac: デコンパイル結果に埋め込み文字列がでてくるが，winはPTR__で表示されるので注意
             	if(str.contains("str")) {
            		logger.info("FunctionName:"+f.getName() +", Line:"+str);
             		//debug
             		//println("matched:"+str);
             		//logger.info(str);
             	}
             	
                 String regex = ".*strn?cmp\\((.*,.*,.*|.*,.*)\\).*";
                 Pattern p = Pattern.compile(regex);
                 Matcher m = p.matcher(str);
                 if (m.find()){

 					//logger.info(str);
 					String matchstr = m.group();
 					//m.group(1)はｓｔｒｃｍｐの引数が表示される，0は全文
 					String[] vars = m.group(1).split(",");
 					for(String var: vars) {
 					  if(!result_strncmp.contains(var)) {
 					      result_strncmp.add(var);
 					      //boolean res = checkParentValue(var,str,decompiled);
 					      //if(res) {
 					    //	  found = true;
 					      //}
 					     //println("matched:"+var);
 	             		//logger.info(var);
 					  }
 					}
                 }
             }
             
             
             if (hfunction == null)
             	return null;
         } catch (NullPointerException e){
         	return null;
         }

         return null;
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


	private boolean printIncomingCallsInit(Function function, int depth, FlatDecompilerAPI flatApi) throws CancelledException, NullPointerException, DecompileException {
		
		//println("DEPTH Main: " + depth + ", Function: "+function.getName());
		//logger.info("DEPTH Main: " + depth + ", Function: "+function.getName());
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
			//println("printIncomingCallsInit: " + f.getName() + " @ " + f.getEntryPoint());
			decompileFunction2(f, flatApi);
	    	if(!printOutgoingCalls(f, depth, flatApi)) {
	    		continue;
	    	}
		}
		return false;
	}
	
	private boolean printOutgoingCalls(Function function, int depth, FlatDecompilerAPI flatApi) throws NullPointerException, DecompileException {
		//println("DEPTH child: " + depth + ", Function: "+function.getName());
		//logger.info("DEPTH child: " + depth + ", Function: "+function.getName());
		if (Math.signum(depth) == -1.0) {
			//System.exit(0);
			return false;
		}else {
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
				//logger.info("Outgoing Function Call: " + f.getName() + " @ " + f.getEntryPoint());
				decompileFunction2(f, flatApi);
		    	// Step C
				depth -= 1;
		    	printOutgoingCalls(f, depth, flatApi);
	
		    	/*
		    	try {
					printIncomingCalls(f, depth, flatApi);
				} catch (CancelledException e) {
					continue;
				}*/
	
			}
			return true;
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

	@Override
	protected void run() throws Exception {
		// TODO Auto-generated method stub
		
	}
}
