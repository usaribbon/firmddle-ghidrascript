package yoda.ghidra.api;

//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.io.File;
import java.io.IOException;
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
import ghidra.program.flatapi.*;
import ghidra.base.project.*;
import java.util.regex.*;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.Logger;


public class NetWorkFunction extends GhidraScript {

  private HashMap<String, Integer> searchedList = new HashMap<String, Integer>();
  private int searchedCount = 0;
  private int candidateCount = 0;
	//logger
  private Logger logger = Logger.getLogger("MyLog");
  private FileHandler fh;
  private FlatDecompilerAPI decompApi;
  private TaskMonitor monitor;
  private GhidraState state;
  private HashMap<String, String> result = new HashMap<>();
  private int MaxDepth = 3;
  
   /**
   * @throws Exception 
   * @see ghidra.app.script.GhidraScript#run()
   */
  public HashMap<String,String> getVals(FlatDecompilerAPI api, GhidraState s, TaskMonitor m, Program c, int depth) throws Exception {
	  decompApi = api;
	  state = s;
	  monitor = m;
	  currentProgram = c;
	  MaxDepth = depth;

      //reset 
      searchedList = new HashMap<String, Integer>();
      searchedCount = 0;
      candidateCount = 0;
      
	  /* FILE LOGGER */
	  /*
      LocalDateTime date = LocalDateTime.now();
      DateTimeFormatter formatter_day = DateTimeFormatter.ofPattern("yyyy-MM-dd");
      DateTimeFormatter formatter_time = DateTimeFormatter.ofPattern("HH-mm");
      String homepath = "C:/Users/MinamiYoda/Documents/Program/firmware/docker/result/files/Yoda20220310GetFunctionSummury/"+date.format(formatter_day)+"/";

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
      
		//logger
      try {  

          // This block configure the logger with handler and formatter  append true
      	fh = new FileHandler( directory.toString() + "/" + date.format(formatter_time) + "-networkfunction.log", true);
          logger.addHandler(fh);
          fh.setFormatter(new MyCustomFormatter()); 

      } catch (SecurityException e) {  
          e.printStackTrace();  
      } catch (IOException e) {  
          e.printStackTrace();  
      } 

      */
      
      //measure running time
      long runningTimeStart = System.nanoTime();
      
      SymbolTable st = state.getCurrentProgram().getSymbolTable();
      SymbolIterator iter = st.getSymbolIterator(true);
      
      decompApi = setUpDecompiler();
  	
      while (iter.hasNext() && !monitor.isCancelled()) {
          Symbol sym = iter.next();
          //FoundString foundString = iter.next();
          //println(sym.getName()); print all symbol
          //if (sym != null && sym.getName().contains("str")) {

      	Address addr = sym.getAddress();
          //println("socket() @ " + addr.toString());
      	Listing listing = state.getCurrentProgram().getListing();
      	Function func = listing.getFunctionContaining(addr);

   		addSearchedCount();

   		//該当するシンボルを参照し，参照した関数を出力する
   		if (sym != null && (sym.getName().matches("socket") || sym.getName().matches("revfrom") || sym.getName().matches("sendto") || sym.getName().matches("bind") || sym.getName().matches("recvmsg") || sym.getName().matches("connect") || sym.getName().matches("sendmsg") || sym.getName().matches("connect"))) {
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
         			
      			//decompileFunction2(refFunc, decomplib);
      			
      			//Step B
      			/*try {
      				printOutgoingCalls(refFunc, decomplib, depth);
      			} catch(NullPointerException e){
                  	continue;
                  }*/
      			
      			try {
      				//println(sym.getName());
      				printIncomingCallsInit(refFunc, decompApi);
      			} catch(NullPointerException e){
                  	continue;
                  }
      		}
              
          }//end if symbol found         
      }// end while     
      
      return result;
      
      /* FILE LOGGER*/
      /* logger.info(getCondidateCount() +" functions were chosen as candidate");
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
      decompApi.dispose();

      logger.setUseParentHandlers(false);
      */

  }

  
  private void addSearchedCount() {
  	searchedCount += 1;
  }
  
  private int getSearchedCount() {
  	return searchedCount;
  }
  
  private void addCondidateCount() {
  	candidateCount += 1;
  	//logger.info("candidate"+ candidateCount);
  }
  
  private int getCondidateCount() {
  	return candidateCount;
  }
  
  HighFunction hfunction = null;
  ClangTokenGroup docroot = null;
  public DecompileResults decompileFunction2(Function f, FlatDecompilerAPI flatApi) {
  	// decomplib.setSimplificationStyle("normalize", null);
      // HighFunction hfunction = decomplib.decompileFunction(f);
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
          List<String> result_strncmp_etc = new ArrayList<String>(); //not above
                  
          boolean found = false;
          String matched = "";

          //strcmp("password", Stack) どちらかが埋め込み文字列であること["'].*["'] -> ("password", hogehoge) や(hogehoge,'password')をさがす
          for(String str: decompiled) {
          	//mac: デコンパイル結果に埋め込み文字列がでてくるが，winはPTR__で表示されるので注意
          	if(str.contains("cmp")) {
          		//debug
          		//println("ORG:"+str);
          		//logger.info("ORG:"+str);
          		result.put(f.getName(), str);
          	}
          	/*
              String regex = ".*str.*cmp(.*\".*\".*).*";
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

					      found = true;
					      logger.info(m.group(0));
					      println(m.group(0));
					      
					  }
					}
              }*/	
          }
          
          if(found) {
          	addCondidateCount();
              logger.info("..... " + f.getName() +"\n\n\n");
          }
      
          
          if (hfunction == null)
          	return null;
      } catch (NullPointerException e){
      	logger.info("ERROR@"+ f.getName());
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


	private boolean printIncomingCallsInit(Function function, FlatDecompilerAPI flatApi) throws CancelledException, NullPointerException, DecompileException {
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
	    	printIncomingCalls(f, flatApi, MaxDepth);
		}
		return true;
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
			//println("Incoming Function Call: " + f.getName() + " @ " + f.getEntryPoint());
			//decompileFunctionRecursive(f, childFunctionName, paramN, flatApi, depth);
	    	// Step C
	    	//printIncomingCalls(f, decomplib, "now", 2);
//
	    	// Step C
	    	//printOutgoingCalls(f, decomplib, depth);
			decompileFunction2(f, flatApi);
	    	printIncomingCalls(f, flatApi, depth);
		}
		return true;
	}

	private boolean printOutgoingCalls(Function function, DecompInterface decomplib, String childFunctionName) throws NullPointerException, DecompileException {
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
	    	//decompileFunctionRecurisive(f, decomplib, childFunctionName);
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

	@Override
	protected void run() throws Exception {
		// TODO Auto-generated method stub
		
	}
}
