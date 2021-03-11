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
import java.util.regex.*;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
 

public class YodaGetStrcmpMemsetUserInput extends GhidraScript {

    private HashMap<String, Integer> searchedList = new HashMap<String, Integer>();
    private int searchedCount = 0;
    private int candidateCount = 0;
    private int maxDepth = 2;
	//logger
    private Logger logger = Logger.getLogger("MyLog");
    private FileHandler fh;  
    
     /**
     * @throws Exception 
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() throws Exception {
        monitor.setMessage("Counting symbols...");

        /*DefinedStringIterator definedStringIterator = new DefinedStringIterator(state.getCurrentProgram(), false);
		while (definedStringIterator.hasNext()) {
			FoundString string = definedStringIterator.next();
			Address address = string.getAddress();

		}*/

        LocalDateTime date = LocalDateTime.now();
        DateTimeFormatter formatter_day = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        DateTimeFormatter formatter_time = DateTimeFormatter.ofPattern("HH-mm");
        String homepath = "C:/Users/MinamiYoda/Documents/Program/firmware/docker/result/files/"+date.format(formatter_day)+"/";
        String projectName = this.getProgramFile().getName();
        String FirmwareMaker = this.getProgramFile().getPath();
        FirmwareMaker = FirmwareMaker.substring(61).replace("\\", "_").replace(".bin", "");
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
        
		//logger
        try {  

            // This block configure the logger with handler and formatter  append true
        	fh = new FileHandler( directory.toString() + "/" + date.format(formatter_time) + ".log", true);
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
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
            //FoundString foundString = iter.next();
            //println(sym.getName()); print all symbol
            //if (sym != null && sym.getName().contains("str")) {

        	Address addr = sym.getAddress();
            //println("socket() @ " + addr.toString());
        	Listing listing = state.getCurrentProgram().getListing();
        	Function func = listing.getFunctionContaining(addr);

        	FlatDecompilerAPI decomplib = setUpDecompiler();

            if (sym != null && sym.getName().matches("strn?cmp")) {
    			//don't start function search if it's already searched as start point
    	    	if (searchedList.containsKey(sym.getName())) {
    	    		// Skip decompile if it is already searched
    	    		//print("Skipped " + f.getName() + "," + searchedList.get(f.getName()) + "\n");
    	    		searchedList.put(sym.getName(), searchedList.get(sym.getName())+1);
    				continue;
    	    	}
    	    	searchedList.put(sym.getName(), 1);
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
        				printIncomingCallsInit(refFunc, decomplib);
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

    }

    
    private void addSearchedCount() {
    	searchedCount += 1;
    }
    
    private int getSearchedCount() {
    	return searchedCount;
    }
    
    private void addCondidateCount() {
    	candidateCount += 1;
    	logger.info("candidate"+ candidateCount);
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
            List<String> result_strncmp_etc = new ArrayList<String>(); //not abobe
            
            
            logger.info("\n\n\nStart" + f.getName());
            
            boolean found = false;
            String matched = "";

     		addSearchedCount();
            //strcmp("password", Stack) �ǂ��炩�����ߍ��ݕ�����ł��邱��["'].*["'] -> ("password", hogehoge) ��(hogehoge,'password')��������
            for(String str: decompiled) {
            	//mac: �f�R���p�C�����ʂɖ��ߍ��ݕ����񂪂łĂ��邪�Cwin��PTR__�ŕ\�������̂Œ���
            	if(str.contains("str")) {
            		//debug
            		//println("ORG:"+str);
            		//logger.info(str);
            	}
                String regex = ".*strn?cmp\\((.*,[^\"'].*[^\"']|[^\"'].*[^\"'],.*)\\).*";
                Pattern p = Pattern.compile(regex);
                Matcher m = p.matcher(str);
                if (m.find()){
                	//logger.info(str);
                	//println(str);
                	String matchstr = m.group();
                  if(m.group(1).contains("param") || m.group(1).contains("Stack") || m.group(1).contains("DAT") || m.group(1).contains("local")) {

                      String regex2 = "['\"].*[\"']";
                      Pattern p2 = Pattern.compile(regex2);
                      Matcher m2_embeddedString = p2.matcher(m.group(1));
                      if(m2_embeddedString.find()) {
                    	  if(m2_embeddedString.group(0).length() > 4) { //embedded string is morethen 4 include quatation
                    		  matched = m.group(1);
                    		  logger.info("matched line: " + matched);
                    		  println("matched line: " + matched);
                              String var = matched;
                              var = var.replaceAll("['\"].*[\"']|,|\\(.*\\)|\\*", ""); 
                              if(!result_strncmp.contains(var)) { 
                            	  logger.info(str);
                                  result_strncmp.add(var);
                                  found = true;
                              }
                    	  }
                      }
                    	 
                  }else {
                      String var = m.group(1);
                      var = var.replaceAll("['\"].*[\"']|,|\\(.*\\)|\\*", ""); 
                      if(!result_strncmp_etc.contains(var)) { 
                    	  logger.info("not matched;"+str);
                    	  result_strncmp_etc.add(var);
                      }                   
                	  
                  }
                  
                }	
            }
            //�ϐ����̂Ƃ肾��
            String rootValue = "";
            
            for(String var : result_strncmp) {  
            	logger.info("varname"+var);
                //first low that val appers
            	if(found) {
               	 	rootValue = checkParentValue(var, decompiled, f, flatApi); 
               	 	logger.info("rootvalue" + rootValue); 
            	}
            }
            
            
            for(String var : result_strncmp_etc) {  
            	logger.info("varname etc "+var);
                //first low that val appers
           	 	rootValue = checkParentValue(var, decompiled, f, flatApi); 
           	 	logger.info("rootvalue" + rootValue); 
            }
            
            logger.info("End\n\n\n");
        
            
            if (hfunction == null)
            	return null;
        } catch (NullPointerException e){
        	return null;
        }

        return null;
    }

	
	private String checkParentValue(String var, List<String> decompiled, Function f, FlatDecompilerAPI flatApi) {

		for(String line :decompiled) {
			String right  = "";
			String left   = "";
	     	//���Ԃ�̕ϐ���������ۂ�������o��
	         //�ォ��p�[�X���āA�ϐ��̑�����𒲂ׂ�
    		line = line.replaceAll("[\\(\\)\"\\^\\[\\]\";]", "."); 
    		try {
    	     	if (!var.contains("'") && !var.contains("/") && var.length() > 2 && line.matches("[^\\(]*" +var+ ".* = .*")) {//����ȊO�̕ϐ��Ȃ�������Ă��邩���ׂ�
    	     		// hoge = var;
    	     		// pcvar��
    	     		//strncmp���ŏ�����������Ȃ�
    	   			right = getVariableAndContent(line, true);
    	   			left = getVariableAndContent(line, false);
    	   			logger.info("right"+right);
    	   			logger.info("hoge"+left);
    	     	}    			
    		}catch (Exception e) {
    			logger.info("error happened to reach root");
	     		return "none";
	     	}
        	if(right.length() > 0) {
             	   addCondidateCount();
                if(right.contains("memset")) {
    	            logger.info("Child Function:"+ f.getName());
    	           	logger.info("Strcmp: "+ var);
    	   			logger.info(line);
                	logger.info("memset!!!"+right);
                	return right;
                }else if(right.contains("uStack") && left.contains("0x")) {
    	            logger.info("Child Function:"+ f.getName());
    	           	logger.info("Strcmp: "+ var);
    	   			logger.info(line);
                	logger.info("uStack!!!"+right);
                	return right;
                }else if(right.matches("param_\\d")) {
        			String childFunctionName = f.getName();
        			int paramN = 0;
        			try {
        				paramN = parseInt(right.replaceAll("param_", ""));
        				logger.info("right" + paramN);
        			}catch (NullPointerException e){
        				logger.info("unyaa");
        			}
        			
        			logger.info("printIncomingCalls(f, decomplib, f.getName(),paramN);"+ f.getName() + paramN);
     
                	try {
                		printIncomingCalls(f, f.getName(), paramN, flatApi, maxDepth);
                	} catch(CancelledException e) {
                		println("cancelled expection at 387" + e);
                	} catch(DecompileException e) {
                		println("cancelled expection at 387" + e);
                	} catch(NullPointerException e) {
                		println("cancelled expection at 387" + e);
                	}
                }else {
                	return null;
                	//strcmp�̕ϐ������̑������������e����L�ȊO�̕ϐ���������A���̕ϐ��ōēx�T�����Ă݂�
                	//return checkParentValue(right, decompiled, f, flatApi, depth); 
                }
                break;
        	}else {
        		continue;
        	}
        }
		return null;
	}

    public DecompileResults decompileFunctionRecursive(Function f, String childFunctionName, int childVar, FlatDecompilerAPI flatApi, int depth) {

        try {


            Stream<String> resLines = null;
			try {
				resLines = functionDecompile(f, flatApi).lines();
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

            List<String> decompiled = resLines.collect(Collectors.toList());
            //variables
            List<String> result_strncmp = new ArrayList<String>();
            boolean found = false;
            String matched = "";
            String[] params = new String[10]; 
            String varToBackdoor = "";
            //�@strcmp("password", Stack) �ǂ��炩�����ߍ��ݕ�����ł��邱��["'].*["'] -> ("password", hogehoge) ��(hogehoge,'password')��������
            logger.info("childFunctionName is "+childFunctionName);
            for(String str: decompiled) {
            	if (str.contains(childFunctionName) || str.contains(childFunctionName.replaceAll("\\(|\\)", "_"))) {
            		logger.info(f.getName());
            		logger.info("child function" + str);
            		logger.info("child var" + childVar);
            		params = str.split(",");
            		varToBackdoor = params[childVar];
            		logger.info("varToBackdoor" + varToBackdoor);
                    //first low that val appers
            		
            		String res = checkParentValue(varToBackdoor,decompiled, f, flatApi);
                    
            		if(res != null) {
                    	try {
                    		printIncomingCalls(f, f.getName(),childVar, flatApi, depth);
                    	} catch(CancelledException e) {
                    		println("cancelled expection at 387" + e);
                    	} catch(DecompileException e) {
                    		println("cancelled expection at 387" + e);
                    	} catch(NullPointerException e) {
                    		println("cancelled expection at 387" + e);
                    	}
            		}else {
            			logger.info("result" + res);
            		}
            	}

            }
           if(found) {
         		addSearchedCount();
           }
            
            if (hfunction == null)
            	return null;
        } catch (NullPointerException e){
        	return null;
        }

        return null;
    }
    
    
    private String getVariableAndContent(String line,boolean content) {
    	String left = line.replaceAll(" = .*", ""); 
    	String right = line.replaceAll(".* = |;|\\*|\\+|\\)|\\(", ""); 

    	if(content) {
    		return right;
    	}else {
    		return left;
    	}
    }


	private FlatDecompilerAPI setUpDecompiler() throws Exception {
		FlatDecompilerAPI decompApi = new FlatDecompilerAPI(this);
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
	    	if (searchedList.containsKey(f.getName())) {
	    		// Skip decompile if it is already searched
	    		//print("Skipped " + f.getName() + "," + searchedList.get(f.getName()) + "\n");
	    		searchedList.put(f.getName(), searchedList.get(f.getName())+1);
	    		return true;
	    	}
	    	searchedList.put(f.getName(), 1);
			println("printIncomingCallsInit: " + f.getName() + " @ " + f.getEntryPoint());
			decompileFunction2(f, flatApi);
	    	//decompileFunctionRecursive(f, decomplib);
	    	// Step C
	    	//printIncomingCalls(f, decomplib, depth);
//
	    	// Step C
	    	//printOutgoingCalls(f, decomplib, depth);
		}
		return true;
	}
	
	private boolean printIncomingCalls(Function function,  String childFunctionName, int paramN, FlatDecompilerAPI flatApi, int depth) throws CancelledException, NullPointerException, DecompileException {
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
			println("Incoming Function Call: " + f.getName() + " @ " + f.getEntryPoint());
			decompileFunctionRecursive(f, childFunctionName, paramN, flatApi, depth);
	    	// Step C
	    	//printIncomingCalls(f, decomplib, "now", 2);
//
	    	// Step C
	    	//printOutgoingCalls(f, decomplib, depth);
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
}