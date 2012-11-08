import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import soot.MethodOrMethodContext;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Sources;
import soot.jimple.toolkits.callgraph.TransitiveTargets;


public class LeakAnalysis extends SceneTransformer {
	private CallGraph mCallGraph;
	
	private static final List<String> sourceAPIs = Arrays.asList(
		"<android.provider.Browser: android.database.Cursor getAllVisitedUrls(android.content.ContentResolver)>"
	);
	
	private static final List<String> sinkAPIs = Arrays.asList(
		"<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)>"
	);
	
	public void internalTransform(String phaseName, Map options) {
		CHATransformer.v().transform();
		mCallGraph = Scene.v().getCallGraph();
		TransitiveTargets trans = new TransitiveTargets(mCallGraph);
		
		List<SootMethod> entries = Scene.v().getEntryPoints();
		Iterator<SootMethod> iter = entries.iterator();
		
		while (iter.hasNext()) {
			SootMethod entry = iter.next();
			System.out.println("Processing entrypoint: " + entry.toString());
			Iterator<MethodOrMethodContext> targets = trans.iterator(entry);
			
			while (targets.hasNext()) {
				SootMethod current = (SootMethod)targets.next();
				
				if (sourceAPIs.contains(current.toString())) {
					//System.out.println("Uses source:\t" + current.toString());
					checkTransitiveSources(current, current.toString());
					
					/*
					Iterator<MethodOrMethodContext> sources = new Sources(mCallGraph.edgesInto(current));
					
					while (sources.hasNext()) {						
						SootMethod caller = (SootMethod)sources.next();
						System.out.println("Used by caller: " + caller.toString());
						Iterator<MethodOrMethodContext> callees = trans.iterator(caller);
						
						while (callees.hasNext()) {
							SootMethod callee = (SootMethod)callees.next();
							
							if (callee.toString() == sinkAPIs[0][0]) {
								System.out.println("Leaks to sink: " + callee.toString());
								//System.out.println("Through method: " + caller.toString());
							}
						}
						
						checkTransitiveSources(caller);
					}
					*/		
				}
				
				//if (current.toString() == sinkAPIs[0][0]) {
				//	System.out.println("Uses sink:\t" + current.toString());
				//}
			}
		}
	}
	
	private void checkTransitiveSources(SootMethod method, String apiSource) {
		TransitiveTargets trans = new TransitiveTargets(mCallGraph);
		Iterator<MethodOrMethodContext> sources = new Sources(mCallGraph.edgesInto(method));
		
		while (sources.hasNext()) {
			SootMethod source = (SootMethod)sources.next();
			
			//Iterator<MethodOrMethodContext> callees = new Targets(mCallGraph.edgesOutOf(source));
			Iterator<MethodOrMethodContext> callees = trans.iterator(source);
			
			while (callees.hasNext()) {
				SootMethod callee = (SootMethod)callees.next();
				
				if (sinkAPIs.contains(callee.toString())){
					System.out.println("\nLeak Detected!\nSource:\t" + apiSource + "\nSink:\t" + callee.toString() + "\nMethod:\t" + source.toString());
				}
			}
			
			checkTransitiveSources(source, apiSource);
		}
	}
	
	/*
	public void internalTransform(String phaseName, Map options) {
		CHATransformer.v().transform();
		CallGraph cg = Scene.v().getCallGraph();
		
		SootMethod src = Scene.v().getMainClass().getMethodByName("leakToSMSDirectly");
		//SootMethod src = Scene.v().getMethod("<com.utoronto.miwong.leaktest.MainActivity: void leakToSMSDirectly(android.view.View)>");
		//SootMethod src = Scene.v().getMethod("<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)>");

		Iterator<MethodOrMethodContext> targets = new Targets(cg.edgesOutOf(src));
		//Iterator<MethodOrMethodContext> targets = new Sources(cg.edgesInto(src));
		//TransitiveTargets trans = new TransitiveTargets(cg);
		//Iterator<MethodOrMethodContext> targets = trans.iterator(src);

		while (targets.hasNext()) {
			SootMethod tgt = (SootMethod)targets.next();
			//System.out.println(src + " may call " + tgt);
			System.out.println(tgt);
		}
	}
	*/
}
