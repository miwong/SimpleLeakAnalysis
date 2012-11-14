/* Soot - a J*va Optimization Framework
 * Copyright (C) 1997-1999 Raja Vallee-Rai
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Modified by the Sable Research Group and others 1997-1999.  
 * See the 'credits' file distributed with Soot for the complete list of
 * contributors.  (Soot is distributed at http://www.sable.mcgill.ca/soot)
 */


import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import soot.Body;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Value;
import soot.ValueBox;
import soot.jimple.InvokeExpr;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Sources;
import soot.options.Options;

public class SimpleLeakAnalysis
{
	private static String[] activityCallbacks = {"onCreate", "onStart", "onResume", "onRestart", "onPause", "onStop", "onDestroy"};

	public static void main(String[] args) throws FileNotFoundException, IOException
	{		
		if (args.length < 1) {
			System.out.println("Usage: SimpleLeakAnalysis <main class to be analyzed> [options]");
			return;
		}
		
		if (args[0].equals("--list") && args.length == 2) {
			SootClass mClass = Scene.v().loadClassAndSupport(args[1]);
			printClassMethods(mClass);
			return;
		} else {
			/*
			List<String> argsList = new ArrayList<String>(Arrays.asList("-w", "-main-class"));
			argsList.addAll(activities);

			PackManager.v().getPack("wjtp").add(new Transform("wjtp.myTrans", new SceneTransformer() {
	
				protected void internalTransform(String phaseName, Map options) {
					CHATransformer.v().transform();
					CallGraph cg = Scene.v().getCallGraph();
					
					//SootMethod src = Scene.v().getMethod("<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)>");
					//SootClass a = Scene.v().getSootClass("com.utoronto.miwong.leaktest.MainActivity");
					SootMethod src = Scene.v().getMainClass().getMethodByName("leakToSMSDirectly");
	
					Iterator<MethodOrMethodContext> targets = new Targets(cg.edgesOutOf(src));
					//Iterator<MethodOrMethodContext> targets = new Targets(cg.edgesInto(src));
	
					while (targets.hasNext()) {
						SootMethod tgt = (SootMethod)targets.next();
						System.out.println(src + " may call " + tgt);
					}
				}
	
			}));
			
			args = argsList.toArray(new String[0]);
			soot.Main.main(args);
			*/
			
			// Obtain list of activities in application
			List<String> activities = new ArrayList<String>();
			
			try {
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	            DocumentBuilder docBuilder = dbf.newDocumentBuilder();
	            Document manifest = docBuilder.parse(new File(args[0] + "//AndroidManifest.xml"));
	            
	            NodeList manifestNode = manifest.getElementsByTagName("manifest");
	            NamedNodeMap manifestAttr = manifestNode.item(0).getAttributes();
	            String packageName = manifestAttr.getNamedItem("package").getNodeValue();
	            
	            NodeList activityNodes = manifest.getElementsByTagName("activity");
	            
	            for (int i = 0; i < activityNodes.getLength(); i++) {
	            	Node activity = activityNodes.item(i);
	            	String activityName = activity.getAttributes().getNamedItem("android:name").getNodeValue();
	            	
	            	if (activityName.startsWith(".")) {
	            		activityName = packageName + activityName;
	            	}
	            	
	            	activities.add(activityName);
	            }

			} catch (Exception err) {
				System.out.println("Error in obtaining activities: " + err);
			}
			
			// Obtain every possible UI event handler from layout XML file
			List<String> uiCallbacks = new ArrayList<String>();
			
			try {
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	            DocumentBuilder docBuilder = dbf.newDocumentBuilder();
				File layoutFolder = new File(args[0] + "//res/layout");
				
				for (File layoutFile : layoutFolder.listFiles()) {
		            Document layout = docBuilder.parse(layoutFile);
		            
		            NodeList buttons = layout.getElementsByTagName("Button");
		            
		            for (int i = 0; i < buttons.getLength(); i++) {
		            	Node node = buttons.item(i);
		            	NamedNodeMap nodeAttr = node.getAttributes();
		            	
		            	if (nodeAttr != null) {
		            		Node onclick = nodeAttr.getNamedItem("android:onClick");
		            		if (onclick != null) {
		            			uiCallbacks.add(onclick.getNodeValue());
		            		}
		            	}
		            }
				}
				
			} catch (Exception err) {
				System.out.println("Error in obtaining UI event handlers: " + err);
			}
			
			// Whole-program mode
			String[] argsList = {"-w"};
			Options.v().parse(argsList);
			
			PackManager.v().getPack("wjtp").add(new Transform("wjtp.LeakAnalysis", new LeakAnalysis()));
			
			// Add entry points to scene
			List<SootMethod> entryPoints = new ArrayList<SootMethod>();

			for (String activity : activities) {
				SootClass mainClass = Scene.v().forceResolve(activity, SootClass.BODIES);
				mainClass.setApplicationClass();
				Scene.v().loadNecessaryClasses();
			
				// Add activity callbacks as entry points
				for (String callback : activityCallbacks) {
					if (mainClass.declaresMethodByName(callback)) {
						entryPoints.add(mainClass.getMethodByName(callback));
					}
				}
				
				// Add UI event handlers as entry points
				for (String callback : uiCallbacks) {
					if (mainClass.declaresMethodByName(callback)) {
						entryPoints.add(mainClass.getMethodByName(callback));
					}
				}
				
				// Check for implementers of OnClickListener and add as entrypoints
				// TODO: check for other UI listeners (e.g. OnDragListener, etc.)
				SootClass listenerInterface = Scene.v().getSootClass("android.view.View$OnClickListener");
				List<SootClass> listenerClasses = Scene.v().getActiveHierarchy().getImplementersOf(listenerInterface);
				
				for (SootClass listener : listenerClasses) {
					entryPoints.add(listener.getMethodByName("onClick"));
				}
			}
	
			Scene.v().setEntryPoints(entryPoints);
			
			PackManager.v().runPacks();
		}
	}

	private static void printPossibleCallers(SootMethod target) {
		CallGraph cg = Scene.v().getCallGraph();
		Sources sources = new Sources(cg.edgesInto(target));
		while (sources.hasNext()) {
			SootMethod src = (SootMethod)sources.next();
			System.out.println(target + " might be called by " + src);
		}
	}

	/* Doesn't use whole program mode */
	private static void printClassMethods(SootClass mclass) {
		System.out.println(mclass.toString());
		//out = new BufferedWriter(new FileWriter(FILE));

		List<SootMethod> methods = mclass.getMethods();
		Iterator<SootMethod> iter = methods.iterator();

		while (iter.hasNext()) {
			SootMethod m = iter.next();
			if (!m.isConcrete()) {
				continue;
			}

			System.out.println("\t" + m.toString());

			Body b = m.retrieveActiveBody();
			Iterator<ValueBox> iter_v = b.getUseBoxes().iterator();
			while (iter_v.hasNext()) {
				Value v = iter_v.next().getValue();

				if (v instanceof InvokeExpr) {
					InvokeExpr iv = (InvokeExpr) v;
					System.out.println("\t\t" + iv.getMethod().toString());
				}
			}
		}
	}
}