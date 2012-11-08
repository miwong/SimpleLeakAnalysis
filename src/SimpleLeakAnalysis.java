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


import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

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
	/*
	private static String[][] sourceAPIs = {
		{"<android.provider.Browser: android.database.Cursor getAllVisitedUrls(android.content.ContentResolver)>", "Web History" }
	};

	private static String[][] sinkAPIs = {
		{"<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)>", "SMS"}
	};
	*/
	
	private static String[] activityCallbacks = {"onCreate", "onStart", "onResume", "onRestart", "onPause", "onStop", "onDestroy"};

	public static void main(String[] args) throws FileNotFoundException, IOException
	{
		List<String> argsList = new ArrayList<String>(Arrays.asList(args));
		argsList.addAll(Arrays.asList(new String[]{
				"-w",
				"-main-class",
				args[0],//main-class
				args[0] //argument classes
		}));
		
		/*
		SootClass mClass = Scene.v().loadClassAndSupport(args[0]);
		printClassMethods(mClass);
		*/
		
		/*
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
		
		PackManager.v().getPack("wjtp").add(new Transform("wjtp.LeakAnalysis", new LeakAnalysis()));
		
		args = argsList.toArray(new String[0]);
		Options.v().parse(args);
		
		SootClass mainClass = Scene.v().forceResolve(args[0], SootClass.BODIES);
		mainClass.setApplicationClass();
		Scene.v().loadNecessaryClasses();
		
		List<SootMethod> entryPoints = new ArrayList<SootMethod>();
		
		// Add activity callbacks as entry points
		for (int i = 0; i < activityCallbacks.length; i++) {
			if (mainClass.declaresMethodByName(activityCallbacks[i])) {
				entryPoints.add(mainClass.getMethodByName(activityCallbacks[i]));
			}
		}
		
		// Find UI callbacks
		entryPoints.add(mainClass.getMethodByName("leakToSMSDirectly"));
		entryPoints.add(mainClass.getMethodByName("leakToSMS"));
		entryPoints.add(mainClass.getMethodByName("getWebHistory"));

		Scene.v().setEntryPoints(entryPoints);
		
		PackManager.v().runPacks();
		
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