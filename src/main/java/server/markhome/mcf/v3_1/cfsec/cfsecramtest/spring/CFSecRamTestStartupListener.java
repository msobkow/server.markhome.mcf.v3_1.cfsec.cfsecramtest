
// Description: Spring StartupListener for the RamTest program

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecramtest.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecram.*;

@Component
public class CFSecRamTestStartupListener {
    @Autowired
    // @Qualifier("TestCFSec")
    private CFSecRamTestTestSchema testCFSec;

    @EventListener
    public void onApplicationReady(ApplicationReadyEvent event) {
        System.err.println("CFSecRamTest StartupListener tests beginning...");

		ICFSecSchema.getBackingCFSec().wireTableTableInstances();

		ICFSecSchema.getBackingCFSec().bootstrapSchema(ICFSecSchema.getConsolidatedTableInfo());

        System.err.println("Executing testCFSec.performTests()");
        try {
            String response = testCFSec.performTests(null);
            if (response != null) {
                System.err.println("CFSecRamTestTestSchema.performTests() responded: " + response);
            }
            else {
                System.err.println("CFSecRamTestTestSchema.performTests() did not return a response");
            }
        }
        catch (Throwable th) {
            System.err.println("testCFSec.performTests() threw " + th.getClass().getCanonicalName() + " - " + th.getMessage());
            th.printStackTrace(System.err);
        }

        System.err.println("CFSecRamTest StartupListener tests complete.");
    }
}
