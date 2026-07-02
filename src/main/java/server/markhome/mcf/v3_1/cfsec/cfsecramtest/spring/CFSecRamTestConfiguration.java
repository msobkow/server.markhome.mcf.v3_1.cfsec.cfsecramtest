
// Description: Java 25 Configuration of the RamTest application

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

import java.util.Properties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import server.markhome.mcf.v3_1.cfsec.cfsecpub.*;
import server.markhome.mcf.v3_1.cfsec.cfsecpubobj.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsecpubobj.*;
import server.markhome.mcf.v3_1.cfsec.cfsecram.*;
import server.markhome.mcf.v3_1.cfsec.cfsecramtest.CFSecRamTest;

@Configuration
public class CFSecRamTestConfiguration {
	
	@Bean(name = "appApplicationProperties")
	public Properties appApplicationProperties() {
		return( CFSecRamTest.getApplicationProperties() );
	}
	
	@Bean(name = "appSystemProperties")
	public Properties appSystemProperties() {
		return( CFSecRamTest.getSystemProperties() );
	}

	@Bean(name = "appUserDefaultProperties")
	public Properties appUserDefaultProperties() {
		return( CFSecRamTest.getUserDefaultProperties() );
	}
	
	@Bean(name = "appUserProperties")
	public Properties appUserProperties() {
		return( CFSecRamTest.getUserProperties() );
	}
	
	@Bean(name = "appMergedProperties")
	public Properties appMergedProperties() {
		return( CFSecRamTest.getMergedProperties() );
	}
}
