
// Description: Java 25 Main for testing the CFSec schema instance creation

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

package server.markhome.mcf.v3_1.cfsec.cfsecramtest;

import java.lang.reflect.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.rmi.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.env.ConfigurableEnvironment;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.inz.Inz;
import server.markhome.mcf.v3_1.cflib.inz.InzPathEntry;
import server.markhome.mcf.v3_1.cflib.dbutil.*;

import server.markhome.mcf.v3_1.cfsec.cfsecpub.*;
import server.markhome.mcf.v3_1.cfsec.cfsecpubobj.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsecpubobj.*;
import server.markhome.mcf.v3_1.cfsec.cfsecram.*;

@SpringBootApplication
@ComponentScan(basePackages = {
    "server.markhome.mcf.v3_1.cfsec.cfsecramtest.spring"   // if you have service beans here
})
@EnableAutoConfiguration(exclude = {
})
public class CFSecRamTest
{
    private static final AtomicReference<Properties> systemProperties = new AtomicReference<>(null);
    private static final AtomicReference<Properties> applicationProperties = new AtomicReference<>(null);
    private static final AtomicReference<Properties> userDefaultProperties = new AtomicReference<>(null);
    private static final AtomicReference<Properties> userProperties = new AtomicReference<>(null);
    private static final AtomicReference<Properties> mergedProperties = new AtomicReference<>(null);

    /**
     * Loads the application properties file from the application resources.
     */
    public static Properties getApplicationProperties() {
        if (applicationProperties.get() == null) {
            Properties props = new Properties();
            try (var in = CFSecRamTest.class.getClassLoader().getResourceAsStream("application.properties")) {
                if (in != null) {
                    props.load(in);
                } else {
                    throw new RuntimeException(Inz.x("cfsecramtest.ApplicationPropertiesNotFound"));
                }
            } catch (IOException e) {
                throw new RuntimeException(Inz.x("cfsecramtest.CouldNotLoadApplicationProperties"), e);
            }
            applicationProperties.compareAndSet(null, props);
        }
        return applicationProperties.get();
    }

    /**
     * Loads the system properties, which hopefully haven't had the merge applied yet.
     */
    public static Properties getSystemProperties() {
        if (systemProperties.get() == null) {
            Properties props = new Properties();
            props.putAll(System.getProperties());
            systemProperties.compareAndSet(null, props);
        }
        return systemProperties.get();
    }
  
    /**
     * Loads the user default properties file from the application resources.
     */
    public static Properties getUserDefaultProperties() {
        if (userDefaultProperties.get() == null) {
            Properties props = new Properties();
            try (var in = CFSecRamTest.class.getClassLoader().getResourceAsStream("user-default.properties")) {
                if (in != null) {
                    props.load(in);
                } else {
                    throw new RuntimeException(Inz.x("cfsecramtest.UserDefaultPropertiesNotFound"));
                }
            } catch (IOException e) {
                throw new RuntimeException(Inz.x("cfsecramtest.FailedToLoadUserDefaultProperties"), e);
            }
            userDefaultProperties.compareAndSet(null, props);
        }
        return userDefaultProperties.get();
    }

    /**
     * Loads the user properties file from their home directory.
     */
    public static Properties getUserProperties() {
        if (userProperties.get() == null) {
            Properties props = new Properties();
            File userFile = new File(System.getProperty("user.home"), ".cfsecramtest.properties");
            if (userFile.exists()) {
                try (FileInputStream fis = new FileInputStream(userFile)) {
                    props.load(fis);
                } catch (IOException e) {
                    throw new RuntimeException(Inz.x("cfsecramtest.FailedToLoadUserProperties"), e);
                }
            } else {
                try (var in = CFSecRamTest.class.getClassLoader().getResourceAsStream("user-default.properties")) {
                    if (in != null) {
                        Files.copy(in, userFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                        System.out.println(String.format(Inz.x("cfsecramtest.NewUserPropsFileCreatedAt"), userFile.getAbsolutePath()));
                        System.out.println(Inz.x("cfsecramtest.PleaseCustomizeThisFile"));
                        System.exit(0);
                    }
                    else {
                        var subin = CFSecRamTest.class.getClassLoader().getResourceAsStream("application.properties");
                        if (subin != null) {
                            Files.copy(subin, userFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                            System.out.println(String.format(Inz.x("cfsecramtest.NewUserPropsFileCreatedAt"), userFile.getAbsolutePath()));
                            System.out.println(Inz.x("cfsecramtest.PleaseCustomizeThisFile"));
                            System.exit(0);
                        } else {
                            throw new RuntimeException(Inz.x("cfsecramtest.NeitherUserDefaultNorApplicationPropertiesFound"));
                        }
                    }
                } catch (IOException e) {
                    System.err.println(String.format(Inz.x("cfsecramtest.FailedToCreateUserPropertiesFile"), userFile.getAbsolutePath(), e.getMessage()));
                    System.exit(1);
                }
            }
            userProperties.compareAndSet(null, props);
        }
        return userProperties.get();
    }

    /**
     * Merges the System and User properties, giving preference to the User properties.
     */
    public static Properties getMergedProperties() {
        if (mergedProperties.get() == null) {
            Properties merged = new Properties();
            merged.putAll(getApplicationProperties());
            merged.putAll(getUserDefaultProperties());
            merged.putAll(getSystemProperties());
            merged.putAll(getUserProperties());
            mergedProperties.compareAndSet(null, merged);
        }
        return mergedProperties.get();
    }

    public static void main(String[] args) {
        Inz.addPathEntry(new InzPathEntry("/opt/mcf/v3_1/java" + "/server.markhome.mcf.v3_1.cfsec.cfsecramtest/src/main/resources/" + "/server.markhome.mcf.v3_1.cfsec.cfsecramtest".replace(".","/") + "/langs"));

        // This weird looking cadence ensures that all the sub-property lists are prepared before getMergedProperties() is invoked, ensuring that any errors and exceptions along the way are thrown first and in predictable order
        Properties mergedProperties = getApplicationProperties();
        mergedProperties = getUserDefaultProperties();
        mergedProperties = getSystemProperties();
        mergedProperties = getUserProperties();
        mergedProperties = getMergedProperties();
        System.getProperties().putAll(mergedProperties);

        SpringApplication app = new SpringApplication(CFSecRamTest.class);
        app.addInitializers((applicationContext) -> {
            ConfigurableEnvironment env = applicationContext.getEnvironment();
            env.getPropertySources().addLast(new org.springframework.core.env.PropertiesPropertySource("userProperties", userProperties.get()));
        });
		int finalvalue = 0xf00000;
		CFSecRamSchema jsCFSec = new CFSecRamSchema();
		finalvalue = jsCFSec.initClassMapEntries(finalvalue);
		jsCFSec.setCFSecSchema(jsCFSec);
		jsCFSec.wireTableTableInstances();

		System.err.println("Runtime class codes are " + 0xf00000 + ".." + (finalvalue-1) + " (" + (finalvalue-0xf00000-1) + " tables in total)");
        app.run(args);
    }
}

