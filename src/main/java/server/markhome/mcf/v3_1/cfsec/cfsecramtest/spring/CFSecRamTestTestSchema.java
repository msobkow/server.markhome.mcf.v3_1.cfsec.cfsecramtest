
// Description: Spring Ram storage tests for CFSec for the RamTest program

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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;

import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecram.*;

@Service("RamTestCFSec")
public class CFSecRamTestTestSchema {
    
    public String performTests(EntityManager em) {
		StringBuffer messages = new StringBuffer("Starting CFSec tests...\n");
		{
			try {
				LocalDateTime now = LocalDateTime.now();
				CFLibDbKeyHash256 adminpid = new CFLibDbKeyHash256("f012301230123012301230123012301230123012301230123012301230123012");
				CFLibDbKeyHash256 mgrpid =   new CFLibDbKeyHash256("fabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc");
				ICFSecSecUser secUserResults = ICFSecSchema.getBackingCFSec().getTableSecUser().readDerived(null, adminpid);
				if( secUserResults == null ) {
					CFSecBuffSecUser newuser = (CFSecBuffSecUser)(ICFSecSchema.getBackingCFSec().getFactorySecUser().newRec());
					newuser.setCreatedByUserId( adminpid );
					newuser.setCreatedAt( now );
					newuser.setUpdatedByUserId( adminpid );
					newuser.setUpdatedAt( now );
					newuser.setPKey(adminpid);
					newuser.setRequiredSecUserId( adminpid );
					newuser.setRequiredRevision( 1 );
					newuser.setRequiredLoginId( "admin" );
					newuser.setRequiredEMailAddress("admin@localhost");
					
					ICFSecSecUser secUserCreated = ICFSecSchema.getBackingCFSec().getTableSecUser().createSecUser(null, newuser);
					if (secUserCreated == null) {
						messages.append("Error creating secuser admin - null returned\n");
					}
					else {
						messages.append("Created admin user: " + secUserCreated.toString() + "\n");
					}
				}
				else {
					messages.append("Admin user already exists: " + secUserResults.toString() + "\n");
				}
			}
			catch (Exception e) {
				String msg = "ERROR: performTests() Caught and rethrew " + e.getClass().getCanonicalName() + " while modifying or creating the 'admin' user - " + e.getMessage();
				messages.append(msg);
				System.err.println(msg);
				e.printStackTrace(System.err);
			}
		}

		ICFSecCluster[] clusterResults = ICFSecSchema.getBackingCFSec().getTableCluster().readAllDerived(null);
		if (clusterResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getClusterTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + clusterResults.length + " entities from CFSec.Cluster\n");
		}

		ICFSecTenant[] tenantResults = ICFSecSchema.getBackingCFSec().getTableTenant().readAllDerived(null);
		if (tenantResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getTenantTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + tenantResults.length + " entities from CFSec.Tenant\n");
		}

		ICFSecISOCcy[] iSOCcyResults = ICFSecSchema.getBackingCFSec().getTableISOCcy().readAllDerived(null);
		if (iSOCcyResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getISOCcyTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + iSOCcyResults.length + " entities from CFSec.ISOCcy\n");
		}

		ICFSecISOCtry[] iSOCtryResults = ICFSecSchema.getBackingCFSec().getTableISOCtry().readAllDerived(null);
		if (iSOCtryResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getISOCtryTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + iSOCtryResults.length + " entities from CFSec.ISOCtry\n");
		}

		ICFSecISOCtryCcy[] iSOCtryCcyResults = ICFSecSchema.getBackingCFSec().getTableISOCtryCcy().readAllDerived(null);
		if (iSOCtryCcyResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getISOCtryCcyTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + iSOCtryCcyResults.length + " entities from CFSec.ISOCtryCcy\n");
		}

		ICFSecISOCtryLang[] iSOCtryLangResults = ICFSecSchema.getBackingCFSec().getTableISOCtryLang().readAllDerived(null);
		if (iSOCtryLangResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getISOCtryLangTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + iSOCtryLangResults.length + " entities from CFSec.ISOCtryLang\n");
		}

		ICFSecISOLang[] iSOLangResults = ICFSecSchema.getBackingCFSec().getTableISOLang().readAllDerived(null);
		if (iSOLangResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getISOLangTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + iSOLangResults.length + " entities from CFSec.ISOLang\n");
		}

		ICFSecISOTZone[] iSOTZoneResults = ICFSecSchema.getBackingCFSec().getTableISOTZone().readAllDerived(null);
		if (iSOTZoneResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getISOTZoneTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + iSOTZoneResults.length + " entities from CFSec.ISOTZone\n");
		}

		ICFSecSecUser[] secUserResults = ICFSecSchema.getBackingCFSec().getTableSecUser().readAllDerived(null);
		if (secUserResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecUserTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secUserResults.length + " entities from CFSec.SecUser\n");
		}

		ICFSecSecUserPassword[] secUserPasswordResults = ICFSecSchema.getBackingCFSec().getTableSecUserPassword().readAllDerived(null);
		if (secUserPasswordResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecUserPasswordTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secUserPasswordResults.length + " entities from CFSec.SecUserPassword\n");
		}

		ICFSecSecUserEMConf[] secUserEMConfResults = ICFSecSchema.getBackingCFSec().getTableSecUserEMConf().readAllDerived(null);
		if (secUserEMConfResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecUserEMConfTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secUserEMConfResults.length + " entities from CFSec.SecUserEMConf\n");
		}

		ICFSecSecUserPWReset[] secUserPWResetResults = ICFSecSchema.getBackingCFSec().getTableSecUserPWReset().readAllDerived(null);
		if (secUserPWResetResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecUserPWResetTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secUserPWResetResults.length + " entities from CFSec.SecUserPWReset\n");
		}

		ICFSecSecUserPWHistory[] secUserPWHistoryResults = ICFSecSchema.getBackingCFSec().getTableSecUserPWHistory().readAllDerived(null);
		if (secUserPWHistoryResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecUserPWHistoryTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secUserPWHistoryResults.length + " entities from CFSec.SecUserPWHistory\n");
		}

		ICFSecSecSysGrp[] secSysGrpResults = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readAllDerived(null);
		if (secSysGrpResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecSysGrpTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secSysGrpResults.length + " entities from CFSec.SecSysGrp\n");
		}

		ICFSecSecSysGrpInc[] secSysGrpIncResults = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().readAllDerived(null);
		if (secSysGrpIncResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecSysGrpIncTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secSysGrpIncResults.length + " entities from CFSec.SecSysGrpInc\n");
		}

		ICFSecSecSysGrpMemb[] secSysGrpMembResults = ICFSecSchema.getBackingCFSec().getTableSecSysGrpMemb().readAllDerived(null);
		if (secSysGrpMembResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecSysGrpMembTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secSysGrpMembResults.length + " entities from CFSec.SecSysGrpMemb\n");
		}

		ICFSecSecClusGrp[] secClusGrpResults = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().readAllDerived(null);
		if (secClusGrpResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecClusGrpTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secClusGrpResults.length + " entities from CFSec.SecClusGrp\n");
		}

		ICFSecSecClusGrpInc[] secClusGrpIncResults = ICFSecSchema.getBackingCFSec().getTableSecClusGrpInc().readAllDerived(null);
		if (secClusGrpIncResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecClusGrpIncTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secClusGrpIncResults.length + " entities from CFSec.SecClusGrpInc\n");
		}

		ICFSecSecClusGrpMemb[] secClusGrpMembResults = ICFSecSchema.getBackingCFSec().getTableSecClusGrpMemb().readAllDerived(null);
		if (secClusGrpMembResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecClusGrpMembTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secClusGrpMembResults.length + " entities from CFSec.SecClusGrpMemb\n");
		}

		ICFSecSecTentGrp[] secTentGrpResults = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().readAllDerived(null);
		if (secTentGrpResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecTentGrpTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secTentGrpResults.length + " entities from CFSec.SecTentGrp\n");
		}

		ICFSecSecTentGrpInc[] secTentGrpIncResults = ICFSecSchema.getBackingCFSec().getTableSecTentGrpInc().readAllDerived(null);
		if (secTentGrpIncResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecTentGrpIncTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secTentGrpIncResults.length + " entities from CFSec.SecTentGrpInc\n");
		}

		ICFSecSecTentGrpMemb[] secTentGrpMembResults = ICFSecSchema.getBackingCFSec().getTableSecTentGrpMemb().readAllDerived(null);
		if (secTentGrpMembResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecTentGrpMembTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secTentGrpMembResults.length + " entities from CFSec.SecTentGrpMemb\n");
		}

		ICFSecSecRole[] secRoleResults = ICFSecSchema.getBackingCFSec().getTableSecRole().readAllDerived(null);
		if (secRoleResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecRoleTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secRoleResults.length + " entities from CFSec.SecRole\n");
		}

		ICFSecSecRoleEnables[] secRoleEnablesResults = ICFSecSchema.getBackingCFSec().getTableSecRoleEnables().readAllDerived(null);
		if (secRoleEnablesResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecRoleEnablesTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secRoleEnablesResults.length + " entities from CFSec.SecRoleEnables\n");
		}

		ICFSecSecRoleMemb[] secRoleMembResults = ICFSecSchema.getBackingCFSec().getTableSecRoleMemb().readAllDerived(null);
		if (secRoleMembResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecRoleMembTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secRoleMembResults.length + " entities from CFSec.SecRoleMemb\n");
		}

		ICFSecSecClusRole[] secClusRoleResults = ICFSecSchema.getBackingCFSec().getTableSecClusRole().readAllDerived(null);
		if (secClusRoleResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecClusRoleTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secClusRoleResults.length + " entities from CFSec.SecClusRole\n");
		}

		ICFSecSecClusRoleMemb[] secClusRoleMembResults = ICFSecSchema.getBackingCFSec().getTableSecClusRoleMemb().readAllDerived(null);
		if (secClusRoleMembResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecClusRoleMembTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secClusRoleMembResults.length + " entities from CFSec.SecClusRoleMemb\n");
		}

		ICFSecSecTentRole[] secTentRoleResults = ICFSecSchema.getBackingCFSec().getTableSecTentRole().readAllDerived(null);
		if (secTentRoleResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecTentRoleTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secTentRoleResults.length + " entities from CFSec.SecTentRole\n");
		}

		ICFSecSecTentRoleMemb[] secTentRoleMembResults = ICFSecSchema.getBackingCFSec().getTableSecTentRoleMemb().readAllDerived(null);
		if (secTentRoleMembResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecTentRoleMembTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secTentRoleMembResults.length + " entities from CFSec.SecTentRoleMemb\n");
		}

		ICFSecSecSession[] secSessionResults = ICFSecSchema.getBackingCFSec().getTableSecSession().readAllDerived(null);
		if (secSessionResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSecSessionTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + secSessionResults.length + " entities from CFSec.SecSession\n");
		}

		ICFSecSysCluster[] sysClusterResults = ICFSecSchema.getBackingCFSec().getTableSysCluster().readAllDerived(null);
		if (sysClusterResults == null) {
			messages.append("Erroneously retrieved null for ICFSecSchema.getSysClusterTable().readAllDerived(null)\n");
		}
		else {
			messages.append("Retrieved " + sysClusterResults.length + " entities from CFSec.SysCluster\n");
		}

		messages.append("CFSec tests complete\n");
		return( messages.toString() );
	}

	// From Google's AI
    /**
     * Computes the SHA-256 hash of a given string and returns it as a hex string.
     *
     * @param text The input string to hash.
     * @return The SHA-256 hash in hexadecimal format.
     */
    public static String computeSHA256(String text) {
        try {
            // Step 1: Get a MessageDigest instance for SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Step 2: Convert the input string to bytes using UTF-8 encoding
            byte[] hashBytes = digest.digest(text.getBytes(StandardCharsets.UTF_8));

            // Step 3: Convert the byte array to a hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                // Convert byte to hex (ensure two characters per byte)
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            // Handle the case where the algorithm is not available (highly unlikely for SHA-256)
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}