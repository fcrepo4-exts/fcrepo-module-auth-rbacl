/*
 * Licensed to DuraSpace under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership.
 *
 * DuraSpace licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.fcrepo.auth.roles.basic.integration;

import static javax.ws.rs.core.Response.Status.CREATED;
import static javax.ws.rs.core.Response.Status.FORBIDDEN;
import static javax.ws.rs.core.Response.Status.GONE;
import static javax.ws.rs.core.Response.Status.NO_CONTENT;
import static javax.ws.rs.core.Response.Status.OK;
import static org.junit.Assert.assertEquals;
import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.util.List;

import org.fcrepo.auth.roles.common.integration.RolesFadTestObjectBean;

import org.apache.http.client.ClientProtocolException;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;

/**
 * Verifies that role for admins is properly enforced.
 *
 * @author Scott Prater
 * @author Gregory Jansen
 */
public class BasicRolesAdminIT extends AbstractBasicRolesIT {

    private static Logger logger = getLogger(BasicRolesAdminIT.class);

    private final static String TESTDS = "admintestds";

    private final static String TESTCHILD = "admintestchild";

    @Override
    protected List<RolesFadTestObjectBean> getTestObjs() {
        return test_objs;
    }

    /* Public object, one open datastream */
    @Test
    public void testAdminCanReadOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals("Admin cannot read testparent1!", OK.getStatusCode(),
                canRead(
                        "exampleadmin", testParent1, true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot write datastream to testparent1!", CREATED
                .getStatusCode(), canAddDS("exampleadmin", testParent1,
                        TESTDS, true));
    }

    @Test
    public void testAdminCanAddChildToOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add child to testparent1!", CREATED
                .getStatusCode(), canAddChild("exampleadmin", testParent1,
                        TESTCHILD, true));
    }

    @Test
    public void testAdminCanAddACLToOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals("Admin cannot add an ACL to testparent1!", CREATED
                .getStatusCode(),
                canAddACL("exampleadmin", testParent1,
                        "EVERYONE", "admin", true));
    }

    /* Public object, one open datastream, one restricted datastream */
    /* object */
    @Test
    public void
    testAdminCanReadOpenObjWithRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals("Admin cannot read testparent2!", OK.getStatusCode(),
                canRead(
                        "exampleadmin", testParent2, true));
    }

    /* open datastream */
    @Test
    public void testAdminCanReadOpenObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read datastream testparent2/tsp1_data!", OK
                .getStatusCode(), canRead("exampleadmin",
                        testParent2 + "/" + tsp1Data,
                        true));
    }

    @Test
    public void
    testAdminCanUpdateOpenObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot update datastream testparent2/tsp1_data!",
                NO_CONTENT
                .getStatusCode(), canUpdateDS("exampleadmin",
                        testParent2,
                        tsp1Data, true));
    }

    @Test
    public void testAdminCanAddACLToOpenObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to datastream testparent2/tsp1_data!",
                CREATED
                .getStatusCode(), canAddACL("exampleadmin",
                        testParent2 + "/" + tsp1Data, "EVERYONE", "admin", true));
    }

    /* restricted datastream */
    @Test
    public void testAdminCanReadOpenObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read restricted datastream testparent2/tsp2_data!",
                OK.getStatusCode(), canRead("exampleadmin",
                        testParent2 + "/" + tsp2Data, true));
    }

    @Test
    public void testAdminCanUpdateOpenObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot update restricted datastream testparent2/tsp2_data!",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        testParent2,
                        tsp2Data, true));
    }

    @Test
    public void testAdminCanAddACLToOpenObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to restricted datastream testparent2/tsp2_data!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent2 + "/" + tsp2Data, "EVERYONE", "admin", true));
    }

    /* Child object (inherits ACL), one open datastream */
    @Test
    public void testAdminCanReadInheritedACLChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read testparent1/testchild1NoACL!", OK
                .getStatusCode(), canRead("exampleadmin",
                        testParent1 + "/" + testChild1NoACL,
                        true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnInheritedACLChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot write datastream to testparent1/testchild1NoACL!",
                CREATED
                .getStatusCode(), canAddDS("exampleadmin",
                        testParent1 + "/" + testChild1NoACL, TESTDS, true));
    }

    @Test
    public void testAdminCanAddChildToInheritedACLChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add child to testparent1/testchild1NoACL!",
                CREATED
                .getStatusCode(), canAddChild("exampleadmin",
                        testParent1 + "/" + testChild1NoACL, TESTCHILD, true));
    }

    @Test
    public void testAdminCanAddACLToInheritedACLChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to testparent1/testchild1NoACL!",
                CREATED
                .getStatusCode(), canAddACL("exampleadmin",
                        testParent1 + "/" + testChild1NoACL, "EVERYONE", "admin",
                        true));
    }

    @Test
    public void testAdminCanReadInheritedACLChildObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read datastream testparent1/testchild1NoACL/tsc1_data!",
                OK.getStatusCode(), canRead("exampleadmin",
                        testParent1 + "/" + testChild1NoACL + "/" + tsc1Data, true));
    }

    @Test
    public void testAdminCanUpdateInheritedACLChildObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot update datastream testparent1/testchild1NoACL/tsc1_data!",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        testParent1 + "/" + testChild1NoACL, tsc1Data, true));
    }

    @Test
    public
    void testAdminCanAddACLToInheritedACLChildObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to datastream testparent1/testchild1NoACL/tsc1_data!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent1 + "/" + testChild1NoACL + "/" + tsc1Data, "EVERYONE",
                        "admin", true));
    }

    /* Restricted child object with own ACL, two restricted datastreams */
    @Test
    public void testAdminCanReadRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read testparent1/testchild2WithACL!", OK
                .getStatusCode(), canRead("exampleadmin",
                        testParent1 + "/" + testChild2WithACL, true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot write datastream to testparent1/testchild2WithACL!",
                CREATED.getStatusCode(), canAddDS("exampleadmin",
                        testParent1 + "/" + testChild2WithACL, TESTDS, true));
    }

    @Test
    public void testAdminCanAddChildToRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add child to testparent1/testchild2WithACL!",
                CREATED.getStatusCode(), canAddChild("exampleadmin",
                        testParent1 + "/" + testChild2WithACL, TESTCHILD, true));
    }

    @Test
    public void testAdminCanAddACLToRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to testparent1/testchild2WithACL!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent1 + "/" + testChild2WithACL, "EVERYONE", "admin",
                        true));
    }

    @Test
    public void testAdminCanReadRestrictedChildObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read datastream testparent1/testchild2WithACL/tsc1_data!",
                OK.getStatusCode(), canRead("exampleadmin",
                        testParent1 + "/" + testChild2WithACL + "/" + tsc1Data, true));
    }

    @Test
    public void testAdminCanUpdateRestrictedChildObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot update datastream testparent1/testchild2WithACL/tsc1_data!",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        testParent1 + "/" + testChild2WithACL, tsc1Data, true));
    }

    @Test
    public void
    testAdminCanAddACLToRestrictedChildObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to datastream testparent1/testchild2WithACL/tsc1_data!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent1 + "/" + testChild2WithACL + "/" + tsc1Data, "EVERYONE",
                        "admin", true));
    }

    /* Even more restricted datastream */
    @Test
    public void
    testAdminCanReadRestrictedChildObjReallyRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read datastream testparent1/testchild2WithACL/tsc2_data!",
                OK.getStatusCode(), canRead("exampleadmin",
                        testParent1 + "/" + testChild2WithACL + "/" + tsc2Data, true));
    }

    @Test
    public
    void
    testAdminCanUpdateRestrictedChildObjReallyRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot update datastream testparent1/testchild2WithACL/tsc2_data!",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        testParent1 + "/" + testChild2WithACL, tsc2Data, true));
    }

    @Test
    public
    void
    testAdminCanAddACLToRestrictedChildObjReallyRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to datastream testparent1/testchild2WithACL/tsc2_data!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent1 + "/" + testChild2WithACL + "/" + tsc2Data, "EVERYONE",
                        "admin", true));
    }

    /* Writer/Admin child object with own ACL, two restricted datastreams */
    @Test
    public void testAdminCanReadWriterRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals("Admin cannot read testparent1/testchild4WithACL!", OK
                .getStatusCode(), canRead("exampleadmin",
                testParent1 + "/" + testChild4WithACL, true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnWriterRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot write datastream to testparent1/testchild4WithACL!",
                CREATED.getStatusCode(), canAddDS("exampleadmin",
                        testParent1 + "/" + testChild4WithACL, TESTDS, true));
    }

    @Test
    public void testAdminCanAddChildToWriterRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add child to testparent1/testchild4WithACL!",
                CREATED.getStatusCode(), canAddChild("exampleadmin",
                        testParent1 + "/" + testChild4WithACL, TESTCHILD, true));
    }

    @Test
    public void testAdminCanAddACLToWriterRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to testparent1/testchild4WithACL!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent1 + "/" + testChild4WithACL, "EVERYONE", "admin",
                        true));
    }

    @Test
    public
    void
    testAdminCanReadWriterRestrictedChildObjWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read datastream testparent1/testchild4WithACL/tsc1_data!",
                OK.getStatusCode(), canRead("exampleadmin",
                        testParent1 + "/" + testChild4WithACL + "/" + tsc1Data, true));
    }

    @Test
    public
    void
    testAdminCanUpdateWriterRestrictedChildObjWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot update datastream testparent1/testchild4WithACL/tsc1_data!",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        testParent1 + "/" + testChild4WithACL, tsc1Data, true));
    }

    @Test
    public
    void
    testAdminCanAddACLToWriterRestrictedChildObjWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to datastream testparent1/testchild4WithACL/tsc1_data!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent1 + "/" + testChild4WithACL + "/" + tsc1Data, "EVERYONE",
                        "admin", true));
    }

    /* Even more restricted datastream */
    @Test
    public
    void
    testAdminCanReadWriterRestrictedChildObjReallyWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read datastream testparent1/testchild4WithACL/tsc2_data!",
                OK.getStatusCode(), canRead("exampleadmin",
                        testParent1 + "/" + testChild4WithACL + "/" + tsc2Data, true));
    }

    @Test
    public
    void
    testAdminCanUpdateWriterRestrictedChildObjReallyWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot update datastream testparent1/testchild4WithACL/tsc2_data!",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        testParent1 + "/" + testChild4WithACL, tsc2Data, true));
    }

    @Test
    public
    void
    testAdminCanAddACLToWriterRestrictedChildObjReallyWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to datastream testparent1/testchild4WithACL/tsc2_data!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent1 + "/" + testChild4WithACL + "/" + tsc2Data, "EVERYONE",
                        "admin", true));
    }

    /* Admin object with public datastream */
    @Test
    public void testAdminCanReadAdminObj() throws ClientProtocolException,
    IOException {
        assertEquals("Admin cannot read testparent2/testChild5WithACL!", OK
                .getStatusCode(), canRead("exampleadmin",
                testParent2 + "/" + testChild5WithACL, true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnAdminObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot write datastream to testparent2/testChild5WithACL!",
                CREATED.getStatusCode(), canAddDS("exampleadmin",
                        testParent2 + "/" + testChild5WithACL, TESTDS, true));
    }

    @Test
    public void testAdminCanAddChildToAdminObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add child to testparent2/testChild5WithACL!",
                CREATED.getStatusCode(), canAddChild("exampleadmin",
                        testParent2 + "/" + testChild5WithACL, TESTCHILD, true));
    }

    @Test
    public void testAdminCanAddACLToAdminObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to testparent2/testChild5WithACL!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent2 + "/" + testChild5WithACL, "EVERYONE", "admin",
                        true));
    }

    @Test
    public void testAdminCanReadAdminObjAdminRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read datastream testparent2/testChild5WithACL/tsc1_data!",
                OK.getStatusCode(), canRead("exampleadmin",
                        testParent2 + "/" + testChild5WithACL + "/" + tsc1Data, true));
    }

    @Test
    public void testAdminCanUpdateAdminObjAdminRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot update datastream testparent2/testChild5WithACL/tsc1_data!",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        testParent2 + "/" + testChild5WithACL, tsc1Data, true));
    }

    @Test
    public void testAdminCanAddACLToAdminObjAdminRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add an ACL to datastream testparent2/testChild5WithACL/tsc1_data!",
                CREATED.getStatusCode(), canAddACL("exampleadmin",
                        testParent2 + "/" + testChild5WithACL + "/" + tsc1Data, "EVERYONE",
                        "admin", true));
    }

    @Test
    public void testAdminCanReadAdminObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot read datastream testparent2/testChild5WithACL/tsc2_data!",
                OK.getStatusCode(), canRead("exampleadmin",
                        testParent2 + "/" + tsp1Data, true));
    }

    @Test
    public void testAdminCannotUpdateAdminObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin should not be allowed to update datastream testparent2/testChild5WithACL/tsc2_data!",
                FORBIDDEN.getStatusCode(), canUpdateDS("exampleadmin",
                        testParent2 + "/" + testChild5WithACL, tsc2Data, true));
    }

    @Test
    public void testAdminCannotAddACLToAdminObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin should not be allowed to add an ACL to datastream testparent2/testChild5WithACL/tsc2_data!",
                FORBIDDEN.getStatusCode(), canAddACL("exampleadmin",
                        testParent2 + "/" + testChild5WithACL + "/" + tsc2Data, "EVERYONE",
                        "admin", true));
    }

    /* Deletions */
    @Test
    public void testAdminCanDeleteOpenObjAndItsDescendants() throws Exception {
        logger.debug("Running testAdminCanDeleteOpenObjAndItsDescendants()");

        // "exampleadmin" must be able to write to '/' (tombstones added on delete)
        final RolesFadTestObjectBean root = new RolesFadTestObjectBean();
        root.setPath("/");
        root.addACL("exampleadmin", "writer");
        addObjectACLs(root);

        assertEquals("Admin cannot delete object testparent3!", NO_CONTENT
                .getStatusCode(),
                     canDelete("exampleadmin", testParent3, true));

        assertEquals(
                "Admin should not be able to read deleted datastream testparent3/tsp1_data!",
                GONE.getStatusCode(), canDelete("exampleadmin",
                        testParent3 + "/" + tsp1Data, true));

        assertEquals(
                "Admin should not be able to read deleted datastream testparent3/tsp2_data!",
                GONE.getStatusCode(), canDelete("exampleadmin",
                        testParent3 + "/" + tsp2Data, true));

        assertEquals(
                "Admin should not be able to read deleted object testparent3/testchild3a!",
                GONE.getStatusCode(), canDelete("exampleadmin",
                        testParent3 + "/" + testChild3A, true));

        assertEquals(
                "Admin should not be able to read deleted object testparent3/testchild3b!",
                GONE.getStatusCode(), canDelete("exampleadmin",
                        testParent3 + "/" + testChild3B, true));

        assertEquals(
                "Fedora Admin should not be able to read deleted datastream testparent3/tsp1_data!",
                GONE.getStatusCode(), canDelete("fedoraAdmin",
                        testParent3 + "/" + tsp1Data, true));

        assertEquals(
                "Fedora Admin should not be able to read deleted datastream testparent3/tsp2_data!",
                GONE.getStatusCode(), canDelete("fedoraAdmin",
                        testParent3 + "/" + tsp2Data, true));

        assertEquals(
                "Fedora Admin should not be able to read deleted object testparent3/testchild3a!",
                GONE.getStatusCode(), canDelete("fedoraAdmin",
                        testParent3 + "/" + testChild3A, true));

        assertEquals(
                "Fedora Admin should not be able to read deleted object testparent3/testchild3b!",
                GONE.getStatusCode(), canDelete("fedoraAdmin",
                        testParent3 + "/" + testChild3B, true));
    }

    /* root node */
    @Test
    public void testAdminCannotReadRootNode()
            throws ClientProtocolException, IOException {
        assertEquals("Admin should not be allowed to read root node!",
                FORBIDDEN
                .getStatusCode(),
                canRead("exampleadmin", "/", true));
    }

    @Test
    public void testAdminCannotWriteDatastreamOnRootNode()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin should not be allowed to write datastream to root node!",
                FORBIDDEN
                .getStatusCode(), canAddDS("exampleadmin", "/", TESTDS, true));
    }

    @Test
    public void testAdminCannotAddACLToRootNode()
            throws ClientProtocolException, IOException {
        assertEquals("Admin should not be allowed to add an ACL to root node!",
                FORBIDDEN
                .getStatusCode(), canAddACL("exampleadmin", "/", "EVERYONE",
                        "admin", true));
    }

    @Ignore("Awaiting bug fix for story 72982948")
    @Test
    public void testAdminCanAddChildToRestrictedChildObjUnderRestrictedParent()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot add child to testparent4/testchild4WithACL!",
                CREATED.getStatusCode(), canAddChild("exampleadmin",
                        testParent4 + "/" + testChild4WithACL, TESTCHILD, true));
    }
}
