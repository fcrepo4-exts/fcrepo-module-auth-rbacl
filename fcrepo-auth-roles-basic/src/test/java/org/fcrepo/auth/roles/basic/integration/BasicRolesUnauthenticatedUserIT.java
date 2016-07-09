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

import static javax.ws.rs.core.Response.Status.FORBIDDEN;
import static javax.ws.rs.core.Response.Status.OK;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.List;

import org.fcrepo.auth.roles.common.integration.RolesFadTestObjectBean;

import org.junit.Test;

/**
 * Verifies that role for unauthenticated users is properly enforced.
 *
 * @author Scott Prater
 * @author Gregory Jansen
 */
public class BasicRolesUnauthenticatedUserIT extends AbstractBasicRolesIT {

    private final static String TESTDS = "uutestds";

    private final static String TESTCHILD = "uutestchild";

    @Override
    protected List<RolesFadTestObjectBean> getTestObjs() {
        return test_objs;
    }

    /* Public object, one open datastream */
    @Test
    public void testUnauthenticatedReaderCanReadOpenObj()
            throws IOException {
        assertEquals("Unauthenticated user cannot read testparent1!", OK
                .getStatusCode(), canRead(null, testParent1, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotWriteDatastreamOnOpenObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to write datastream to testparent1!",
                FORBIDDEN.getStatusCode(), canAddDS(null, testParent1,
                                                    TESTDS, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddChildOnOpenObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add child to testparent1!",
                FORBIDDEN.getStatusCode(), canAddChild(null, testParent1,
                                                    TESTCHILD, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddACLToOpenObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to testparent1!",
                FORBIDDEN.getStatusCode(), canAddACL(null, testParent1,
                                                     "everyone", "admin", false));
    }

    /* Public object, one open datastream, one restricted datastream */
    /* object */
    @Test
    public void
    testUnauthenticatedReaderCanReadOpenObjWithRestrictedDatastream()
            throws IOException {
        assertEquals("Unauthenticated user cannot read testparent2!", OK
                .getStatusCode(), canRead(null, testParent2, false));
    }

    /* open datastream */
    @Test
    public void testUnauthenticatedReaderCanReadOpenObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user cannot read datastream testparent2/tsp1_data!",
                OK.getStatusCode(), canRead(null, testParent2 + "/" + tsp1Data,
                                            false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotUpdateOpenObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to update datastream testparent2/tsp1_data!",
                FORBIDDEN.getStatusCode(), canUpdateDS(null, testParent2,
                                                       tsp1Data, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotAddACLToOpenObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to datastream testparent2/tsp1_data!",
                FORBIDDEN.getStatusCode(), canAddACL(null,
                                                     testParent2 + "/" + tsp1Data, "everyone", "admin", false));
    }

    /* restricted datastream */
    @Test
    public void
    testUnauthenticatedReaderCannotReadOpenObjRestrictedDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to read restricted datastream testparent2/tsp2_data!",
                FORBIDDEN.getStatusCode(), canRead(null,
                                                   testParent2 + "/" + tsp2Data, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotUpdateOpenObjRestrictedDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to update restricted datastream testparent2/tsp2_data!",
                FORBIDDEN.getStatusCode(), canUpdateDS(null, testParent2,
                                                       tsp2Data, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotAddACLToOpenObjRestrictedDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to restricted datastream " +
                        testParent2 + "/tsp2_data!",
                FORBIDDEN.getStatusCode(),
                canAddACL(null,
                          testParent2 + "/" + tsp2Data, "everyone", "admin", false));
    }

    /* Child object (inherits ACL), one open datastream */
    @Test
    public void testUnauthenticatedReaderCanReadInheritedACLChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user cannot read testparent1/testchild1NoACL!",
                OK
                        .getStatusCode(), canRead(null, testParent1 + "/" + testChild1NoACL,
                                                  false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotWriteDatastreamOnInheritedACLChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to write datastream to testparent1/testchild1NoACL!",
                FORBIDDEN.getStatusCode(), canAddDS(null,
                                                    testParent1 + "/" + testChild1NoACL, TESTDS, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotAddChildToInheritedACLChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add child to testparent1/testchild1NoACL!",
                FORBIDDEN.getStatusCode(), canAddChild(null,
                                                    testParent1 + "/" + testChild1NoACL, TESTCHILD, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddACLToInheritedACLChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to testparent1/testchild1NoACL!",
                FORBIDDEN.getStatusCode(), canAddACL(null,
                                                     testParent1 + "/" + testChild1NoACL, "everyone", "admin",
                                                     false));
    }

    @Test
    public void
    testUnauthenticatedReaderCanReadInheritedACLChildObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user cannot read datastream testparent1/testchild1NoACL/tsc1_data!",
                OK.getStatusCode(), canRead(null,
                                            testParent1 + "/" + testChild1NoACL + "/" + tsc1Data, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotUpdateInheritedACLChildObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to update datastream " +
                        testParent1 + "/testchild1NoACL/tsc1_data!",
                FORBIDDEN.getStatusCode(), canUpdateDS(null,
                                                       testParent1 + "/" + testChild1NoACL, tsc1Data, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotAddACLToInheritedACLChildObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to datastream " +
                        testParent1 + "/testchild1NoACL/tsc1_data!",
                FORBIDDEN.getStatusCode(),
                canAddACL(null,
                          testParent1 + "/" + testChild1NoACL + "/" + tsc1Data, "everyone",
                          "admin", false));
    }

    /* Restricted child object with own ACL, two restricted datastreams */
    @Test
    public void testUnauthenticatedReaderCannotReadRestrictedChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to read testparent1/testchild2WithACL!",
                FORBIDDEN.getStatusCode(), canRead(null,
                                                   testParent1 + "/" + testChild2WithACL, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotWriteDatastreamOnRestrictedChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to write datastream to testparent1/testchild2WithACL!",
                FORBIDDEN.getStatusCode(), canAddDS(null,
                                                    testParent1 + "/" + testChild2WithACL, TESTDS, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotAddChildToRestrictedChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add child to testparent1/testchild2WithACL!",
                FORBIDDEN.getStatusCode(), canAddChild(null,
                                                    testParent1 + "/" + testChild2WithACL, TESTCHILD, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddACLToRestrictedChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to testparent1/testchild2WithACL!",
                FORBIDDEN.getStatusCode(), canAddACL(null,
                                                     testParent1 + "/" + testChild2WithACL, "everyone", "admin",
                                                     false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotReadRestrictedChildObjRestrictedDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to read datastream " +
                        testParent1 + "/testchild2WithACL/tsc1_data!",
                FORBIDDEN.getStatusCode(), canRead(null,
                                                   testParent1 + "/" + testChild2WithACL + "/" + tsc1Data, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotUpdateRestrictedChildObjRestrictedDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to update datastream " +
                        testParent1 + "/testchild2WithACL/tsc1_data!",
                FORBIDDEN.getStatusCode(),
                canUpdateDS(null,
                            testParent1 + "/" + testChild2WithACL, tsc1Data, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotAddACLToRestrictedChildObjRestrictedDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to datastream " +
                        testParent1 + "/testchild2WithACL/tsc1_data!",
                FORBIDDEN.getStatusCode(),
                canAddACL(null,
                          testParent1 + "/" + testChild2WithACL + "/" + tsc1Data, "everyone",
                          "admin", false));
    }

    /* Admin object with public datastream */
    @Test
    public void testUnauthenticatedReaderCannotReadAdminObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to read testparent2/testchild5WithACL!",
                FORBIDDEN.getStatusCode(), canRead(null,
                                                   testParent2 + "/" + testChild5WithACL, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotWriteDatastreamOnAdminObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to write datastream to testparent2/testchild5WithACL!",
                FORBIDDEN.getStatusCode(), canAddDS(null,
                                                    testParent2 + "/" + testChild5WithACL, TESTDS, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddChildToAdminObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add child to testparent2/testchild5WithACL!",
                FORBIDDEN.getStatusCode(), canAddChild(null,
                                                    testParent2 + "/" + testChild5WithACL, TESTCHILD, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddACLToAdminObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to testparent2/testchild5WithACL!",
                FORBIDDEN.getStatusCode(), canAddACL(null,
                                                     testParent2 + "/" + testChild5WithACL, "everyone", "admin",
                                                     false));
    }

    @Test
    public void testUnauthenticatedReaderCanReadAdminObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user cannot read datastream testparent2/testchild5WithACL/tsc2_data!",
                OK.getStatusCode(), canRead(null, testParent2 + "/" + tsp1Data,
                                            false));
    }

    @Test
    public void testUnauthenticatedReaderCannotUpdateAdminObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to update datastream " +
                        testParent2 + "/testchild5WithACL/tsc2_data!",
                FORBIDDEN.getStatusCode(),
                canUpdateDS(null,
                            testParent2 + "/" + testChild5WithACL, tsc2Data, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotAddACLToAdminObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to datastream " +
                        testParent2 + "/testchild5WithACL/tsc2_data!",
                FORBIDDEN.getStatusCode(),
                canAddACL(null,
                          testParent2 + "/" + testChild5WithACL + "/" + tsc2Data, "everyone",
                          "admin", false));
    }

    /* Deletions */
    @Test
    public void testUnauthenticatedReaderCannotDeleteOpenObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to delete testparent3!",
                FORBIDDEN.getStatusCode(),
                canDelete(null, testParent3, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotDeleteOpenObjPublicDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to delete datastream testparent3/tsp1_data!",
                FORBIDDEN.getStatusCode(), canDelete(null,
                                                     testParent3 + "/" + tsp1Data, false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotDeleteOpenObjRestrictedDatastream()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to delete datastream testparent3/tsp2_data!",
                FORBIDDEN.getStatusCode(), canDelete(null,
                                                     testParent3 + "/" + tsp2Data, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotDeleteRestrictedChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to delete object testparent3/testchild3a!",
                FORBIDDEN.getStatusCode(), canDelete(null,
                                                     testParent3 + "/" + testChild3A, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotDeleteInheritedACLChildObj()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to delete object testparent3/testchild3b!",
                FORBIDDEN.getStatusCode(), canDelete(null,
                                                     testParent3 + "/" + testChild3B, false));
    }

    /* root node */
    @Test
    public void testUnauthenticatedReaderCannotReadRootNode()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to read root node!",
                FORBIDDEN
                        .getStatusCode(), canRead(null, "/", false));
    }

    @Test
    public void testUnauthenticatedReaderCannotWriteDatastreamOnRootNode()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to write datastream to root node!",
                FORBIDDEN.getStatusCode(), canAddDS(null, "/", TESTDS, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddChildToRootNode()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add child to root node!",
                FORBIDDEN.getStatusCode(), canAddChild(null, "/", TESTCHILD, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddACLToRootNode()
            throws IOException {
        assertEquals(
                "Unauthenticated user should not be allowed to add an ACL to root node!",
                FORBIDDEN.getStatusCode(), canAddACL(null, "/", "everyone",
                                                     "admin", false));
    }
}
