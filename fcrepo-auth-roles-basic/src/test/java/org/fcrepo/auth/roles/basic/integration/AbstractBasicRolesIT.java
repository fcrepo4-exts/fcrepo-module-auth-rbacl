/**
 * Copyright 2014 DuraSpace, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

import static org.fcrepo.auth.common.ServletContainerAuthenticationProvider.EVERYONE_NAME;
import static org.slf4j.LoggerFactory.getLogger;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.fcrepo.auth.roles.common.integration.AbstractRolesIT;
import org.fcrepo.auth.roles.common.integration.RolesFadTestObjectBean;
import org.slf4j.Logger;

/**
 * @author Scott Prater
 */
public abstract class AbstractBasicRolesIT extends AbstractRolesIT {

    private static Logger logger = getLogger(AbstractBasicRolesIT.class);

    protected final static String testParent1 = getRandomPid();
    protected final static String testParent2 = getRandomPid();
    protected final static String testParent3 = getRandomPid();
    protected final static String testParent4 = getRandomPid();
    protected final static String testChild1NoACL = getRandomPid();
    protected final static String testChild2WithACL = getRandomPid();
    protected final static String testChild3A = getRandomPid();
    protected final static String testChild3B = getRandomPid();
    protected final static String testChild4WithACL = getRandomPid();
    protected final static String testChild5WithACL = getRandomPid();
    protected final static String tsp1Data = getRandomPid();
    protected final static String tsp2Data = getRandomPid();
    protected final static String tsc1Data = getRandomPid();
    protected final static String tsc2Data = getRandomPid();

    protected final static List<RolesFadTestObjectBean> test_objs =
            defineTestObjects();

    private static List<RolesFadTestObjectBean> defineTestObjects() {

        logger.debug("testParent1: {}", testParent1);
        logger.debug("testParent2: {}", testParent2);
        logger.debug("testParent3: {}", testParent3);
        logger.debug("testParent4: {}", testParent4);
        logger.debug("testChild1NoACL: {}", testChild1NoACL);
        logger.debug("testChild2WithACL: {}", testChild2WithACL);
        logger.debug("testChild3A: {}", testChild3A);
        logger.debug("testChild3B: {}", testChild3B);
        logger.debug("testChild4WithACL: {}", testChild4WithACL);
        logger.debug("testChild5WithACL: {}", testChild5WithACL);
        logger.debug("tsp1Data: {}", tsp1Data);
        logger.debug("tsp2Data: {}", tsp2Data);
        logger.debug("tsc1Data: {}", tsc1Data);
        logger.debug("tsc2Data: {}", tsc2Data);

        final List<RolesFadTestObjectBean> test_objs = new ArrayList<>();
        /* public object with public datastream */
        final RolesFadTestObjectBean objA = new RolesFadTestObjectBean();
        objA.setPath(testParent1);
        objA.addACL(EVERYONE_NAME, "reader");
        objA.addACL("examplereader", "reader");
        objA.addACL("examplewriter", "writer");
        objA.addACL("exampleadmin", "admin");
        objA.addDatastream(tsp1Data, "Test Parent 1, datastream 1,  Hello!");
        test_objs.add(objA);

        /* public object with one public datastream, one restricted datastream */
        final RolesFadTestObjectBean objB = new RolesFadTestObjectBean();
        objB.setPath(testParent2);
        objB.addACL(EVERYONE_NAME, "reader");
        objB.addACL("examplereader", "reader");
        objB.addACL("examplewriter", "writer");
        objB.addACL("exampleadmin", "admin");
        objB.addDatastream(tsp1Data, "Test Parent 2, datastream 1,  Hello!");
        objB.addDatastream(tsp2Data,
                "Test Parent 2, datastream 2,  secret stuff");
        objB.addDatastreamACL(tsp2Data, "examplereader", "reader");
        objB.addDatastreamACL(tsp2Data, "examplewriter", "writer");
        objB.addDatastreamACL(tsp2Data, "exampleadmin", "admin");
        test_objs.add(objB);

        /* public child object with datastream, no ACLs */
        final RolesFadTestObjectBean objC = new RolesFadTestObjectBean();
        objC.setPath(testParent1 + "/" + testChild1NoACL);
        objC.addDatastream(tsc1Data, "Test Child 1, datastream 1,  Hello!");
        test_objs.add(objC);

        /* restricted child object with restricted datastreams */
        final RolesFadTestObjectBean objD = new RolesFadTestObjectBean();
        objD.setPath(testParent1 + "/" + testChild2WithACL);
        objD.addACL("examplereader", "reader");
        objD.addACL("examplewriter", "writer");
        objD.addACL("exampleadmin", "admin");
        objD.addDatastream(tsc1Data,
                "Test Child 2, datastream 1,  really secret stuff");
        objD.addDatastream(tsc2Data,
                "Test Child 2, datastream 2,  really really secret stuff");
        objD.addDatastreamACL(tsc2Data, "examplewriter", "writer");
        objD.addDatastreamACL(tsc2Data, "exampleadmin", "admin");
        test_objs.add(objD);

        /*
         * even more restricted child object, with even more restricted
         * datastreams
         */
        final RolesFadTestObjectBean objE = new RolesFadTestObjectBean();
        objE.setPath(testParent1 + "/" + testChild4WithACL);
        objE.addACL("examplewriter", "writer");
        objE.addACL("exampleadmin", "admin");
        objE.addDatastream(tsc1Data,
                "Test Child 3, datastream 1,  really secret stuff");
        objE.addDatastream(tsc2Data,
                "Test Child 3, datastream 2,  really really secret stuff");
        objE.addDatastreamACL(tsc2Data, "exampleadmin", "admin");
        test_objs.add(objE);

        /* private child object with 1 private datastream, 1 public datastream */
        final RolesFadTestObjectBean objF = new RolesFadTestObjectBean();
        objF.setPath(testParent2 + "/" + testChild5WithACL);
        objF.addACL("exampleadmin", "admin");
        objF.addDatastream(tsc1Data,
                "Test Child 5, datastream 1, burn before reading");
        objF.addDatastream(tsc2Data, "Test Child 5, datastream 2, Hello!");
        objF.addDatastreamACL(tsc2Data, EVERYONE_NAME, "reader");
        test_objs.add(objF);

        /* Public object, restricted datastream */
        final RolesFadTestObjectBean objG = new RolesFadTestObjectBean();
        objG.setPath(testParent3);
        objG.addACL(EVERYONE_NAME, "reader");
        objG.addACL("examplereader", "reader");
        objG.addACL("examplewriter", "writer");
        objG.addACL("exampleadmin", "admin");
        objG.addDatastream(tsp1Data, "Test Parent 3, datastream 1, hello!");
        objG.addDatastream(tsp2Data,
                "Test Parent 3, datastream 2, private stuff");
        objG.addDatastreamACL(tsp2Data, "exampleadmin", "admin");
        test_objs.add(objG);

        final RolesFadTestObjectBean objH = new RolesFadTestObjectBean();
        objH.setPath(testParent3 + "/" + testChild3A);
        objH.addACL("exampleadmin", "admin");
        test_objs.add(objH);

        final RolesFadTestObjectBean objI = new RolesFadTestObjectBean();
        objI.setPath(testParent3 + "/" + testChild3B);
        test_objs.add(objI);

        final RolesFadTestObjectBean objJ = new RolesFadTestObjectBean();
        objJ.setPath(testParent4);
        objJ.addACL("exampleWriterReader", "reader");
        objJ.addACL("exampleWriterReader", "writer");
        test_objs.add(objJ);

        /* restricted child object with restricted parent */
        final RolesFadTestObjectBean objK = new RolesFadTestObjectBean();
        objK.setPath(testParent4 + "/" + testChild4WithACL);
        objK.addACL("examplewriter", "writer");
        objK.addACL("exampleadmin", "admin");
        test_objs.add(objK);

        return test_objs;

    }

    public static String getRandomPid() {
        return UUID.randomUUID().toString();
    }
}
