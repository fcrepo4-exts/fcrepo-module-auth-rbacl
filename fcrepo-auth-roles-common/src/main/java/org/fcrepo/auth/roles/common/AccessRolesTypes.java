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
package org.fcrepo.auth.roles.common;

import java.io.IOException;
import java.net.URL;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.nodetype.NodeType;
import javax.jcr.nodetype.NodeTypeIterator;

import org.fcrepo.http.commons.session.SessionFactory;
import org.fcrepo.kernel.api.exception.RepositoryRuntimeException;
import org.modeshape.jcr.api.nodetype.NodeTypeManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * @author Gregory Jansen
 *
 */
@Component
public class AccessRolesTypes {

    private static final Logger LOGGER = LoggerFactory
            .getLogger(AccessRolesTypes.class);

    @Inject
    private final SessionFactory sessionFactory = null;

    /**
     * Initialize, register role assignment node types.
     *
     * @throws IOException if io exception occurred
     */
    @PostConstruct
    public void setUpRepositoryConfiguration() throws IOException {
        registerNodeTypes(sessionFactory);
    }

    private void registerNodeTypes(final SessionFactory sessions) throws IOException {
        Session session = null;
        try {
            session = sessions.getInternalSession();
            final NodeTypeManager mgr =
                    (NodeTypeManager) session.getWorkspace()
                            .getNodeTypeManager();
            final URL cnd =
                    AccessRoles.class
                            .getResource("/cnd/access-control.cnd");
            final NodeTypeIterator nti =
                    mgr.registerNodeTypes(cnd, true);
            while (nti.hasNext()) {
                final NodeType nt = nti.nextNodeType();
                LOGGER.debug("registered node type: {}", nt.getName());
            }
            session.save();
            LOGGER.debug("Registered access role node types");

        } catch (final RepositoryException e) {
            throw new RepositoryRuntimeException(e);
        } finally {
            if (session != null) {
                session.logout();
            }
        }
    }
}
