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

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.fcrepo.kernel.modeshape.utils.FedoraTypesUtils.getJcrNode;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import org.fcrepo.http.commons.AbstractResource;
import org.fcrepo.http.commons.api.rdf.HttpResourceConverter;
import org.fcrepo.kernel.api.identifiers.IdentifierConverter;
import org.fcrepo.kernel.api.models.FedoraBinary;
import org.fcrepo.kernel.api.models.FedoraResource;

import org.jvnet.hk2.annotations.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;

import com.codahale.metrics.annotation.Timed;
import com.google.common.annotations.VisibleForTesting;
import org.apache.jena.rdf.model.Resource;

/**
 * RESTful interface to create and manage access roles
 *
 * @author Gregory Jansen
 * @since Sep 5, 2013
 */
@Scope("request")
@Path("/{path: .*}/fcr:accessroles")
public class AccessRoles extends AbstractResource {

    private static final Logger LOGGER = LoggerFactory
            .getLogger(AccessRoles.class);

    protected IdentifierConverter<Resource, FedoraResource> identifierTranslator;


    @Inject
    protected Session session;

    @Inject
    @Optional
    private AccessRolesProvider accessRolesProvider;

    @Context protected Request request;
    @Context protected HttpServletResponse servletResponse;
    @Context protected UriInfo uriInfo;

    protected FedoraResource resource;

    @PathParam("path") protected String externalPath;


    /**
     * Default JAX-RS entry point
     */
    public AccessRoles() {
        super();
    }

    /**
     * Create a new FedoraNodes instance for a given path
     * @param externalPath external path
     */
    @VisibleForTesting
    public AccessRoles(final String externalPath) {
        this.externalPath = externalPath;
    }


    /**
     * @return the accessRolesProvider
     */
    private AccessRolesProvider getAccessRolesProvider() {
        return accessRolesProvider;
    }

    /**
     * Retrieve the roles assigned to each principal on this specific path.
     *
     * @param effective the effective roles
     * @return JSON representation of assignment map
     */
    @GET
    @Produces(APPLICATION_JSON)
    @Timed
    public Response get(@QueryParam("effective") final String effective) {
        LOGGER.debug("Get access roles for: {}", externalPath);
        LOGGER.debug("effective: {}", effective);
        Response.ResponseBuilder response;
        try {
            final Node node;

            if (resource instanceof FedoraBinary) {
                node = getJcrNode(((FedoraBinary) resource()).getDescription());
            } else {
                node = getJcrNode(resource());
            }

            final AccessRolesProvider provider = this.getAccessRolesProvider();
            if (provider == null) {
                LOGGER.debug("accessRolesProvider is null");
                response = Response.status(Status.NOT_FOUND);
            } else {
                final Map<String, Collection<String>> data =
                        provider.getRoles(node, (effective != null));
                if (data == null) {
                    LOGGER.debug("no content response");
                    response = Response.noContent();
                } else {
                    response = Response.ok(data);
                }
            }
        } finally {
            session.logout();
        }
        return response.build();
    }

    /**
     * Apply new role assignments at the specified node.
     *
     * @param data access roles
     * @return response
     * @throws RepositoryException if IllegalArgumentException can not handle
     */
    @POST
    @Consumes(APPLICATION_JSON)
    @Timed
    public Response post(final Map<String, Set<String>> data)
            throws RepositoryException {
        LOGGER.debug("POST Received request param: {}", request);
        Response.ResponseBuilder response;

        try {
            validatePOST(data);

            final FedoraResource resource = resource();

            if (resource instanceof FedoraBinary) {
                this.getAccessRolesProvider().postRoles(getJcrNode(((FedoraBinary) resource).getDescription()), data);
            } else {
                this.getAccessRolesProvider().postRoles(getJcrNode(resource), data);
            }
            session.save();
            LOGGER.debug("Saved access roles {}", data);
            response =
                    Response.created(getUriInfo().getBaseUriBuilder()
                            .path(externalPath).path("fcr:accessroles").build());

        } catch (final IllegalArgumentException e) {
            throw new WebApplicationException(e, Response.status(Status.BAD_REQUEST).build());
        } finally {
            session.logout();
        }

        return response.build();
    }

    /**
     * @param data
     */
    private void validatePOST(final Map<String, Set<String>> data) {
        if (data.isEmpty()) {
            throw new IllegalArgumentException(
                    "Posted access roles must include role assignments");
        }
        for (final Map.Entry<String, Set<String>> entry : data.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null || entry.getValue().isEmpty()) {
                throw new IllegalArgumentException(
                        "Assignments must include principal name and one or more roles");
            }
            if (entry.getKey().trim().length() == 0) {
                throw new IllegalArgumentException(
                        "Principal names cannot be an empty strings or whitespace.");
            }
            for (final String r : entry.getValue()) {
                if (r.trim().length() == 0) {
                    throw new IllegalArgumentException(
                            "Role names cannot be an empty strings or whitespace.");
                }
            }
        }
    }

    /**
     * Delete the access roles and node type.
     * @return response
     * @throws RepositoryException if delete failed
     */
    @DELETE
    @Timed
    public Response deleteNodeType() throws RepositoryException {
        try {

            final Node node;

            if (resource instanceof FedoraBinary) {
                node = getJcrNode(((FedoraBinary) resource()).getDescription());
            } else {
                node = getJcrNode(resource());
            }

            this.getAccessRolesProvider().deleteRoles(node);
            session.save();
            return Response.noContent().build();
        } finally {
            session.logout();
        }
    }

    private UriInfo getUriInfo() {
        return this.uriInfo;
    }

    protected FedoraResource resource() {
        if (resource == null) {
            resource = getResourceFromPath(externalPath);
        }

        return resource;
    }


    protected IdentifierConverter<Resource, FedoraResource> translator() {
        if (identifierTranslator == null) {
            identifierTranslator = new HttpResourceConverter(session,
                    uriInfo.getBaseUriBuilder().clone().path("{path: .*}"));
        }

        return identifierTranslator;
    }

    private FedoraResource getResourceFromPath(final String externalPath) {
        return translator().convert(translator().toDomain(externalPath));
    }

}
