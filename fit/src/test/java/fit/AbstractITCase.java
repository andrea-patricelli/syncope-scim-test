package fit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.nimbusds.jose.JWSAlgorithm;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.syncope.client.lib.AnonymousAuthenticationHandler;
import org.apache.syncope.client.lib.SyncopeClient;
import org.apache.syncope.client.lib.SyncopeClientFactoryBean;
import org.apache.syncope.common.keymaster.client.api.ConfParamOps;
import org.apache.syncope.common.keymaster.client.api.DomainOps;
import org.apache.syncope.common.keymaster.client.api.ServiceOps;
import org.apache.syncope.common.keymaster.client.self.SelfKeymasterClientContext;
import org.apache.syncope.common.lib.AnyOperations;
import org.apache.syncope.common.lib.Attr;
import org.apache.syncope.common.lib.SyncopeConstants;
import org.apache.syncope.common.lib.audit.AuditEntry;
import org.apache.syncope.common.lib.policy.*;
import org.apache.syncope.common.lib.request.*;
import org.apache.syncope.common.lib.to.*;
import org.apache.syncope.common.lib.types.*;
import org.apache.syncope.common.rest.api.RESTHeaders;
import org.apache.syncope.common.rest.api.batch.BatchPayloadParser;
import org.apache.syncope.common.rest.api.batch.BatchResponseItem;
import org.apache.syncope.common.rest.api.beans.AuditQuery;
import org.apache.syncope.common.rest.api.beans.ExecSpecs;
import org.apache.syncope.common.rest.api.beans.TaskQuery;
import org.apache.syncope.common.rest.api.service.*;
import org.apache.syncope.common.rest.api.service.wa.*;
import org.junit.jupiter.api.BeforeAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.support.TestPropertySourceUtils;

@SpringJUnitConfig(classes = {SelfKeymasterClientContext.class},
        initializers = AbstractITCase.KeymasterInitializer.class)
@TestPropertySource("classpath:test.properties")
public abstract class AbstractITCase {

    static class KeymasterInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

        @Override
        public void initialize(final ConfigurableApplicationContext ctx) {
            String profiles = ctx.getEnvironment().getProperty("springActiveProfiles");
            if (profiles.contains("zookeeper")) {
                TestPropertySourceUtils.addInlinedPropertiesToEnvironment(
                        ctx, "keymaster.address=127.0.0.1:2181");
            } else {
                TestPropertySourceUtils.addInlinedPropertiesToEnvironment(
                        ctx, "keymaster.address=https://localhost:9443/syncope/rest/keymaster");
            }
            TestPropertySourceUtils.addInlinedPropertiesToEnvironment(
                    ctx, "keymaster.username=anonymous");
            TestPropertySourceUtils.addInlinedPropertiesToEnvironment(
                    ctx, "keymaster.password=4LvK4M4dahCp7f2343FuxV6q");
        }
    }

    protected static final Logger LOG = LoggerFactory.getLogger(AbstractITCase.class);

    protected static final JsonMapper JSON_MAPPER = JsonMapper.builder().findAndAddModules().build();

    protected static final XmlMapper XML_MAPPER = XmlMapper.builder().findAndAddModules().build();

    protected static final YAMLMapper YAML_MAPPER = YAMLMapper.builder().findAndAddModules().build();

    protected static final String ADMIN_UNAME = "admin";

    protected static final String ADMIN_PWD = "password";

    protected static final String ADDRESS = "https://localhost:9443/syncope/rest";

    protected static final String IOV_ADDRESS = "http://localhost:18080/syncope/rest";

    protected static final String ACTUATOR_ADDRESS = "https://localhost:9443/syncope/actuator";

    protected static final String BUILD_TOOLS_ADDRESS = "https://localhost:9443/syncope-fit-build-tools/cxf";

    protected static final String ENV_KEY_CONTENT_TYPE = "jaxrsContentType";

    private static final String MAIL_API_BASE_URL = "http://172.17.0.5:8025/api/v1/messages";

    protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    protected static final String EN_LANGUAGE = "en-US,en;q=0.5";

    protected static final JsonMapper MAPPER = JsonMapper.builder().findAndAddModules().build();

    protected static final int MAX_WAIT_SECONDS = 50;

    protected static String ANONYMOUS_UNAME;

    protected static String ANONYMOUS_KEY;

    protected static String JWS_KEY;

    protected static String JWT_ISSUER;

    protected static JWSAlgorithm JWS_ALGORITHM;

    protected static SyncopeClientFactoryBean clientFactory;

    protected static SyncopeClient adminClient;

    protected static SyncopeClient adminClientIOV;

    protected static SyncopeClient anonymusClient;

    protected static SyncopeService syncopeService;

    protected static ApplicationService applicationService;

    protected static AnyTypeClassService anyTypeClassService;

    protected static AnyTypeService anyTypeService;

    protected static RelationshipTypeService relationshipTypeService;

    protected static RealmService realmService;

    protected static AnyObjectService anyObjectService;

    protected static RoleService roleService;

    protected static DynRealmService dynRealmService;

    protected static UserService userService;

    protected static UserService userServiceIOV;

    protected static UserSelfService userSelfService;

    protected static UserRequestService userRequestService;

    protected static UserWorkflowTaskService userWorkflowTaskService;

    protected static GroupService groupService;

    protected static ResourceService resourceService;

    protected static ConnectorService connectorService;

    protected static AuditService auditService;

    protected static ReportService reportService;

    protected static TaskService taskService;

    protected static TaskService taskServiceIOV;

    protected static ReconciliationService reconciliationService;

    protected static BpmnProcessService bpmnProcessService;

    protected static MailTemplateService mailTemplateService;

    protected static NotificationService notificationService;

    protected static SchemaService schemaService;

    protected static PolicyService policyService;

    protected static AuthModuleService authModuleService;

    protected static SecurityQuestionService securityQuestionService;

    protected static ImplementationService implementationService;

    protected static RemediationService remediationService;

    protected static DelegationService delegationService;

    protected static SRARouteService sraRouteService;

    protected static ClientAppService clientAppService;

    protected static AuthProfileService authProfileService;

    protected static SAML2SPEntityService saml2SPEntityService;

    protected static SAML2IdPEntityService saml2IdPEntityService;

    protected static OIDCJWKSService oidcJWKSService;

    protected static WAConfigService waConfigService;

    protected static GoogleMfaAuthTokenService googleMfaAuthTokenService;

    protected static GoogleMfaAuthAccountService googleMfaAuthAccountService;

    protected static U2FRegistrationService u2fRegistrationService;

    protected static WebAuthnRegistrationService webAuthnRegistrationService;

    protected static ImpersonationService impersonationService;

    @Autowired
    protected ConfParamOps confParamOps;

    @Autowired
    protected ServiceOps serviceOps;

    @Autowired
    protected DomainOps domainOps;

    @BeforeAll
    public static void securitySetup() {
        try (InputStream propStream = new ClassPathResource("/core.properties").getInputStream()) {
            Properties props = new Properties();
            props.load(propStream);

            ANONYMOUS_UNAME = props.getProperty("security.anonymousUser");
            ANONYMOUS_KEY = props.getProperty("security.anonymousKey");
            JWT_ISSUER = props.getProperty("security.jwtIssuer");
            JWS_ALGORITHM = JWSAlgorithm.parse(props.getProperty("security.jwsAlgorithm"));
            JWS_KEY = props.getProperty("security.jwsKey");
        } catch (Exception e) {
            LOG.error("Could not read core.properties", e);
        }

        assertNotNull(ANONYMOUS_UNAME);
        assertNotNull(ANONYMOUS_KEY);
        assertNotNull(JWS_KEY);
        assertNotNull(JWT_ISSUER);

        anonymusClient = clientFactory.create(new AnonymousAuthenticationHandler(ANONYMOUS_UNAME, ANONYMOUS_KEY));

        googleMfaAuthTokenService = anonymusClient.getService(GoogleMfaAuthTokenService.class);
        googleMfaAuthAccountService = anonymusClient.getService(GoogleMfaAuthAccountService.class);
        u2fRegistrationService = anonymusClient.getService(U2FRegistrationService.class);
        webAuthnRegistrationService = anonymusClient.getService(WebAuthnRegistrationService.class);
        impersonationService = anonymusClient.getService(ImpersonationService.class);
    }

    @BeforeAll
    public static void restSetup() {
        System.setProperty("javax.net.ssl.trustStore",
                AbstractITCase.class.getClassLoader().getResource("keystore.jks").getPath());
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        clientFactory = new SyncopeClientFactoryBean().setAddress(ADDRESS);

        String envContentType = System.getProperty(ENV_KEY_CONTENT_TYPE);
        if (StringUtils.isNotBlank(envContentType)) {
            clientFactory.setContentType(envContentType);
        }
        LOG.info("Performing IT with content type {}", clientFactory.getContentType().getMediaType());

        adminClient = clientFactory.create(ADMIN_UNAME, ADMIN_PWD);

        syncopeService = adminClient.getService(SyncopeService.class);
        applicationService = adminClient.getService(ApplicationService.class);
        anyTypeClassService = adminClient.getService(AnyTypeClassService.class);
        anyTypeService = adminClient.getService(AnyTypeService.class);
        relationshipTypeService = adminClient.getService(RelationshipTypeService.class);
        realmService = adminClient.getService(RealmService.class);
        anyObjectService = adminClient.getService(AnyObjectService.class);
        roleService = adminClient.getService(RoleService.class);
        dynRealmService = adminClient.getService(DynRealmService.class);
        userService = adminClient.getService(UserService.class);
        userSelfService = adminClient.getService(UserSelfService.class);
        userRequestService = adminClient.getService(UserRequestService.class);
        userWorkflowTaskService = adminClient.getService(UserWorkflowTaskService.class);
        groupService = adminClient.getService(GroupService.class);
        resourceService = adminClient.getService(ResourceService.class);
        connectorService = adminClient.getService(ConnectorService.class);
        auditService = adminClient.getService(AuditService.class);
        reportService = adminClient.getService(ReportService.class);
        taskService = adminClient.getService(TaskService.class);
        reconciliationService = adminClient.getService(ReconciliationService.class);
        policyService = adminClient.getService(PolicyService.class);
        bpmnProcessService = adminClient.getService(BpmnProcessService.class);
        mailTemplateService = adminClient.getService(MailTemplateService.class);
        notificationService = adminClient.getService(NotificationService.class);
        schemaService = adminClient.getService(SchemaService.class);
        securityQuestionService = adminClient.getService(SecurityQuestionService.class);
        implementationService = adminClient.getService(ImplementationService.class);
        remediationService = adminClient.getService(RemediationService.class);
        delegationService = adminClient.getService(DelegationService.class);
        sraRouteService = adminClient.getService(SRARouteService.class);
        clientAppService = adminClient.getService(ClientAppService.class);
        authModuleService = adminClient.getService(AuthModuleService.class);
        saml2SPEntityService = adminClient.getService(SAML2SPEntityService.class);
        saml2IdPEntityService = adminClient.getService(SAML2IdPEntityService.class);
        authProfileService = adminClient.getService(AuthProfileService.class);
        oidcJWKSService = adminClient.getService(OIDCJWKSService.class);
        waConfigService = adminClient.getService(WAConfigService.class);
    }

    protected static String getUUIDString() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    protected static Attr attr(final String schema, final String value) {
        return new Attr.Builder(schema).value(value).build();
    }

    protected static AttrPatch attrAddReplacePatch(final String schema, final String value) {
        return new AttrPatch.Builder(attr(schema, value)).operation(PatchOperation.ADD_REPLACE).build();
    }

    protected static <T> T getObject(final URI location, final Class<?> serviceClass, final Class<T> resultClass) {
        WebClient webClient = WebClient.fromClient(WebClient.client(adminClient.getService(serviceClass)));
        webClient.accept(clientFactory.getContentType().getMediaType()).to(location.toASCIIString(), false);

        return webClient.
                header(RESTHeaders.DOMAIN, adminClient.getDomain()).
                header(HttpHeaders.AUTHORIZATION, "Bearer " + adminClient.getJWT()).
                get(resultClass);
    }

    @SuppressWarnings("unchecked")
    protected <T extends SchemaTO> T createSchema(final SchemaType type, final T schemaTO) {
        Response response = schemaService.create(type, schemaTO);
        if (response.getStatusInfo().getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            Exception ex = clientFactory.getExceptionMapper().fromResponse(response);
            if (ex != null) {
                throw (RuntimeException) ex;
            }
        }

        return (T) getObject(response.getLocation(), SchemaService.class, schemaTO.getClass());
    }

    protected RoleTO createRole(final RoleTO roleTO) {
        Response response = roleService.create(roleTO);
        if (response.getStatusInfo().getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            Exception ex = clientFactory.getExceptionMapper().fromResponse(response);
            if (ex != null) {
                throw (RuntimeException) ex;
            }
        }
        return getObject(response.getLocation(), RoleService.class, RoleTO.class);
    }

    protected ReportTO createReport(final ReportTO report) {
        Response response = reportService.create(report);
        assertEquals(Response.Status.CREATED.getStatusCode(), response.getStatusInfo().getStatusCode());
        return getObject(response.getLocation(), ReportService.class, ReportTO.class);
    }

    protected Pair<String, String> createNotificationTask(
            final boolean active,
            final boolean includeAbout,
            final TraceLevel traceLevel,
            final String sender,
            final String subject,
            final String... staticRecipients) {

        // 1. Create notification
        NotificationTO notification = new NotificationTO();
        notification.setTraceLevel(traceLevel);
        notification.getEvents().add("[LOGIC]:[UserLogic]:[]:[create]:[SUCCESS]");

        if (includeAbout) {
            notification.getAbouts().put(AnyTypeKind.USER.name(),
                    SyncopeClient.getUserSearchConditionBuilder().
                            inGroups("bf825fe1-7320-4a54-bd64-143b5c18ab97").query());
        }

        notification.setRecipientsFIQL(SyncopeClient.getUserSearchConditionBuilder().
                inGroups("f779c0d4-633b-4be5-8f57-32eb478a3ca5").query());
        notification.setSelfAsRecipient(true);
        notification.setRecipientAttrName("email");
        if (staticRecipients != null) {
            notification.getStaticRecipients().addAll(List.of(staticRecipients));
        }

        notification.setSender(sender);
        notification.setSubject(subject);
        notification.setTemplate("optin");
        notification.setActive(active);

        Response response = notificationService.create(notification);
        notification = getObject(response.getLocation(), NotificationService.class, NotificationTO.class);
        assertNotNull(notification);

        // 2. create user
        UserCR req = getUniqueSample("notificationtest@syncope.apache.org");
        req.getMemberships().add(new MembershipTO.Builder("bf825fe1-7320-4a54-bd64-143b5c18ab97").build());

        UserTO userTO = createUser(req).getEntity();
        assertNotNull(userTO);
        return Pair.of(notification.getKey(), req.getUsername());
    }

    protected ProvisioningResult<UserTO> createUser(final UserCR req) {
        Response response = userService.create(req);
        if (response.getStatusInfo().getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            Exception ex = clientFactory.getExceptionMapper().fromResponse(response);
            if (ex != null) {
                throw (RuntimeException) ex;
            }
        }
        return response.readEntity(new GenericType<>() {
        });
    }

    protected ProvisioningResult<UserTO> updateUser(final UserUR req) {
        return userService.update(req).
                readEntity(new GenericType<>() {
                });
    }

    protected ProvisioningResult<UserTO> updateUser(final UserTO userTO) {
        UserTO before = userService.read(userTO.getKey());
        return userService.update(AnyOperations.diff(userTO, before, false)).
                readEntity(new GenericType<>() {
                });
    }

    protected static ProvisioningResult<UserTO> deleteUser(final String key) {
        return userService.delete(key).
                readEntity(new GenericType<>() {
                });
    }

    protected ProvisioningResult<AnyObjectTO> createAnyObject(final AnyObjectCR req) {
        Response response = anyObjectService.create(req);
        if (response.getStatusInfo().getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            Exception ex = clientFactory.getExceptionMapper().fromResponse(response);
            if (ex != null) {
                throw (RuntimeException) ex;
            }
        }
        return response.readEntity(new GenericType<>() {
        });
    }

    protected ProvisioningResult<AnyObjectTO> updateAnyObject(final AnyObjectUR req) {
        return anyObjectService.update(req).
                readEntity(new GenericType<>() {
                });
    }

    protected static ProvisioningResult<AnyObjectTO> deleteAnyObject(final String key) {
        return anyObjectService.delete(key).
                readEntity(new GenericType<>() {
                });
    }

    protected ProvisioningResult<GroupTO> createGroup(final GroupCR req) {
        Response response = groupService.create(req);
        if (response.getStatusInfo().getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            Exception ex = clientFactory.getExceptionMapper().fromResponse(response);
            if (ex != null) {
                throw (RuntimeException) ex;
            }
        }
        return response.readEntity(new GenericType<>() {
        });
    }

    protected ProvisioningResult<GroupTO> updateGroup(final GroupUR req) {
        return groupService.update(req).
                readEntity(new GenericType<>() {
                });
    }

    protected ProvisioningResult<GroupTO> deleteGroup(final String key) {
        return groupService.delete(key).
                readEntity(new GenericType<>() {
                });
    }

    @SuppressWarnings("unchecked")
    protected <T extends PolicyTO> T createPolicy(final PolicyType type, final T policy) {
        Response response = policyService.create(type, policy);
        if (response.getStatusInfo().getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            Exception ex = clientFactory.getExceptionMapper().fromResponse(response);
            if (ex != null) {
                throw (RuntimeException) ex;
            }
        }
        return (T) getObject(response.getLocation(), PolicyService.class, policy.getClass());
    }

    @SuppressWarnings("unchecked")
    protected AuthModuleTO createAuthModule(final AuthModuleTO authModule) {
        Response response = authModuleService.create(authModule);
        if (response.getStatusInfo().getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            Exception ex = clientFactory.getExceptionMapper().fromResponse(response);
            if (ex != null) {
                throw (RuntimeException) ex;
            }
        }
        return getObject(response.getLocation(), AuthModuleService.class, authModule.getClass());
    }

    protected ResourceTO createResource(final ResourceTO resourceTO) {
        Response response = resourceService.create(resourceTO);
        if (response.getStatusInfo().getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            Exception ex = clientFactory.getExceptionMapper().fromResponse(response);
            if (ex != null) {
                throw (RuntimeException) ex;
            }
        }
        return getObject(response.getLocation(), ResourceService.class, ResourceTO.class);
    }

    protected List<BatchResponseItem> parseBatchResponse(final Response response) throws IOException {
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        return BatchPayloadParser.parse(
                (InputStream) response.getEntity(), response.getMediaType(), new BatchResponseItem());
    }

    protected OIDCRPClientAppTO buildOIDCRP() {
        AuthPolicyTO authPolicyTO = new AuthPolicyTO();
        authPolicyTO.setKey("AuthPolicyTest_" + getUUIDString());
        authPolicyTO.setName("Authentication Policy");
        authPolicyTO = createPolicy(PolicyType.AUTH, authPolicyTO);
        assertNotNull(authPolicyTO);

        AccessPolicyTO accessPolicyTO = new AccessPolicyTO();
        accessPolicyTO.setKey("AccessPolicyTest_" + getUUIDString());
        accessPolicyTO.setName("Access policy");
        accessPolicyTO = createPolicy(PolicyType.ACCESS, accessPolicyTO);
        assertNotNull(accessPolicyTO);

        OIDCRPClientAppTO oidcrpTO = new OIDCRPClientAppTO();
        oidcrpTO.setName("ExampleRP_" + getUUIDString());
        oidcrpTO.setClientAppId(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE);
        oidcrpTO.setDescription("Example OIDC RP application");
        oidcrpTO.setClientId("clientId_" + getUUIDString());
        oidcrpTO.setClientSecret("secret");
        oidcrpTO.setSubjectType(OIDCSubjectType.PUBLIC);
        oidcrpTO.getSupportedGrantTypes().add(OIDCGrantType.authorization_code);
        oidcrpTO.getSupportedResponseTypes().add(OIDCResponseType.CODE);

        oidcrpTO.setAuthPolicy(authPolicyTO.getKey());
        oidcrpTO.setAccessPolicy(accessPolicyTO.getKey());

        return oidcrpTO;
    }

    protected SAML2SPClientAppTO buildSAML2SP() {
        AuthPolicyTO authPolicyTO = new AuthPolicyTO();
        authPolicyTO.setKey("AuthPolicyTest_" + getUUIDString());
        authPolicyTO.setName("Authentication Policy");
        authPolicyTO = createPolicy(PolicyType.AUTH, authPolicyTO);
        assertNotNull(authPolicyTO);

        AccessPolicyTO accessPolicyTO = new AccessPolicyTO();
        accessPolicyTO.setKey("AccessPolicyTest_" + getUUIDString());
        accessPolicyTO.setName("Access policy");
        accessPolicyTO = createPolicy(PolicyType.ACCESS, accessPolicyTO);
        assertNotNull(accessPolicyTO);

        SAML2SPClientAppTO saml2spto = new SAML2SPClientAppTO();
        saml2spto.setName("ExampleSAML2SP_" + getUUIDString());
        saml2spto.setClientAppId(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE);
        saml2spto.setDescription("Example SAML 2.0 service provider");
        saml2spto.setEntityId("SAML2SPEntityId_" + getUUIDString());
        saml2spto.setMetadataLocation("file:./test.xml");
        saml2spto.setRequiredNameIdFormat(SAML2SPNameId.EMAIL_ADDRESS);
        saml2spto.setEncryptionOptional(true);
        saml2spto.setEncryptAssertions(true);

        saml2spto.setAuthPolicy(authPolicyTO.getKey());
        saml2spto.setAccessPolicy(accessPolicyTO.getKey());

        return saml2spto;
    }

    @SuppressWarnings("unchecked")
    protected <T extends ClientAppTO> T createClientApp(final ClientAppType type, final T clientAppTO) {
        Response response = clientAppService.create(type, clientAppTO);
        if (response.getStatusInfo().getStatusCode() != Response.Status.CREATED.getStatusCode()) {
            Exception ex = clientFactory.getExceptionMapper().fromResponse(response);
            if (ex != null) {
                throw (RuntimeException) ex;
            }
        }
        return (T) getObject(response.getLocation(), ClientAppService.class, clientAppTO.getClass());
    }

    protected AuthPolicyTO buildAuthPolicyTO(final String authModuleKey) {
        AuthPolicyTO policy = new AuthPolicyTO();
        policy.setName("Test Authentication policy");

        DefaultAuthPolicyConf conf = new DefaultAuthPolicyConf();
        conf.getAuthModules().add(authModuleKey);
        policy.setConf(conf);

        return policy;
    }

    protected AttrReleasePolicyTO buildAttrReleasePolicyTO() {
        AttrReleasePolicyTO policy = new AttrReleasePolicyTO();
        policy.setName("Test Attribute Release policy");
        policy.setStatus(Boolean.TRUE);

        DefaultAttrReleasePolicyConf conf = new DefaultAttrReleasePolicyConf();
        conf.getAllowedAttrs().addAll(List.of("cn", "givenName"));
        conf.getIncludeOnlyAttrs().add("cn");

        policy.setConf(conf);

        return policy;
    }

    protected List<AuditEntry> query(final AuditQuery query, final int maxWaitSeconds) {
        int i = 0;
        List<AuditEntry> results = List.of();
        do {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
            }
            results = auditService.search(query).getResult();
            i++;
        } while (results.isEmpty() && i < maxWaitSeconds);
        return results;
    }

    protected static UserCR getUniqueSample(final String email) {
        return getSample(getUUIDString() + email);
    }

    protected static UserCR getSample(final String email) {
        return new UserCR.Builder(SyncopeConstants.ROOT_REALM, email).
                password("password123").
                plainAttr(attr("fullname", email)).
                plainAttr(attr("firstname", email)).
                plainAttr(attr("surname", "surname")).
                plainAttr(attr("ctype", "a type")).
                plainAttr(attr("userId", email)).
                plainAttr(attr("email", email)).
                plainAttr(attr("loginDate", DateFormatUtils.ISO_8601_EXTENDED_DATETIME_FORMAT.format(new Date()))).
                build();
    }

    protected static ExecTO execTask(
            final TaskService taskService,
            final TaskType type,
            final String taskKey,
            final String initialStatus,
            final int maxWaitSeconds,
            final boolean dryRun) {

        AtomicReference<TaskTO> taskTO = new AtomicReference<>(taskService.read(type, taskKey, true));
        int preSyncSize = taskTO.get().getExecutions().size();
        ExecTO execution = taskService.execute(new ExecSpecs.Builder().key(taskKey).dryRun(dryRun).build());
        assertEquals(initialStatus, execution.getStatus());
        assertNotNull(execution.getExecutor());

        await().atMost(maxWaitSeconds, TimeUnit.SECONDS).pollInterval(1, TimeUnit.SECONDS).until(() -> {
            try {
                taskTO.set(taskService.read(type, taskKey, true));
                return preSyncSize < taskTO.get().getExecutions().size();
            } catch (Exception e) {
                return false;
            }
        });

        return taskTO.get().getExecutions().get(taskTO.get().getExecutions().size() - 1);
    }

    protected static List<PropagationTaskTO> queryPropagationTasks(
            final String userKey, final int beforeCount, final int maxWaitSeconds) {

        int i = 0;
        List<PropagationTaskTO> tasks;
        do {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                LOG.debug("Interrupted");
            }
            tasks = taskService.<PropagationTaskTO>search(
                            new TaskQuery.Builder(TaskType.PROPAGATION).
                                    anyTypeKind(AnyTypeKind.USER).entityKey(userKey).build()).
                    getResult();
            i++;
        } while (tasks.size() == beforeCount && i < maxWaitSeconds);
        if (i == maxWaitSeconds) {
            fail("Timeout checking for Propagation Tasks of user " + userKey);
        }
        return tasks;
    }

    protected <T> void waitForCondition(
            final int maxWaitSecs,
            final Callable<T> callable,
            final Function<T, Boolean> check,
            final String errorMessage) throws Exception {

        T result;
        int i = 0;

        // wait for completion
        do {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
            }

            result = callable.call();

            i++;
        } while (!check.apply(result) && i < maxWaitSecs);

        if (i == maxWaitSecs) {
            fail("Timeout when checking condition: " + errorMessage);
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes", "UseOfObsoleteCollectionType"})
    protected static InitialDirContext getADResourceDirContext(final String adResourceKey) throws NamingException {
        ResourceTO adResource = resourceService.read(adResourceKey);
        ConnInstanceTO adConn = connectorService.read(adResource.getConnector(), Locale.ENGLISH.getLanguage());

        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL,
                "ldaps://" + adConn.getConf("host").get().getValues().get(0) + ":" + adConn.getConf("port").get()
                        .getValues().get(0) + "/");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, adConn.getConf("principal").get().getValues().get(0));
        env.put(Context.SECURITY_CREDENTIALS, adConn.getConf("credentials").get().getValues().get(0));
        env.put("java.naming.ldap.factory.socket", TrustAllCertsSocketFactory.class.getName());

        return new InitialDirContext(env);
    }

    protected static NamingEnumeration<SearchResult> getADRemoteObject(final String objectDn,
                                                                       final String adResourceKey) {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setTimeLimit(30000);

        InitialDirContext ctx = null;
        try {
            ctx = getADResourceDirContext(adResourceKey);
            return ctx.search(objectDn, "(objectclass=*)", searchControls);
        } catch (NamingException e) {
            LOG.error("Could not fetch {}", objectDn, e);
            return null;
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException e) {
                    // ignore
                }
            }
        }
    }

    protected static boolean adChecks(final String adResourceKey) throws NamingException {
        try {
            resourceService.check(resourceService.read(adResourceKey));
        } catch (Exception e) {
            LOG.error("Checks for AD: {} ", adResourceKey, e);
            return false;
        }
        NamingEnumeration<SearchResult> adminObjs =
                getADRemoteObject("cn=administrator,cn=users,dc=tirasa,dc=net", adResourceKey);
        boolean adChecks = adminObjs == null
                ? false
                : adminObjs.hasMore();
        LOG.debug("Checks for AD: {} {}", adChecks, adResourceKey);
        return adChecks;
    }

    protected static void clearTasks(final List<TaskType> taskTypes) {
        taskTypes.forEach(taskType
                -> {
            taskService.search(new TaskQuery.Builder(taskType).build()).getResult().forEach(pt
                    -> {
                try {
                    taskService.delete(taskType, pt.getKey());
                } catch (Exception e) {
                    // ignore this
                }
            });
        });
    }

}
