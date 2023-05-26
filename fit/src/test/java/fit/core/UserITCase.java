package fit.core;

import fit.AbstractITCase;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.apache.syncope.common.lib.Attr;
import org.apache.syncope.common.lib.SyncopeClientException;
import org.apache.syncope.common.lib.SyncopeConstants;
import org.apache.syncope.common.lib.request.AttrPatch;
import org.apache.syncope.common.lib.request.GroupCR;
import org.apache.syncope.common.lib.request.MembershipUR;
import org.apache.syncope.common.lib.request.PasswordPatch;
import org.apache.syncope.common.lib.request.UserCR;
import org.apache.syncope.common.lib.request.UserUR;
import org.apache.syncope.common.lib.to.ConnObject;
import org.apache.syncope.common.lib.to.GroupTO;
import org.apache.syncope.common.lib.to.MembershipTO;
import org.apache.syncope.common.lib.to.UserTO;
import org.apache.syncope.common.lib.types.AnyTypeKind;
import org.apache.syncope.common.lib.types.ClientExceptionType;
import org.apache.syncope.common.lib.types.PatchOperation;
import org.apache.syncope.common.rest.api.beans.AnyQuery;
import org.apache.syncope.common.rest.api.beans.ReconQuery;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.test.annotation.DirtiesContext;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD) public class UserITCase
        extends AbstractITCase {

    @Test public void crudSCIMv11SalesforceUser() {
        // create a new user and associate to SCIMv2
        String username = "testv11sales" + UUID.randomUUID().toString().substring(0, 5);
        UserCR userCR =
                new UserCR.Builder(SyncopeConstants.ROOT_REALM, "testv11sales" + username + "@test.com").password(
                                "Password123").plainAttr(new Attr.Builder("firstname").value(username).build())
                        .plainAttr(new Attr.Builder("surname").value("v11sales" + username).build())
                        .plainAttr(new Attr.Builder("email").value(username + "@test.com").build())
                        .plainAttr(new Attr.Builder("locale").value("it_IT").build())
                        .plainAttr(new Attr.Builder("language").value("it").build())
                        .plainAttr(new Attr.Builder("ctype").value("00e09000000iZP5AAM").build())
                        .plainAttr(new Attr.Builder("fullname").value("testv11sales v11sales").build())
                        .plainAttr(new Attr.Builder("aLong").value("10").build())
                        .plainAttr(new Attr.Builder("userId").value(username + "@test.com").build())
                        .resource("SCIM v11 resource").build();

        UserTO userTO = createUser(userCR).getEntity();
        Assertions.assertTrue(userTO.getPlainAttr("SCIMId").isPresent());
        try {
            ConnObject connObject = resourceService.readConnObject("SCIM v11 resource", AnyTypeKind.USER.name(),
                    userTO.getPlainAttr("SCIMId").get().getValues().get(0));
            Assertions.assertTrue(connObject.getAttr("name.givenName").isPresent());
            Assertions.assertTrue(connObject.getAttr("emails.work.value").isPresent());
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
            Assertions.fail(sce.getMessage());
        }
        // update
        UserUR userUR = new UserUR.Builder(userTO.getKey()).plainAttr(
                new AttrPatch.Builder(new Attr.Builder("firstname").value("testv11sales_upd").build()).build()).build();
        userTO = updateUser(userUR).getEntity();
        try {
            ConnObject connObject =
                    resourceService.readConnObject("SCIM v11 resource", AnyTypeKind.USER.name(), userTO.getKey());
            Assertions.assertTrue(connObject.getAttr("name.givenName").isPresent());
            Assertions.assertTrue(connObject.getAttr("name.givenName").get().getValues().contains("testv11sales_upd"));
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
            Assertions.fail(sce.getMessage());
        }

        // finally delete user
        deleteUser(userTO.getKey());

        try {
            ConnObject connObject = resourceService.readConnObject("SCIM v11 resource", AnyTypeKind.USER.name(),
                    userTO.getPlainAttr("SCIMId").get().getValues().get(0));
            Assertions.fail("Should not arrive here");
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
        }
    }

    @Test public void crudSCIMv2Salesforce() throws InterruptedException {
        // create group
        String group1Name = "scimgroup" + UUID.randomUUID().toString().substring(0, 5);
        GroupCR group1CR =
                new GroupCR.Builder(SyncopeConstants.ROOT_REALM, group1Name).resources("SCIMv2 Salesforce resource")
                        .build();
        GroupTO group1TO = createGroup(group1CR).getEntity();
        Assertions.assertTrue(group1TO.getPlainAttr("SCIMGroupId").isPresent());

        String group2Name = "scimgroup" + UUID.randomUUID().toString().substring(0, 5);
        GroupCR group2CR =
                new GroupCR.Builder(SyncopeConstants.ROOT_REALM, group2Name).resources("SCIMv2 Salesforce resource")
                        .build();
        GroupTO group2TO = createGroup(group2CR).getEntity();
        Assertions.assertTrue(group2TO.getPlainAttr("SCIMGroupId").isPresent());

        String group3Name = "scimgroup" + UUID.randomUUID().toString().substring(0, 5);
        GroupCR group3CR =
                new GroupCR.Builder(SyncopeConstants.ROOT_REALM, group3Name).resources("SCIMv2 Salesforce resource")
                        .build();
        GroupTO group3TO = createGroup(group3CR).getEntity();
        Assertions.assertTrue(group3TO.getPlainAttr("SCIMGroupId").isPresent());
        // create a new user and associate to SCIMv2
        String username = "testv2sales" + UUID.randomUUID().toString().substring(0, 5);
        UserCR userCR =
                new UserCR.Builder(SyncopeConstants.ROOT_REALM, "testv2sales" + username + "@test.com").password(
                                "Password123").plainAttr(new Attr.Builder("firstname").value(username).build())
                        .plainAttr(new Attr.Builder("surname").value("v2sales" + username).build())
                        .plainAttr(new Attr.Builder("email").value(username + "@test.com").build())
                        .plainAttr(new Attr.Builder("locale").value("it_IT").build())
                        .plainAttr(new Attr.Builder("language").value("it").build())
                        .plainAttr(new Attr.Builder("ctype").value("00e09000000iZP5AAM").build())
                        .plainAttr(new Attr.Builder("fullname").value("testv2sales v2sales").build())
                        .plainAttr(new Attr.Builder("aLong").value("10").build())
                        .plainAttr(new Attr.Builder("userId").value(username + "@test.com").build())
                        .memberships(new MembershipTO.Builder(group1TO.getKey()).build(),
                                new MembershipTO.Builder(group2TO.getKey()).build())
                        .resources("SCIMv2 Salesforce resource").build();

        UserTO userTO = createUser(userCR).getEntity();
        Assertions.assertTrue(userTO.getPlainAttr("SCIMId").isPresent());
        try {
            ConnObject connObject = reconciliationService.status(
                    new ReconQuery.Builder(AnyTypeKind.USER.name(), "SCIMv2 Salesforce resource").anyKey(
                            userTO.getKey()).moreAttrsToGet("groups").build()).getOnResource();
            Assertions.assertTrue(connObject.getAttr("name.givenName").isPresent());
            Assertions.assertTrue(connObject.getAttr("emails.work.value").isPresent());
            Assertions.assertTrue(connObject.getAttr("groups").isPresent());
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group1TO.getPlainAttr("SCIMGroupId").get().getValues()));
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group2TO.getPlainAttr("SCIMGroupId").get().getValues()));
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
            Assertions.fail(sce.getMessage());
        }
        // update
        UserUR userUR = new UserUR.Builder(userTO.getKey()).plainAttr(
                        new AttrPatch.Builder(new Attr.Builder("firstname").value("testv2sales_upd").build()).build())
                .password(new PasswordPatch.Builder().value("Password123!").resources(userTO.getResources()).build())
                // remove group 2 and add group3 
                .memberships(new MembershipUR.Builder(group2TO.getKey()).operation(PatchOperation.DELETE).build(),
                        new MembershipUR.Builder(group3TO.getKey()).build()).build();
        userTO = updateUser(userUR).getEntity();
        try {
            ConnObject connObject = reconciliationService.status(
                    new ReconQuery.Builder(AnyTypeKind.USER.name(), "SCIMv2 Salesforce resource").anyKey(
                            userTO.getKey()).moreAttrsToGet("groups").build()).getOnResource();
            Assertions.assertTrue(connObject.getAttr("name.givenName").isPresent());
            Assertions.assertTrue(connObject.getAttr("name.givenName").get().getValues().contains("testv2sales_upd"));
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group1TO.getPlainAttr("SCIMGroupId").get().getValues()));
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group3TO.getPlainAttr("SCIMGroupId").get().getValues()));
            Assertions.assertFalse(connObject.getAttr("groups").get().getValues()
                    .containsAll(group2TO.getPlainAttr("SCIMGroupId").get().getValues()));
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
            Assertions.fail(sce.getMessage());
        }

        // finally delete user
        deleteUser(userTO.getKey());
        deleteGroup(group1TO.getKey());
        deleteGroup(group2TO.getKey());
        deleteGroup(group3TO.getKey());

        String finalKey = userTO.getKey();
        Awaitility.await().atMost(30, TimeUnit.SECONDS).until(() -> {
            try {
                resourceService.readConnObject("SCIMv2 Salesforce resource", AnyTypeKind.USER.name(), finalKey);
            } catch (SyncopeClientException sce) {
                return ClientExceptionType.NotFound == sce.getType();
            }
            return false;
        });
        Awaitility.await().atMost(30, TimeUnit.SECONDS).until(() -> {
            try {
                resourceService.readConnObject("SCIMv2 Salesforce resource", AnyTypeKind.GROUP.name(),
                        group3TO.getPlainAttr("SCIMGroupId").get().getValues().get(0));
                Assertions.fail("Should not arrive here");
            } catch (SyncopeClientException sce) {
                return ClientExceptionType.NotFound == sce.getType();
            }
            return false;
        });
    }

    @Test public void crudSCIMv2Slack() throws InterruptedException {
        // create group
        String group1Name = "scimgroup" + UUID.randomUUID().toString().substring(0, 3);
        GroupCR group1CR =
                new GroupCR.Builder(SyncopeConstants.ROOT_REALM, group1Name).resources("SCIMv2 Slack resource")
                        .build();
        GroupTO group1TO = createGroup(group1CR).getEntity();
        Assertions.assertTrue(group1TO.getPlainAttr("SCIMGroupId").isPresent());

        String group2Name = "scimgroup" + UUID.randomUUID().toString().substring(0, 5);
        GroupCR group2CR =
                new GroupCR.Builder(SyncopeConstants.ROOT_REALM, group2Name).resources("SCIMv2 Slack resource")
                        .build();
        GroupTO group2TO = createGroup(group2CR).getEntity();
        Assertions.assertTrue(group2TO.getPlainAttr("SCIMGroupId").isPresent());

        String group3Name = "scimgroup" + UUID.randomUUID().toString().substring(0, 5);
        GroupCR group3CR =
                new GroupCR.Builder(SyncopeConstants.ROOT_REALM, group3Name).resources("SCIMv2 Slack resource")
                        .build();
        GroupTO group3TO = createGroup(group3CR).getEntity();
        Assertions.assertTrue(group3TO.getPlainAttr("SCIMGroupId").isPresent());
        // create a new user and associate to SCIMv2
        String username = "testv2slack" + UUID.randomUUID().toString().substring(0, 3);
        UserCR userCR =
                new UserCR.Builder(SyncopeConstants.ROOT_REALM, username + "@test.com").password(
                                "3yUBxPe7jb").plainAttr(new Attr.Builder("firstname").value(username).build())
                        .plainAttr(new Attr.Builder("surname").value("v2sales" + username).build())
                        .plainAttr(new Attr.Builder("email").value(username + "@test.com").build())
                        .plainAttr(new Attr.Builder("aLong").value("12345").build())
                        .plainAttr(new Attr.Builder("fullname").value("testv2slack v2slack").build())
                        .plainAttr(new Attr.Builder("aLong").value("12345").build())
                        .plainAttr(new Attr.Builder("userId").value(username + "@test.com").build())
                        .memberships(new MembershipTO.Builder(group1TO.getKey()).build(),
                                new MembershipTO.Builder(group2TO.getKey()).build())
                        .resources("SCIMv2 Slack resource").build();

        UserTO userTO = createUser(userCR).getEntity();
        Assertions.assertTrue(userTO.getPlainAttr("SCIMId").isPresent());
        try {
            ConnObject connObject = reconciliationService.status(
                    new ReconQuery.Builder(AnyTypeKind.USER.name(), "SCIMv2 Slack resource").anyKey(
                            userTO.getKey()).moreAttrsToGet("groups").build()).getOnResource();
            Assertions.assertTrue(connObject.getAttr("name.givenName").isPresent());
            Assertions.assertTrue(connObject.getAttr("emails.value").isPresent());
            Assertions.assertTrue(connObject.getAttr("groups").isPresent());
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group1TO.getPlainAttr("SCIMGroupId").get().getValues()));
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group2TO.getPlainAttr("SCIMGroupId").get().getValues()));
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
            Assertions.fail(sce.getMessage());
        }
        // update
        UserUR userUR = new UserUR.Builder(userTO.getKey()).plainAttr(
                        new AttrPatch.Builder(new Attr.Builder("firstname").value("testv2slack_upd").build()).build())
                .password(new PasswordPatch.Builder().value("Password123!").resources(userTO.getResources()).build())
                // remove group 2 and add group3 
                .memberships(new MembershipUR.Builder(group2TO.getKey()).operation(PatchOperation.DELETE).build(),
                        new MembershipUR.Builder(group3TO.getKey()).build()).build();
        userTO = updateUser(userUR).getEntity();
        try {
            ConnObject connObject = reconciliationService.status(
                    new ReconQuery.Builder(AnyTypeKind.USER.name(), "SCIMv2 Slack resource").anyKey(
                            userTO.getKey()).moreAttrsToGet("groups").build()).getOnResource();
            Assertions.assertTrue(connObject.getAttr("name.givenName").isPresent());
            Assertions.assertTrue(connObject.getAttr("name.givenName").get().getValues().contains("testv2slack_upd"));
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group1TO.getPlainAttr("SCIMGroupId").get().getValues()));
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group3TO.getPlainAttr("SCIMGroupId").get().getValues()));
            Assertions.assertFalse(connObject.getAttr("groups").get().getValues()
                    .containsAll(group2TO.getPlainAttr("SCIMGroupId").get().getValues()));
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
            Assertions.fail(sce.getMessage());
        }

        // finally delete user
        deleteUser(userTO.getKey());
        deleteGroup(group1TO.getKey());
        deleteGroup(group2TO.getKey());
        deleteGroup(group3TO.getKey());

        String finalKey = userTO.getKey();
        Awaitility.await().atMost(30, TimeUnit.SECONDS).until(() -> {
            try {
                resourceService.readConnObject("SCIMv2 Slack resource", AnyTypeKind.USER.name(), finalKey);
            } catch (SyncopeClientException sce) {
                return ClientExceptionType.NotFound == sce.getType();
            }
            return false;
        });
        Awaitility.await().atMost(30, TimeUnit.SECONDS).until(() -> {
            try {
                resourceService.readConnObject("SCIMv2 Slack resource", AnyTypeKind.GROUP.name(),
                        group3TO.getPlainAttr("SCIMGroupId").get().getValues().get(0));
                Assertions.fail("Should not arrive here");
            } catch (SyncopeClientException sce) {
                return ClientExceptionType.NotFound == sce.getType();
            }
            return false;
        });
    }

    @Test public void crudSCIMv2Scimple() {
        // create group
        String group1Name = "scimgroup_" + UUID.randomUUID().toString().substring(0, 5);
        GroupCR group1CR =
                new GroupCR.Builder(SyncopeConstants.ROOT_REALM, group1Name).resources("SCIM v2 resource").build();
        GroupTO group1TO = createGroup(group1CR).getEntity();
        Assertions.assertTrue(group1TO.getPlainAttr("SCIMGroupId").isPresent());

        String group2Name = "scimgroup_" + UUID.randomUUID().toString().substring(0, 5);
        GroupCR group2CR =
                new GroupCR.Builder(SyncopeConstants.ROOT_REALM, group2Name).resources("SCIM v2 resource").build();
        GroupTO group2TO = createGroup(group2CR).getEntity();
        Assertions.assertTrue(group2TO.getPlainAttr("SCIMGroupId").isPresent());

        String group3Name = "scimgroup_" + UUID.randomUUID().toString().substring(0, 5);
        GroupCR group3CR =
                new GroupCR.Builder(SyncopeConstants.ROOT_REALM, group3Name).resources("SCIM v2 resource").build();
        GroupTO group3TO = createGroup(group3CR).getEntity();
        Assertions.assertTrue(group3TO.getPlainAttr("SCIMGroupId").isPresent());

        // create a new user and associate to SCIMv2
        String username = "testv2sales" + UUID.randomUUID().toString().substring(0, 5);
        UserCR userCR =
                new UserCR.Builder(SyncopeConstants.ROOT_REALM, "testv2sales" + username + "@test.com").password(
                                "Password123").plainAttr(new Attr.Builder("firstname").value(username).build())
                        .plainAttr(new Attr.Builder("surname").value("v2sales" + username).build())
                        .plainAttr(new Attr.Builder("email").value(username + "@test.com").build())
                        .plainAttr(new Attr.Builder("locale").value("it_IT").build())
                        .plainAttr(new Attr.Builder("language").value("it").build())
                        .plainAttr(new Attr.Builder("ctype").value("00e09000000iZP5AAM").build())
                        .plainAttr(new Attr.Builder("fullname").value("testv2sales v2sales").build())
                        .plainAttr(new Attr.Builder("aLong").value("10").build())
                        .plainAttr(new Attr.Builder("userId").value(username + "@test.com").build())
                        .memberships(new MembershipTO.Builder(group1TO.getKey()).build(),
                                new MembershipTO.Builder(group2TO.getKey()).build()).resources("SCIM v2 resource")
                        .build();

        UserTO userTO = createUser(userCR).getEntity();
        Assertions.assertTrue(userTO.getPlainAttr("SCIMId").isPresent());
        try {
            ConnObject connObject = reconciliationService.status(
                    new ReconQuery.Builder(AnyTypeKind.USER.name(), "SCIM v2 resource").anyKey(userTO.getKey())
                            .moreAttrsToGet("groups").build()).getOnResource();
            Assertions.assertTrue(connObject.getAttr("name.givenName").isPresent());
            Assertions.assertTrue(connObject.getAttr("emails.work.value").isPresent());
            Assertions.assertTrue(connObject.getAttr("groups").isPresent());
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group1TO.getPlainAttr("SCIMGroupId").get().getValues()));
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group2TO.getPlainAttr("SCIMGroupId").get().getValues()));
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
            Assertions.fail(sce.getMessage());
        }
        // update
        UserUR userUR = new UserUR.Builder(userTO.getKey()).plainAttr(
                new AttrPatch.Builder(new Attr.Builder("firstname").value("testv2sales_upd").build()).build()).build();
        // remove group 2 and add group3 
        userUR.getMemberships()
                .add(new MembershipUR.Builder(group2TO.getKey()).operation(PatchOperation.DELETE).build());
        userUR.getMemberships().add(new MembershipUR.Builder(group3TO.getKey()).build());
        userTO = updateUser(userUR).getEntity();
        try {
            ConnObject connObject = reconciliationService.status(
                    new ReconQuery.Builder(AnyTypeKind.USER.name(), "SCIM v2 resource").anyKey(userTO.getKey())
                            .moreAttrsToGet("groups").build()).getOnResource();
            Assertions.assertTrue(connObject.getAttr("name.givenName").isPresent());
            Assertions.assertTrue(connObject.getAttr("name.givenName").get().getValues().contains("testv2sales_upd"));
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group1TO.getPlainAttr("SCIMGroupId").get().getValues()));
            Assertions.assertTrue(connObject.getAttr("groups").get().getValues()
                    .containsAll(group3TO.getPlainAttr("SCIMGroupId").get().getValues()));
            Assertions.assertFalse(connObject.getAttr("groups").get().getValues()
                    .containsAll(group2TO.getPlainAttr("SCIMGroupId").get().getValues()));
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
            Assertions.fail(sce.getMessage());
        }

        // finally delete user
        deleteUser(userTO.getKey());
        deleteGroup(group1TO.getKey());
        deleteGroup(group2TO.getKey());
        deleteGroup(group3TO.getKey());

        try {
            resourceService.readConnObject("SCIM v2 resource", AnyTypeKind.USER.name(),
                    userTO.getPlainAttr("SCIMId").get().getValues().get(0));
            Assertions.fail("Should not arrive here");
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
        }
        try {
            resourceService.readConnObject("SCIM v2 resource", AnyTypeKind.USER.name(),
                    group3TO.getPlainAttr("SCIMGroupId").get().getValues().get(0));
            Assertions.fail("Should not arrive here");
        } catch (SyncopeClientException sce) {
            sce.printStackTrace();
        }
    }

    @AfterEach public void cleanUpLocal() {
        userService.search(new AnyQuery.Builder().realm(SyncopeConstants.ROOT_REALM).build()).getResult().stream()
                .filter(user -> user.getResources().stream().anyMatch(r -> r.contains("SCIM")))
                .forEach(user -> userService.delete(user.getKey()));
    }
}
