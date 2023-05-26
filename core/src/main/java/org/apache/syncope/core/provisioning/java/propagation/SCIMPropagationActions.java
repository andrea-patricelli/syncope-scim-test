package org.apache.syncope.core.provisioning.java.propagation;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.syncope.common.lib.types.AnyTypeKind;
import org.apache.syncope.common.lib.types.ResourceOperation;
import org.apache.syncope.core.persistence.api.dao.GroupDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.provisioning.api.propagation.PropagationActions;
import org.apache.syncope.core.provisioning.api.propagation.PropagationTaskInfo;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

public class SCIMPropagationActions implements PropagationActions {

    protected static final Logger LOG = LoggerFactory.getLogger(SCIMPropagationActions.class);

    @Autowired private UserDAO userDAO;

    @Autowired private GroupDAO groupDAO;

    protected String getGroupMembershipAttrName() {
        return "groups";
    }

    @Transactional(readOnly = true) @Override public void before(final PropagationTaskInfo taskInfo) {
        if (AnyTypeKind.USER != taskInfo.getAnyTypeKind() || taskInfo.getOperation() == ResourceOperation.DELETE) {
            return;
        }

        User user = userDAO.find(taskInfo.getEntityKey());
        Set<String> groups = new HashSet<>();
        // take groups already assigned from beforeObj and include them, too
        taskInfo.getBeforeObj().map(beforeObj -> beforeObj.getAttributeByName(getGroupMembershipAttrName()))
                .filter(Objects::nonNull)
                .ifPresent(beforeSCIMGroups -> beforeSCIMGroups.getValue().forEach(g -> groups.add(String.valueOf(g))));
        LOG.debug("SCIM groups not managed by Syncope: {}", groups);
        groups.addAll(userDAO.findAllGroupKeys(user).stream().map(groupDAO::find)
                .filter(group -> group.getResources().contains(taskInfo.getResource()) && group.getPlainAttr(
                        "SCIMGroupId").isPresent())
                .map(group -> group.getPlainAttr("SCIMGroupId").get().getValuesAsStrings().get(0))
                .collect(Collectors.toList()));
        LOG.debug("Group SCIMGroupId to propagate for membership: {}", groups);
        taskInfo.getPropagationData().getAttributes().add(AttributeBuilder.build("groups", groups));
    }

}
