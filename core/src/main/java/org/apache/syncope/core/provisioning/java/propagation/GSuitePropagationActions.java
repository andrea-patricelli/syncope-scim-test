package org.apache.syncope.core.provisioning.java.propagation;

import java.util.Set;
import org.apache.syncope.common.lib.types.AnyTypeKind;
import org.apache.syncope.core.persistence.api.dao.GroupDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.group.Group;
import org.apache.syncope.core.provisioning.api.propagation.PropagationActions;
import org.apache.syncope.core.provisioning.api.propagation.PropagationTaskInfo;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

public class GSuitePropagationActions implements PropagationActions {

    protected static final Logger LOG = LoggerFactory.getLogger(GSuitePropagationActions.class);

    @Autowired
    protected UserDAO userDAO;

    @Autowired
    protected GroupDAO groupDAO;

    protected String getGoogleAppsIdSchema() {
        return "GoogleAppsId";
    }

    @Transactional(readOnly = true)
    @Override
    public void before(final PropagationTaskInfo taskInfo) {
        Set<Attribute> attributes = taskInfo.getPropagationData().getAttributes();
        if (AnyTypeKind.USER == taskInfo.getAnyTypeKind()) {
            // DO NOTHING
        } else {
            Group group = groupDAO.find(taskInfo.getEntityKey());
            Attribute attribute = AttributeUtil.find(AttributeUtil.createSpecialName("NAME"), attributes);
            if (attribute != null) {
                attributes.remove(attribute);
            }
            taskInfo.getResource().getConnector().getConf().stream().filter(conf -> "domain"
                            .equals(conf.getSchema().getName()) && !conf.getValues().isEmpty()).findFirst()
                    .ifPresent(conf -> attributes.add(AttributeBuilder.build(AttributeUtil.createSpecialName("NAME"),
                            group.getName() + "@" + conf.getValues().get(0))));
        }
    }

}
