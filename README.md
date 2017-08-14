# SCIM-ID Remover

This component give the ability to,
* Use odbjectGUID attribute in Active Directories to use as the urn:scim:schemas:core:1.0:id attribute in SCIM
* Use timeCreated attribute in Active Directories to use as the urn:scim:schemas:core:1.0:meta.created attribute in SCIM
* Use timeModified attribute in Active Directories to use as the urn:scim:schemas:core:1.0:meta.lastModified attribute in SCIM

In order to deploy this,
* Build the module.
* Copy org.wso2.identity.sample.listener.scim-1.0-SNAPSHOT.jar created in the target folder to <IS_HOME>/repository/components/dropins/ folder.
