# JIT-Associator

This component give the ability to,
* Request to add mandatory claims before JIT provisioning
* JIT Provision user with the requested mandatory claims
* Associate user during the JIT provisioning

In order to deploy this,
* Build the module.
* Copy extended-jit-associator-1.0-SNAPSHOT.jar created in the target folder to <IS_HOME>/repository/components/dropins/ folder.
* Open <IS_HOME>/repository/conf/identity/application-authentication.xml file and update AuthenticationRequestHandler, StepBasedSequenceHandler & ProvisioningHandler tags as below

```
<StepBasedSequenceHandler>org.wso2.identity.sample.ExtendedStepBasedSequenceHandler</StepBasedSequenceHandler>
<ProvisioningHandler>org.wso2.identity.sample.ExtendedJITProvisioningHandler</ProvisioningHandler>
<AuthenticationRequestHandler>org.wso2.identity.sample.ExtendedAuthenticationRequestHandler</AuthenticationRequestHandler>
```