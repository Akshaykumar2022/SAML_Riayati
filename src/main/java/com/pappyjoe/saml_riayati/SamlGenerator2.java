package com.pappyjoe.saml_riayati;

import java.io.FileInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.UUID;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
	/**
	 * A simple SAML generator, that generates an assertion with user roles and additional attributes. The generated SAML assertion is enough to
	 * log in to our server.
	 */
	@Service
	public class SamlGenerator2 {



	        public static final String CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
            public static final String SUCCESS_STATUS_CODE = "urn:oasis:names:tc:SAML:2.0:status:Success";

	        public String getSamlResponse(final String issuerName, final String recipient, final String userId, final String userRole,
	                        final SamlAttribute attributes, final String audienceUri, final String roleSamlAttributeName,
	                        final String keyStoreLocation, final char[] keyStorePassword, final String keyAlias, final char[] keyPassword,final  String destinationUrl) throws ConfigurationException {

				DefaultBootstrap.bootstrap();

	                final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

	                // Create the Assertion
	                final String sessionId = UUID.randomUUID().toString();
	                final Assertion assertion = createSamlAssertion(builderFactory, issuerName, userId, userRole, attributes, recipient, sessionId,
	                                audienceUri, roleSamlAttributeName, keyStoreLocation, keyStorePassword, keyAlias, keyPassword);

                // Create the Response
	                final ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
	                final Response response = responseBuilder.buildObject();



                    response.setDestination(destinationUrl);
                    response.setID(sessionId);
	                response.setIssueInstant(new DateTime());


	                final Issuer issuer = createIssuer(builderFactory, issuerName);
	                response.setIssuer(issuer);



	                final Status status = createSuccessStatus(builderFactory);
	                response.setStatus(status);

	                response.getAssertions().add(assertion);



				final MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
	                Element element = null;
	                try {
	                        marshallerFactory.getMarshaller(response).marshall(response);
	                        Signer.signObject(assertion.getSignature());
	                        final Marshaller marshaller = marshallerFactory.getMarshaller(response);
	                        element = marshaller.marshall(response);
						element.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
						element.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsd", "http://www.w3.org/2001/XMLSchema");

					} catch (final MarshallingException e) {
	                        throw new RuntimeException("Error occurred while marshalling the response", e);
	                } catch (final SignatureException e) {
	                        throw new RuntimeException("Error occurred while signing the response", e);
	                }

	                return XMLHelper.nodeToString(element);
	        }

	        /**
	         * Helper method which includes some basic SAML fields which are part of almost every SAML Assertion.
155	     * @param builderFactory
156	     * @param issuerName
157	     * @param userId
158	     * @param recipient
159	     * @param userRole
160	     * @param audienceUri
161	     * @param attributes
162	     * @param sessionId
163	     * @param roleSamlAttributeName
164	     * @param keyAlias
165	     * @param keyStoreLocation
166	     * @param keyStorePassword
167	     * @param keyPassword
168	     * @return
169	         */
	        public Assertion createSamlAssertion(final XMLObjectBuilderFactory builderFactory, final String issuerName, final String userId,
	                        final String userRole, final SamlAttribute attributes, final String recipient, final String sessionId,
	                        final String audienceUri, final String roleSamlAttributeName, final String keyStoreLocation, final char[] keyStorePassword,
	                        final String keyAlias, final char[] keyPassword) {

	                // Create the NameIdentifier
	                final NameID nameId;
	                if (StringUtils.isEmpty(userId)) {
	                        nameId = null;
	                } else {
	                        final NameIDBuilder nameIdBuilder = (NameIDBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
	                        nameId = nameIdBuilder.buildObject();
	                        nameId.setValue(userId);
	                        nameId.setFormat(NameIDType.EMAIL);
	                }

	                // Create the Issuer
	                final Issuer issuer = createIssuer(builderFactory, issuerName);

	                // Create the AttributeStatement
	                final AttributeStatementBuilder attributeStatementBuilder = (AttributeStatementBuilder) builderFactory
	                                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
	                final AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();



	                // User attributes (optional)


	                                attributeStatement.getAttributes().add(createAttribute(builderFactory,"clinicianId",attributes.getClinicianId()));
									attributeStatement.getAttributes().add(createAttribute(builderFactory,"urn:oasis:names:tc:xacml:2.0:subject:role",attributes.getRole()));



	                // User roles (optional)
	                /*
205	                if (StringUtils.isNotEmpty(roleSamlAttributeName)) {
206	                        attributeStatement.getAttributes()
207	                                        .add(createAttribute(builderFactory, roleSamlAttributeName, userRole.trim().split("\\s*;\\s*")));
208	                }
209	                 */
	                // Create the SubjectConfirmation
	                final SubjectConfirmationDataBuilder subjectConfirmationDataBuilder = (SubjectConfirmationDataBuilder) builderFactory
	                                .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
	                final SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
	                final DateTime now = new DateTime();
	                subjectConfirmationData.setNotOnOrAfter(now.plusMinutes(5));
	                subjectConfirmationData.setRecipient(recipient);

	                final SubjectConfirmationBuilder subjectConfirmationBuilder = (SubjectConfirmationBuilder) builderFactory
	                                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
	                final SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
	                subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
	                subjectConfirmation.setMethod(CONFIRMATION_METHOD_BEARER);

	                // Create the Subject
	                final SubjectBuilder subjectBuilder = (SubjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
	                final Subject subject = subjectBuilder.buildObject();
	                if (nameId != null) {
	                        subject.setNameID(nameId);
	                }
	                subject.getSubjectConfirmations().add(subjectConfirmation);

	                // Create Authentication Statement
	                final AuthnStatementBuilder authStatementBuilder = (AuthnStatementBuilder) builderFactory
	                                .getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
	                final AuthnStatement authnStatement = authStatementBuilder.buildObject();
	                final DateTime now2 = new DateTime();
	                authnStatement.setAuthnInstant(now2);
	                //authnStatement.setSessionIndex(sessionId);

	                final AuthnContextBuilder authContextBuilder = (AuthnContextBuilder) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
	                final AuthnContext authnContext = authContextBuilder.buildObject();

	                final AuthnContextClassRefBuilder authContextClassRefBuilder = (AuthnContextClassRefBuilder) builderFactory
	                                .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
	                final AuthnContextClassRef authnContextClassRef = authContextClassRefBuilder.buildObject();
	                authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes::PasswordProtectedTransport");
	                //authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");

	                authnContext.setAuthnContextClassRef(authnContextClassRef);
	                authnStatement.setAuthnContext(authnContext);

	                // Create the audience restrictions
	                final AudienceBuilder audienceBuilder = (AudienceBuilder) builderFactory.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
	                final Audience audience = audienceBuilder.buildObject();
	                audience.setAudienceURI(audienceUri);

	                final AudienceRestrictionBuilder audienceRestrictionBuilder = (AudienceRestrictionBuilder) builderFactory
	                                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
	                final AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
	                audienceRestriction.getAudiences().add(audience);

	                // Create the conditions
	                final ConditionsBuilder conditionsBuilder = (ConditionsBuilder) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
	                final Conditions conditions = conditionsBuilder.buildObject();
	                conditions.setNotBefore(new DateTime().minusMinutes(5));
	                conditions.setNotOnOrAfter(new DateTime().plusMinutes(5));
	                conditions.getAudienceRestrictions().add(audienceRestriction);

	                // Create the assertion
	                final AssertionBuilder assertionBuilder = (AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
	                final Assertion assertion = assertionBuilder.buildObject();
	                assertion.setID(sessionId);
	                assertion.setIssuer(issuer);
	                assertion.setIssueInstant(now);
	                assertion.setVersion(SAMLVersion.VERSION_20);
	                if (subject != null) {
	                        assertion.setSubject(subject);
	                }
	                assertion.getAuthnStatements().add(authnStatement);
	                assertion.getAttributeStatements().add(attributeStatement);

	                assertion.setConditions(conditions);

	                // Set the signature on the assertion
	                final Credential signingCredential = getSigningCredential(keyStoreLocation, keyStorePassword, keyAlias, keyPassword);
	                final SignatureBuilder sb = (SignatureBuilder) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
	                final Signature signature = sb.buildObject();
	                signature.setSigningCredential(signingCredential);
	                signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);


	                BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
	                config.setSignatureReferenceDigestMethod(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
	                //added
	//                ((SAMLObjectContentReference)signature.getContentReferences().get(0))
	//                .setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);

	                signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);


	                final KeyInfoBuilder kb = (KeyInfoBuilder)builderFactory.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
	                final KeyInfo  keyInfo = kb.buildObject();

	                final X509DataBuilder db =(X509DataBuilder)builderFactory.getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
	                X509Data data = db.buildObject();

	                X509CertificateBuilder cb =(X509CertificateBuilder)builderFactory.getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);

	                X509Certificate cert = cb.buildObject();

	                String value = getX509Certificate(keyStoreLocation, keyStorePassword, keyAlias, keyPassword);
	                cert.setValue(value);
	                data.getX509Certificates().add(cert);
	                keyInfo.getX509Datas().add(data);
	                signature.setKeyInfo(keyInfo);


	                assertion.setSignature(signature);


	                return assertion;
	        }

	        private Status createSuccessStatus(final XMLObjectBuilderFactory builderFactory) {
	                final StatusCodeBuilder statusCodeBuilder = (StatusCodeBuilder) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
	                final StatusCode statusCode = statusCodeBuilder.buildObject();
	                statusCode.setValue(SUCCESS_STATUS_CODE);
	                final StatusBuilder statusBuilder = (StatusBuilder) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
	                final Status status = statusBuilder.buildObject();
	                status.setStatusCode(statusCode);

	                return status;
	        }

	        private Issuer createIssuer(final XMLObjectBuilderFactory builderFactory, final String issuerName) {
	                // Create Issuer
	                final IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
	                final Issuer issuer = issuerBuilder.buildObject();
	                issuer.setValue(issuerName);

	                return issuer;
	        }

	        private Attribute createAttribute(final XMLObjectBuilderFactory builderFactory, final String attributeName,
	                        final String attributeValues) {
	                final AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
	                final Attribute attribute = attributeBuilder.buildObject();
	                attribute.setName(attributeName);
	                attribute.setNameFormat(Attribute.BASIC);
	                final XSStringBuilder xsStringBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

	                        final XSString xsString = xsStringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
	                        xsString.setValue(attributeValues);
	                        attribute.getAttributeValues().add(xsString);


	                return attribute;
	        }

	        /**
361	         * @param keyStoreLocation the location of the key store to load
362	         * @param keyStorePassword the password for the key store
363	         * @param keyPassword the password for the key within the key store or null if there is no key
364	         * @param keyAlias the alias of the key to load
365	     * @return 
366	         */
	        public static Credential getSigningCredential(final String keyStoreLocation, final char[] keyStorePassword, final String keyAlias,
	                        final char[] keyPassword) {
	                try {
	                        final KeyStore keyStore = KeyStore.getInstance("JKS");
	                        System.out.println("*********** keyStoreLocation : "+System.getProperty("user.dir"));
	                        keyStore.load(new FileInputStream(keyStoreLocation), keyStorePassword);
	                        final Certificate certificate = keyStore.getCertificate(keyAlias);

	                        final ProtectionParameter protectionParameter;
	                        if (keyPassword == null) {
	                                protectionParameter = null;
	                        } else {
	                                protectionParameter = new KeyStore.PasswordProtection(keyPassword);
	                        }
	                        final KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, protectionParameter);
	                       // final PrivateKey key = (PrivateKey) keyStore.getKey(keyAlias, keyPassword);
	                        final PrivateKey privateKey = pkEntry.getPrivateKey();

	                    //    final Credential credential = SecurityHelper.getSimpleCredential(certificate.getPublicKey(), privateKey);

	//                         java.security.cert.X509Certificate certificate1 = (java.security.cert.X509Certificate) pkEntry.getCertificate();
	//                         BasicX509Credential credential = new BasicX509Credential();
	//                         credential.setEntityCertificate(certificate1);
	//                         credential.setPrivateKey(key);

	                        return SecurityHelper.getSimpleCredential(certificate.getPublicKey(), privateKey);

	                } catch (final Exception e) {
	                        throw new RuntimeException("Error loading key '" + keyAlias + "' from " + keyStoreLocation, e);
	                }
	        }
	        public static String getX509Certificate(final String keyStoreLocation, final char[] keyStorePassword, final String keyAlias,
	                        final char[] keyPassword) {
	                try {
	                        final KeyStore keyStore = KeyStore.getInstance("JKS");
	                        System.out.println("*********** keyStoreLocation : "+System.getProperty("user.dir"));
	                        keyStore.load(new FileInputStream(keyStoreLocation), keyStorePassword);
	                        final Certificate certificate = keyStore.getCertificate(keyAlias);
	                        System.out.println("X509Certificate");
	                        //return org.apache.xml.security.utils.Base64.encode(certificate.getEncoded());
	                        return org.apache.xml.security.utils.Base64.encode(((java.security.cert.X509Certificate) certificate).getEncoded());
	                } catch (final Exception e) {
	                        throw new RuntimeException("Error loading key '" + keyAlias + "' from " + keyStoreLocation, e);
	                }
	        }


	        public static Document parseXml(final String xml) throws TransformerException {
	                if (xml == null) {
	                        return null;
	                }
	                final TransformerFactory factory = TransformerFactory.newInstance();
	                final Transformer transformer = factory.newTransformer();
	                final DOMResult domResult = new DOMResult();
	                transformer.transform(new StreamSource(new StringReader(xml)), domResult);
	                return (Document) domResult.getNode();
	        }

	        public static String serializeToXml(final Node n) {
	                try {
	                        final TransformerFactory factory = TransformerFactory.newInstance();
	                        final Transformer transformer = factory.newTransformer();
	                        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
	                        transformer.setOutputProperty("{http://xml.apache.org/xalan}indent-amount", "4");
	                        final StringWriter writer = new StringWriter();
	                        final StreamResult streamResult = new StreamResult(writer);
	                        transformer.transform(new DOMSource(n), streamResult);
	                        return writer.toString();
	                } catch (final Exception e) {
	                        throw new RuntimeException(e);
	                }
	        }

	}