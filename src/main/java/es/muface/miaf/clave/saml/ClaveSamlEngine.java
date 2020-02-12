package es.muface.miaf.clave.saml;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.logging.Logger;

import es.clave.sp.ApplicationSpecificServiceException;
import es.clave.sp.Constants;
import es.clave.sp.SpProtocolEngineFactory;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.attribute.PersonType;
import eu.eidas.auth.commons.attribute.impl.StringAttributeValueMarshaller;
import eu.eidas.auth.commons.protocol.IRequestMessageNoMetadata;
import eu.eidas.auth.commons.protocol.eidas.LevelOfAssurance;
import eu.eidas.auth.commons.protocol.eidas.LevelOfAssuranceComparison;
import eu.eidas.auth.commons.protocol.eidas.SpType;
import eu.eidas.auth.commons.protocol.eidas.impl.EidasAuthenticationRequestNoMetadata;
import eu.eidas.auth.commons.protocol.impl.SamlNameIdFormat;
import eu.eidas.auth.engine.ProtocolEngineNoMetadataI;
import eu.eidas.auth.engine.xml.opensaml.SAMLEngineUtils;
import eu.eidas.auth.engine.xml.opensaml.SecureRandomXmlIdGenerator;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

/** Clase de utilidades para la generaci&oacute;n y env&ioacute del token SAML.
 * @author Raquel Cuevas */
public final class ClaveSamlEngine {

	private static Logger LOGGER = Logger.getLogger(ClaveSamlEngine.class.getName());

	private static final String KEY_PROVIDER_NAME = "provider.name"; //$NON-NLS-1$
	private static final String KEY_SP_APPLICATION = "sp.application"; //$NON-NLS-1$
	private static final String KEY_SP_RETURN = "sp.return"; //$NON-NLS-1$
	private static final String KEY_SERVICE_URL = "service.url"; //$NON-NLS-1$
//	private static final String KEY_REDIRECT_METHOD = "redirect.method"; //$NON-NLS-1$

	private static final String PROVIDER_NAME; // ID
	private static final String SP_APPLICATION; // Nombre
	private static final String SP_RETURN; // URL de vuelta del SP
	private static final String SERVICE_URL; // URL de Clave
//	private static final String REDIRECT_METHOD;

	/** Flag para indicar si se env&iacute;a el token SAML a Clave o si &uacute;nicamente se genera */
	public static final boolean SEND = true;

	static {
		LOGGER.info("Cargando valores de configuracion para el motor SAML"); //$NON-NLS-1$
		final Properties spProperties = new Properties();
		try {
			spProperties.load(new FileInputStream("C:/Users/rcuevas/archive-muface-workspace/clave/src/main/resources/claveConfigs/sp.properties")); //$NON-NLS-1$
//			spProperties.load(ClaveSamlEngine.class.getResourceAsStream("/claveConfigs/sp.properties"));
		} catch (final IOException e) {
			LOGGER.severe("Ha ocurrido un error inicializando las propiedades del fichero 'sp.properties'"); //$NON-NLS-1$
		}
		PROVIDER_NAME = spProperties.getProperty(KEY_PROVIDER_NAME);
		SP_APPLICATION = spProperties.getProperty(KEY_SP_APPLICATION);
		SP_RETURN = spProperties.getProperty(KEY_SP_RETURN);
		SERVICE_URL = spProperties.getProperty(KEY_SERVICE_URL);
//		REDIRECT_METHOD = spProperties.getProperty(KEY_REDIRECT_METHOD);

	}

	private static final ProtocolEngineNoMetadataI protocolEngine = SpProtocolEngineFactory.getSpProtocolEngine(Constants.SP_CONF);

	private ClaveSamlEngine() {
		// No instanciable
	}

	/** Genera el Token SAML firmado y codificado en Base64.
	 * @param id Identificador &uacute;nico para el token
	 * @param relayState Atributo RelayState
	 * @return SAML firmado en Base64 */
	public static String generateSamlRequest() {

		final ImmutableAttributeMap.Builder reqAttrsBuilder = new ImmutableAttributeMap.Builder();
		// Deshabilitamos todos los IdPs excepto el de la AEAT (Clave PIN)
		// AFirma
		/*reqAttrsBuilder.put(new AttributeDefinition.Builder<String>()
				.nameUri("http://es.minhafp.clave/AFirmaIdP") //$NON-NLS-1$
				.friendlyName("AFirmaIdP") //$NON-NLS-1$
				.personType(PersonType.NATURAL_PERSON)
				.required(false)
				.uniqueIdentifier(true)
				.xmlType("http://www.w3.org/2001/XMLSchema", "AFirmaIdPType", "cl") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				.attributeValueMarshaller(new StringAttributeValueMarshaller())
					.build()
		);
		// GISS
		reqAttrsBuilder.put(new AttributeDefinition.Builder<String>()
				.nameUri("http://es.minhafp.clave/GISSIdP") //$NON-NLS-1$
				.friendlyName("GISSIdP") //$NON-NLS-1$
				.personType(PersonType.NATURAL_PERSON)
				.required(false)
				.uniqueIdentifier(true)
				.xmlType("http://www.w3.org/2001/XMLSchema", "GISSIdPType", "cl") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				.attributeValueMarshaller(new StringAttributeValueMarshaller())
					.build()
		);
		// EIDAS
		reqAttrsBuilder.put(new AttributeDefinition.Builder<String>()
				.nameUri("http://es.minhafp.clave/EIDASIdP") //$NON-NLS-1$
				.friendlyName("EIDASIdP") //$NON-NLS-1$
				.personType(PersonType.NATURAL_PERSON)
				.required(false)
				.uniqueIdentifier(true)
				.xmlType("http://www.w3.org/2001/XMLSchema", "EIDASIdPType", "cl") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				.attributeValueMarshaller(new StringAttributeValueMarshaller())
					.build()
		);*/
		// Atributo RelayState
		reqAttrsBuilder.putPrimaryValues(new AttributeDefinition.Builder<String>()
				.nameUri("http://es.minhafp.clave/RelayState") //$NON-NLS-1$
				.friendlyName("RelayState") //$NON-NLS-1$
				.personType(PersonType.NATURAL_PERSON)
				.required(false)
				.uniqueIdentifier(true)
				.xmlType("http://eidas.europa.eu/attributes/naturalperson", "PersonIdentifierType", "eidas-natural") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				.attributeValueMarshaller(new StringAttributeValueMarshaller())
					.build(), SecureRandomXmlIdGenerator.INSTANCE.generateIdentifier(8)
		);

		final EidasAuthenticationRequestNoMetadata.Builder reqBuilder = new EidasAuthenticationRequestNoMetadata.Builder();
		reqBuilder.destination(SERVICE_URL); // service.url
		reqBuilder.providerName(PROVIDER_NAME); // Constants.PROVIDER_NAME o provider.name
		reqBuilder.requestedAttributes(reqAttrsBuilder.build());

		reqBuilder.levelOfAssuranceComparison(LevelOfAssuranceComparison.fromString("minimum").stringValue()); //$NON-NLS-1$
		reqBuilder.levelOfAssurance(LevelOfAssurance.LOW.stringValue());

		reqBuilder.nameIdFormat(SamlNameIdFormat.UNSPECIFIED.getNameIdFormat());

		reqBuilder.assertionConsumerServiceURL(SP_RETURN); // Constants.SP_RETURN o sp.return
		reqBuilder.forceAuth(true);
		reqBuilder.spApplication(SP_APPLICATION); // Constants.SP_APLICATION o sp.application
		reqBuilder.spType(SpType.PUBLIC.toString()); // En Clave siempre es PUBLIC
		reqBuilder.id(SAMLEngineUtils.generateNCName()); // Identificador unico generado

		final EidasAuthenticationRequestNoMetadata authRequest = reqBuilder.build();
		final IRequestMessageNoMetadata binaryRequestMessage;
		try {
			binaryRequestMessage = protocolEngine.generateRequestMessage(authRequest);
		}
		catch(final EIDASSAMLEngineException e) {
			throw new ApplicationSpecificServiceException(
				"No se ha podido generar el token SAML", //$NON-NLS-1$
				e.getMessage()
			);
		}

		// Devolvemos el SAML en Base64
		return EidasStringUtil.encodeToBase64(binaryRequestMessage.getMessageBytes());
	}

}