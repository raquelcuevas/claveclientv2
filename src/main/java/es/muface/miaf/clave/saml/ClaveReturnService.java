package es.muface.miaf.clave.saml;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import es.clave.sp.Constants;
import es.clave.sp.SpProtocolEngineFactory;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.AttributeValue;
import eu.eidas.auth.commons.protocol.IAuthenticationResponseNoMetadata;
import eu.eidas.auth.engine.ProtocolEngineNoMetadataI;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;


/** Servicio de recuperaci&oacute;n de datos de la respuesta de Clave.
 * @author Raquel Cuevas */
public class ClaveReturnService extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private static final Logger LOGGER = Logger.getLogger(ClaveReturnService.class.getName());

	private static final String OK_URL_KEY = "sp.ok.url"; //$NON-NLS-1$
	private static final String KO_URL_KEY = "sp.ko.url"; //$NON-NLS-1$

	private static final String OK_URL;
	private static final String KO_URL;

	private static final String KEY_SP_RETURN = "sp.return"; //$NON-NLS-1$
	private static final String SP_RETURN; // URL de vuelta del SP

	static {
		LOGGER.info("Cargando valores de configuracion para el servicio de vuelta de Clave"); //$NON-NLS-1$
		final Properties spProperties = new Properties();
		try {
			spProperties.load(new FileInputStream("C:/Users/rcuevas/archive-muface-workspace/clave/src/main/resources/claveConfigs/sp.properties")); //$NON-NLS-1$
//			spProperties.load(ClaveReturnService.class.getResourceAsStream("claveConfigs/sp.properties"));
		} catch (final IOException e) {
			LOGGER.severe("Ha ocurrido un error inicializando las propiedades del fichero 'sp.properties'"); //$NON-NLS-1$
		}

		OK_URL = spProperties.getProperty(OK_URL_KEY);
		KO_URL = spProperties.getProperty(KO_URL_KEY);
		SP_RETURN = spProperties.getProperty(KEY_SP_RETURN);
	}

	private static final ProtocolEngineNoMetadataI protocolEngine = SpProtocolEngineFactory.getSpProtocolEngine(Constants.SP_CONF);
	private static ImmutableMap<AttributeDefinition<?>, ImmutableSet<? extends AttributeValue<?>>> attrMap = null;
	private static IAuthenticationResponseNoMetadata authnResponse = null;

	@Override
	protected void service(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {

		// Si se ha recibido una respuesta SAML...
		final String relayState = request.getParameter("RelayState"); //$NON-NLS-1$
		final String samlResponseBase64 = request.getParameter("SAMLResponse"); //$NON-NLS-1$
		if(relayState == null || relayState.isEmpty()) {
			LOGGER.severe(
				"El RelayState no puede ser nulo" //$NON-NLS-1$
			);
			response.sendRedirect(KO_URL);
			return;
		}

		if(samlResponseBase64 == null || samlResponseBase64.trim().isEmpty()) {
			LOGGER.severe("El SAML no puede ser nulo"); //$NON-NLS-1$
			// TODO: throw exception
			response.sendRedirect(KO_URL);
			return;
		}

		// Validamos el SAML
		if (validateSaml(samlResponseBase64, relayState)) {
			// Comprobamos que el RelayState que llega es el mismo que se envio
			final String prevRelayState = (String) request.getSession(false).getAttribute("prevRS"); //$NON-NLS-1$
			if (prevRelayState == null || !prevRelayState.equals(relayState)) {
				LOGGER.severe("La respuesta SAML recibida no corresponde con ninguna peticion activa"); //$NON-NLS-1$
				// TODO: throw exception
				response.sendRedirect(KO_URL);
				return;
			}
			// Tratamos datos
			attrMap = authnResponse.getAttributes().getAttributeMap();
			for (final Entry<AttributeDefinition<?>, ImmutableSet<? extends AttributeValue<?>>> entry : attrMap.entrySet()) {
				final String key = entry.getKey().getFriendlyName();
				final String value = entry.getValue().toArray()[0].toString();
				System.out.println("Clave: " + key + " Valor: " + value); //$NON-NLS-1$ //$NON-NLS-2$

				if(key.equals("FirstName")) { //$NON-NLS-1$
					request.getSession(false).setAttribute(key, value);
				}
				if(key.equals("FamilyName")) { //$NON-NLS-1$
					request.getSession(false).setAttribute(key, value);
				}
				if(key.equals("PersonIdentifier")) { //$NON-NLS-1$
					request.getSession(false).setAttribute(key, value);
				}
			}
			response.sendRedirect(OK_URL);
		}
		else {
			response.sendRedirect(KO_URL);
		}

	}

	/** Valida el token SAML de respuesta de Clave.
	 * @param saml Token SAML de respuesta de Clave.
	 * @param relayState Atributo RelayState del SAML.
	 * @return <code>true</code> en caso de que la validaci&oacute;n haya ido bien,
	 * 		   <code>false</code> en otro caso. */
	public static boolean validateSaml(final String saml, final String relayState) {
		final byte[] decodedSaml = EidasStringUtil.decodeBytesFromBase64(saml);
		try {
			authnResponse = protocolEngine.unmarshallResponseAndValidate(
				decodedSaml,
				"127.0.0.1", //$NON-NLS-1$
				0,
				0,
				SP_RETURN
			);
		}
		catch (final EIDASSAMLEngineException e) {
			LOGGER.log(
				Level.SEVERE,
				"No ha sido posible validar la respuesta SAML de Clave", //$NON-NLS-1$
				e
			);
		}
		// Ha ido mal...
		if(authnResponse.isFailure()) {
			LOGGER.log(
				Level.SEVERE,
				"No ha sido posible validar la respuesta SAML de Clave" //$NON-NLS-1$
			);
			// TODO: throw exception
			return false;
		}
		// Ha ido bien...
		return true;
	}

}
