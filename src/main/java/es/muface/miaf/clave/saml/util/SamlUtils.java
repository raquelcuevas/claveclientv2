package es.muface.miaf.clave.saml.util;

import java.io.IOException;

import es.gob.afirma.core.misc.Base64;

public final class SamlUtils {

	private static final String RELAY_STATE_XML_BEGIN_TAG = "<eidas:RequestedAttribute FriendlyName=\"RelayState\""; //$NON-NLS-1$
	private static final String RELAY_STATE_XML_END_TAG = "</eidas:RequestedAttribute>"; //$NON-NLS-1$
	private static final String IDP_URL_TAG = "name=\"idpUrl\""; //$NON-NLS-1$

	/** Decodifica el SAML en Base64.
	 * @param samlBase64 SAML en Base64
	 * @return el SAML como String XML */
	public static String getSamlFromBase64(final String samlBase64) {
		try {
			return new String(Base64.decode(samlBase64));
		} catch (final IOException e) {
			e.printStackTrace();
			return ""; //$NON-NLS-1$
		}
	}

	/** Delvuelve el atributo RelayState del SAML.
	 * @param saml El saml decodificado
	 * @return el atributo RelayState */
	public static String getSamlRelayState(final String saml) {
		if (saml == null) {
			throw new IllegalArgumentException(
				"El SAML no puede ser nulo" //$NON-NLS-1$
			);
		}
		if (!saml.contains(RELAY_STATE_XML_BEGIN_TAG)) {
			throw new IllegalArgumentException(
				"El SAML no contiene un RelayState" //$NON-NLS-1$
			);
		}
		final String relayTag = saml.substring(
			saml.indexOf('>', saml.indexOf(RELAY_STATE_XML_BEGIN_TAG)) + 1,
			saml.indexOf(RELAY_STATE_XML_END_TAG)
		).trim();
		return relayTag.substring(
			relayTag.indexOf('>') + 1,
			relayTag.indexOf('<', relayTag.indexOf('>') + 1)
		);
	}

	/** Obtiene la URL del IdP seleccionado por el usuario dada la respuesta de Clave.
	 * @param res La respuesta de Clave
	 * @return La URL del IdP */
	public static String getIdpUrl(final String res) {
		final String idpPreUrl = res.substring(
			res.indexOf("=", res.indexOf(IDP_URL_TAG)) + 1, //$NON-NLS-1$
			res.indexOf(">", res.indexOf(IDP_URL_TAG)) - 1 //$NON-NLS-1$
		).trim(); // "idpUrl" value="url_del_idp_seleccionado"
		final String idpUrlComillas = idpPreUrl.substring(
			idpPreUrl.indexOf("=") + 1 // "url_del_idp_seleccionado" //$NON-NLS-1$
		);
		return idpUrlComillas.substring(
			1, idpUrlComillas.length() - 1 // url_del_idp_seleccionado
		);
	}

}
