<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Acceso a Cl@ve</title>
</head>
<body>
    <%
    	final String samlAsBase64 = es.muface.miaf.clave.saml.ClaveSamlEngine.generateSamlRequest();
        final String relayState = es.muface.miaf.clave.saml.util.SamlUtils.getSamlRelayState(es.muface.miaf.clave.saml.util.SamlUtils.getSamlFromBase64(samlAsBase64));
    	request.getSession().setAttribute("prevRS", relayState);  //$NON-NLS-1$
    %>
	<form id="accesoClave" name="accesoClave" method="post" action="https://se-pasarela.clave.gob.es/Proxy2/ServiceProvider">
	    <input type="hidden" name="SAMLRequest" value="<%=samlAsBase64%>" />
		<input type="hidden" id="RelayState" name="RelayState" value="<%=relayState%>" />
		<input type="submit" name="Pulse para acceder a Clave" />
	</form>
</body>
</html>