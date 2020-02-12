<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Regreso OK de Cl@ve</title>
</head>
<body>
Bienvenid@ <%= request.getSession(false).getAttribute("FirstName") %> <%= request.getSession(false).getAttribute("FamilyName") %>
<br> con DNI: <%= request.getSession(false).getAttribute("PersonIdentifier") %>
</body>
</html>