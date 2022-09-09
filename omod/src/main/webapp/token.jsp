<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<form action="${pageContext.request.contextPath}/ms/mfa/mfaLoginServlet" method="post" style="padding:15px; width: 300px;" autocomplete="off">
			<table>
				<tr>
					<td>Token:</td>
					<td><input type="password" name="token" value="" id="token" size="25" /></td>
				</tr>
				<tr>
					<td></td>
					<td><input type="submit" value="Login" /></td>
				</tr>
			</table>
		</form>
	</body>
</html>