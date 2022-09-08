<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<form action="${pageContext.request.contextPath}/ms/mfa/mfaLoginServlet" method="post" style="padding:15px; width: 300px;" autocomplete="off">
			<table>
				<tr>
					<td>User:</td>
					<td><input type="text" name="uname" value="" id="username" size="25" maxlength="50" /></td>
				</tr>
				<tr>
					<td>Password:</td>
					<td><input type="password" name="pw" value="" id="password" size="25" /></td>
				</tr>
				<tr>
					<td></td>
					<td><input type="submit" value="Login" /></td>
				</tr>
			</table>
		</form>
	</body>
</html>