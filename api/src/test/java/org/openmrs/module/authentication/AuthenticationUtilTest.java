package org.openmrs.module.authentication;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AuthenticationUtilTest {

	@Test
	public void shouldGenerateDefaultLengthPassword() {
		assertThat(AuthenticationUtil.generateRandomPassword().length(), equalTo(20));
	}

	@Test
	public void shouldGenerateRequestedLengthPassword() {
		assertThat(AuthenticationUtil.generateRandomPassword(12).length(), equalTo(12));
	}

	@Test
	public void shouldRejectTooShortRequestedLength() {
		assertThrows(IllegalArgumentException.class, () -> AuthenticationUtil.generateRandomPassword(2));
	}

	@Test
	public void shouldContainAtLeastOneUpperCaseLowerCaseAndDigit() {
		for (int i = 0; i < 50; i++) {
			String password = AuthenticationUtil.generateRandomPassword();
			assertThat(password.chars().anyMatch(Character::isUpperCase), equalTo(true));
			assertThat(password.chars().anyMatch(Character::isLowerCase), equalTo(true));
			assertThat(password.chars().anyMatch(Character::isDigit), equalTo(true));
		}
	}

	@Test
	public void shouldOnlyContainUnambiguousLettersAndDigits() {
		String password = AuthenticationUtil.generateRandomPassword(200);
		for (char forbidden : "lIO01".toCharArray()) {
			assertThat("password should not contain '" + forbidden + "'", password.indexOf(forbidden), equalTo(-1));
		}
	}

	@Test
	public void shouldGenerateDifferentPasswordsOnEachCall() {
		String first = AuthenticationUtil.generateRandomPassword();
		String second = AuthenticationUtil.generateRandomPassword();
		assertThat(first, not(equalTo(second)));
	}

	@Test
	public void shouldGenerateMinimumLengthPassword() {
		String password = AuthenticationUtil.generateRandomPassword(3);
		assertThat(password.length(), greaterThanOrEqualTo(3));
	}
}
