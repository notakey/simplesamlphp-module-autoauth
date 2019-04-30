<?php

/**
 * This page shows a list of authentication sources. When the user selects
 * one of them if pass this information to the
 * sspmod_autoauth_Auth_Source_autoauth class and call the
 * delegateAuthentication method on it.
 *
 * @author Lorenzo Gil, Yaco Sistemas S.L.
 * @package SimpleSAMLphp
 */

// Retrieve the authentication state
if (!array_key_exists('AuthState', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest('Missing AuthState parameter.');
}
$authStateId = $_REQUEST['AuthState'];
$state = SimpleSAML_Auth_State::loadState($authStateId, sspmod_autoauth_Auth_Source_autoauth::STAGEID);

if (array_key_exists("SimpleSAML_Auth_Source.id", $state)) {
	$authId = $state["SimpleSAML_Auth_Source.id"];
	$as = SimpleSAML_Auth_Source::getById($authId);
} else {
	$as = NULL;
}

$source = NULL;
if (array_key_exists('source', $_REQUEST)) {
	$source = $_REQUEST['source'];
} else {
	foreach ($_REQUEST as $k => $v) {
		$k = explode('-', $k, 2);
		if (count($k) === 2 && $k[0] === 'src') {
			$source = base64_decode($k[1]);
		}
	}
}
if ($source !== NULL) {
	if ($as !== NULL) {
		$as->setPreviousSource($source);
	}
	sspmod_autoauth_Auth_Source_autoauth::delegateAuthentication($source, $state);
}

if (array_key_exists('autoauth:preselect', $state)) {
	$source = $state['autoauth:preselect'];
	sspmod_autoauth_Auth_Source_autoauth::delegateAuthentication($source, $state);
}

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'autoauth:selectsource.php');
$t->data['authstate'] = $authStateId;
$t->data['sources'] = $state[sspmod_autoauth_Auth_Source_autoauth::SOURCESID];
if ($as !== NULL) {
	$t->data['preferred'] = $as->getPreviousSource();
} else {
	$t->data['preferred'] = NULL;
}
$t->show();
exit();
