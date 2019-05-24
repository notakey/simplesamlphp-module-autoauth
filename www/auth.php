<?php

if (!isset($_REQUEST['State'])) {
    throw new SimpleSAML_Error_BadRequest('Missing "State" parameter.');
}

$stateId = urldecode($_REQUEST['State']);
$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_autoauth_Auth_Source_AutoAuth::STAGEID);

