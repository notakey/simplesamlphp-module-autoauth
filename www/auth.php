<?php

if (!isset($_REQUEST['State'])) {
    throw new \SimpleSAML\Error\BadRequest('Missing "State" parameter.');
}

$stateId = urldecode($_REQUEST['State']);
$state = \SimpleSAML\Auth\State::loadState($stateId, sspmod_autoauth_Auth_Source_AutoAuth::STAGEID);
