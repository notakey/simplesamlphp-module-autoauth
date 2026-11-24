<?php

declare(strict_types=1);

use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Module\autoauth\Auth\Source\AutoAuth;

if (!isset($_REQUEST['State'])) {
    throw new Error\BadRequest('Missing "State" parameter.');
}

$stateId = urldecode((string) $_REQUEST['State']);
$state = Auth\State::loadState($stateId, AutoAuth::STAGEID);
