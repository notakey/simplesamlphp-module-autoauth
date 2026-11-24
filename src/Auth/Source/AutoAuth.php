<?php

declare(strict_types=1);

namespace SimpleSAML\Module\autoauth\Auth\Source;

use DateInterval;
use DateTime;
use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\SessionHandler;
use SimpleSAML\Store\StoreFactory;
use SimpleSAML\Store\StoreInterface;
use SimpleSAML\Utils;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Authentication source which let the user chooses among a list of
 * other authentication sources
 *
 * @author Ingemars Asmanis <ingemars.asmanis@notakey.com>
 * @package SimpleSAMLphp-module-autoauth
 */

class AutoAuth extends Auth\Source
{

    /**
     * The key of the AuthId field in the state.
     */
    public const AUTHID = 'sspmod_autoauth_Auth_Source_AutoAuth.AuthId';

    /**
     * The key where the sources is saved in the state.
     */
    public const SOURCESID = 'sspmod_autoauth_Auth_Source_AutoAuth.SourceId';

    /**
     * The key where the sources is saved in the state.
     */
    public const STAGEID = 'autoauth:AutoAuth';

    public const PREAUTH_COMPLETE_TAG = 'autoauth:AutoAuth.preAuthComplete';

    private const PREAUTH_LOGIN_COMPLETED_HANDLER = 'autoauth:AutoAuth.preAuthLoginCompletedHandler';

    /**
     * The key where the selected source is saved in the session.
     */
    public const SESSION_SOURCE = 'autoauth:selectedSource';

    public const SELF_REF = 'autoauth:AutoAuth.instance';
    public const PREAUTH_COOKIE_KEY = 'AutoAuth.PreAuthCookieName';
    public const PREAUTH_UID_KEY = 'AutoAuth.PreAuthUidAttr';
    public const PREAUTH_DURATION_KEY = 'AutoAuth.PreAuthDurationAttr';

    /**
     * Array of sources we let the user chooses among.
     */
    private array $sources;

    /**
     * Int Index in $this->sources[] of default auth source
     */
    private ?int $default_source_id = null;

    /**
     * Key from _SERVER to retreive source IP address
     */
    private string $ipsource;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info     Information about this authentication source.
     * @param array $config     Configuration.
     */
    public function __construct(array $info, array &$config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        // Fail early if no persistent store is configured
        self::getStore();

        if (!array_key_exists('sources', $config)) {
            throw new Exception('The required "sources" config option was not found');
        }

        if (!array_key_exists('default', $config)) {
            throw new Exception('The required "default" config option was not found');
        }

        $this->ipsource = 'REMOTE_ADDR';
        if (array_key_exists('ipsource', $config)) {
            $this->ipsource = $config['ipsource'];
        }

        $this->sources = [];

        $default_found = false;
        $source_id = 0;
        foreach ($config['sources'] as $source => $info) {
            $source = (string) $source;

            $subnets = [];
            if (array_key_exists('subnets', $info) && is_array($info['subnets'])) {
                $subnets = $info['subnets'];
            }

            $is_default = false;
            if ($config['default'] == $source) {
                $is_default = true;
                $default_found = true;
                $this->default_source_id = $source_id;
            }

            $pre_auth_duration = null;
            $pre_auth_source = null;
            $pre_auth_user_attr = null;
            $pre_auth_set_attr = null;

            if (isset($info['preauth-source']) && !empty($info['preauth-source'])) {
                $pre_auth_source = $info['preauth-source'];

                if (!isset($info['preauth-duration'])) {
                    $info['preauth-duration'] = 'PT5D'; // default to 5 days
                }

                try {
                    $pre_auth_duration = new DateInterval($info['preauth-duration']);
                } catch (Exception $ex) {
                    throw new Exception('Invalid config "preauth-duration" for ' . $source);
                }

                if (empty($info['preauth-user-attr'])) {
                    throw new Exception('Missing config "preauth-user-attr" for ' . $source);
                }

                $pre_auth_user_attr = $info['preauth-user-attr'];
                $pre_auth_set_attr = $info['preauth-set-attr'] ?? null;
            }


            $this->sources[$source_id] = [
                'source' => $source,
                'subnets' => $subnets,
                'default' => $is_default,
                'preauth-source' => $pre_auth_source,
                'preauth-user-attr' => $pre_auth_user_attr,
                'preauth-duration' => $pre_auth_duration,
                'preauth-set-attr' => $pre_auth_set_attr,
            ];
            $source_id++;
        }

        if (!$default_found) {
            Logger::warning('AutoAuth: Undefined default auth source in configuration');
        }
    }

    /**
     *
     * This method will never return.
     *
     * @param array &$state     Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        $state[self::AUTHID] = $this->authId;
        $state[self::SOURCESID] = $this->sources;

        $source_hint = null;
        // Allows the user to specify the auth souce to be used
        // TODO
        // make this optional with configuration, as admin can make some unadvised configurations relying on forced source selection
        if (isset($_GET['source']) && is_string($_GET['source'])) {
            $source_hint = $_GET['source'];
        }

        $as = $this->selectAuthSource($state, $source_hint);

        if ($as == null) {
            throw new Exception('Auth source selection returned without result');
        }

        /* Save the selected authentication source for the logout process. */
        $session = Session::getSessionFromRequest();
        $session->setData(
            self::SESSION_SOURCE,
            $state[self::AUTHID],
            $as->getAuthId(),
            Session::DATA_TIMEOUT_SESSION_END,
        );

        try {
            $as->authenticate($state);
        } catch (Error\Exception $e) {
            Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new Error\UnserializableException($e);
            Auth\State::throwException($state, $e);
        }

        Auth\Source::completeAuth($state);
    }

    /**
     * Loops through auth sources and selects the one matching IP filter.
     * Throws if nothing is found.
     *
     * @return \SimpleSAML\Auth\Source matching auth source or default
     */
    private function selectAuthSource(array &$state, ?string $source_hint = null): Auth\Source
    {

        $authId = null;
        $auth_source_index = -1;
        if ($source_hint == null) {
            foreach ($this->sources as $index => $source) {
                foreach ($source['subnets'] as $ipsubnet) {
                    if ($this->belongsToIpSubnet($ipsubnet)) {
                        $authId = $source['source'];
                        $auth_source_index = $index;
                        break 2;
                    }
                }
            }

            if ($authId == null && !is_null($this->default_source_id)) {
                $authId = $this->sources[$this->default_source_id]['source'];
                $auth_source_index = $this->default_source_id;
            }
        } else {
            $authId = $source_hint;
        }

        if (!$authId) {
            throw new Exception('Authentication source cannot be discovered');
        }

        if (
            $auth_source_index > -1 &&
            isset($this->sources[$auth_source_index]) &&
            !is_null($this->sources[$auth_source_index]['preauth-source'])
        ) {

            // pre-auth is enabled
            $cookieKey = 'preauth-' . $this->sources[$auth_source_index]['source'];

            if (isset($state[self::PREAUTH_COMPLETE_TAG]) && $state[self::PREAUTH_COMPLETE_TAG]) {
                $state[$this->sources[$auth_source_index]['preauth-set-attr']] = $state['Attributes'][$state[self::PREAUTH_UID_KEY]][0];
            } else if (($preState = $this->getPreauthState($cookieKey))) {
                $state[$this->sources[$auth_source_index]['preauth-set-attr']] = $preState['username'];
            } else {
                $as = Auth\Source::getById($this->sources[$auth_source_index]['preauth-source']);

                if ($as === null) {
                    throw new Exception('Invalid pre-authentication source: ' . $this->sources[$auth_source_index]['preauth-source']);
                }

                $state[self::PREAUTH_LOGIN_COMPLETED_HANDLER] = [
                    'exists' => array_key_exists('LoginCompletedHandler', $state),
                    'handler' => $state['LoginCompletedHandler'] ?? null,
                ];
                $state['LoginCompletedHandler'] = [self::class, 'preAuthCompleted'];
                $state[self::PREAUTH_COMPLETE_TAG] = false;
                $state[self::PREAUTH_COOKIE_KEY] = $cookieKey;
                $state[self::PREAUTH_UID_KEY] = $this->sources[$auth_source_index]['preauth-user-attr'];
                $state[self::PREAUTH_DURATION_KEY] = $this->sources[$auth_source_index]['preauth-duration'];
                // $state[self::SELF_REF] = $this;

                try {
                    $as->authenticate($state);
                } catch (Error\Exception $e) {
                    Auth\State::throwException($state, $e);
                } catch (Exception $e) {
                    $e = new Error\UnserializableException($e);
                    Auth\State::throwException($state, $e);
                }

                throw new Exception('Pre-authentication source returned without completing authentication');
            }
        }


        $as = Auth\Source::getById($authId);

        if ($as === null) {
            throw new Exception('Invalid authentication source: ' . $authId);
        }

        return $as;
    }

    public static function preAuthCompleted(array $state): void
    {
        self::setPreauthCookie(
            $state[self::PREAUTH_COOKIE_KEY],
            $state['Attributes'][$state[self::PREAUTH_UID_KEY]][0],
            $state[self::PREAUTH_DURATION_KEY]
        );

        $loginCompletedHandler = $state[self::PREAUTH_LOGIN_COMPLETED_HANDLER];
        if ($loginCompletedHandler['exists']) {
            $state['LoginCompletedHandler'] = $loginCompletedHandler['handler'];
        } else {
            unset($state['LoginCompletedHandler']);
        }
        unset($state[self::PREAUTH_LOGIN_COMPLETED_HANDLER]);

        $state[self::PREAUTH_COMPLETE_TAG] = true;
        /*
         * We need to save the $state-array, so that we can resume the
         * login process after authentication.
         *
         * Note the second parameter to the saveState-function. This is a
         * unique identifier for where the state was saved, and must be used
         * again when we retrieve the state.
         *
         * The reason for it is to prevent
         * attacks where the user takes a $state-array saved in one location
         * and restores it in another location, and thus bypasses steps in
         * the authentication process.
         */
        $stateId = Auth\State::saveState($state, self::STAGEID);

        /*
         * Get the URL of the authentication page.
         *
         * Here we use the getModuleURL function again, since the authentication page
         * is also part of this module, but in a real example, this would likely be
         * the absolute URL of the login page for the site.
         */
        $authPage = Module::getModuleURL('autoauth/auth.php');

        /*
         * The redirect to the authentication page.
         *
         * Note the 'ReturnTo' parameter. This must most likely be replaced with
         * the real name of the parameter for the login page.
         */
        (new Utils\HTTP())->redirectTrustedURL($authPage, [
            'State' => $stateId,
        ]);
    }

    private function belongsToIpSubnet(string $subnet): bool
    {
        $ip = $_SERVER[$this->ipsource] ?? null;
        if (!is_string($ip) || $ip === '') {
            return false;
        }

        return IpUtils::checkIp($ip, $subnet);
    }

    /**
     * Log out from this authentication source.
     *
     * This method retrieves the authentication source used for this
     * session and then call the logout method on it.
     *
     * @param array &$state     Information about the current logout operation.
     */
    public function logout(array &$state): void
    {
        /* Get the source that was used to authenticate */
        $session = Session::getSessionFromRequest();
        $authId = $session->getData(self::SESSION_SOURCE, $this->authId);

        $source = is_string($authId) ? Auth\Source::getById($authId) : null;
        if ($source === null) {
            throw new Exception('Invalid authentication source during logout: ' . var_export($authId, true));
        }
        /* Then, do the logout on it */
        $source->logout($state);
    }

    private static function setPreauthCookie(string $cookieKey, string $username, DateInterval $validityInterval): bool
    {
        Logger::debug("setPreauthCookie: called for [$cookieKey] user $username");
        $sessionHandler = SessionHandler::getSessionHandler();
        $params = $sessionHandler->getCookieParams();
        $params['expire'] = (new DateTime('now'))->add($validityInterval)->getTimestamp();

        $sessionId = self::getSessionId();
        $store = self::getStore();
        $store->set('autoauth-preauth', $sessionId, ["username" => $username], $params['expire']);
        (new Utils\HTTP())->setCookie($cookieKey, base64_encode(serialize($sessionId)), $params, false);

        return true;
    }

    private static function getSessionId(): string
    {
        return bin2hex(random_bytes(16));
    }

    private static function getStore(): StoreInterface
    {
        $config = Configuration::getInstance();
        $store = StoreFactory::getInstance($config->getOptionalString('store.type', 'phpsession'));
        if ($store === false) {
            throw new Exception('This module cannot be used without persistent store');
        }

        return $store;
    }

    private function getPreauthState(string $cookieKey): array|false
    {
        Logger::debug("checkPreauthCookie: called for {$this->getAuthId()} [$cookieKey]");

        if (isset($_COOKIE[$cookieKey]) && is_string($_COOKIE[$cookieKey])) {
            $sessionId = unserialize(base64_decode($_COOKIE[$cookieKey]), ['allowed_classes' => false]);
            if (!is_string($sessionId)) {
                return false;
            }

            $store = self::getStore();
            $state = $store->get('autoauth-preauth', $sessionId);

            if (!$state) {
                Logger::warning("checkPreauthCookie: previous login for {$this->getAuthId()} local state not found");
                return false;
            }

            return $state;
        } else {
            Logger::debug("checkPreauthCookie: previous login for {$this->getAuthId()} [$cookieKey] not found");
        }
        return false;
    }
}
