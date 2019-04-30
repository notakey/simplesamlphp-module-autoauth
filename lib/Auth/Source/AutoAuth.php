<?php

/**
 * Authentication source which let the user chooses among a list of
 * other authentication sources
 *
 * @author Lorenzo Gil, Yaco Sistemas S.L.
 * @package SimpleSAMLphp
 */

class sspmod_autoauth_Auth_Source_AutoAuth extends SimpleSAML_Auth_Source {

    /**
     * The key of the AuthId field in the state.
     */
    const AUTHID = 'sspmod_autoauth_Auth_Source_AutoAuth.AuthId';

    /**
     * The string used to identify our states.
     */
    const STAGEID = 'sspmod_autoauth_Auth_Source_AutoAuth.StageId';

    /**
     * The key where the sources is saved in the state.
     */
    const SOURCESID = 'sspmod_autoauth_Auth_Source_AutoAuth.SourceId';

    /**
     * The key where the selected source is saved in the session.
     */
    const SESSION_SOURCE = 'autoauth:selectedSource';

    /**
     * Array of sources we let the user chooses among.
     */
    private $sources;

    /**
     * String name of default auth source
     */
    private $default_source;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info     Information about this authentication source.
     * @param array $config     Configuration.
     */
    public function __construct($info, $config) {
        assert('is_array($info)');
        assert('is_array($config)');

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        if (!array_key_exists('sources', $config)) {
            throw new Exception('The required "sources" config option was not found');
        }

        if (!array_key_exists('default', $config)) {
            throw new Exception('The required "default" config option was not found');
        }
        $this->default_source = $info['default'];

        // $globalConfiguration = SimpleSAML_Configuration::getInstance();
        // $defaultLanguage = $globalConfiguration->getString('language.default', 'en');
        $authsources = SimpleSAML_Configuration::getConfig('authsources.php');
        $this->sources = array();

        $default_found = false;

        foreach($config['sources'] as $source => $info) {

            if (array_key_exists('subnets', $info) && is_array($info['subnets'])) {
                $text = $info['subnets'];
            }

            $is_default = false;
            if ($this->default_source == $source) {
                $is_default = true;
                $default_found = true;
            }

            $this->sources[] = array(
                'source' => $source,
                'subnets' => $subnets,
                'default' => $is_default
            );
        }

        if (!$default_found) {
            SimpleSAML\Logger::warning('AutoAuth: Undefined default auth source in configuration');
        }
    }

    /**
     *
     * This method never return.
     *
     * @param array &$state     Information about the current authentication.
     */
    public function authenticate(&$state) {
        assert('is_array($state)');

        // Allows the user to specify the auth souce to be used
        if(isset($_GET['source'])) {
            $source_hint = $_GET['source'];
        }

        $as = $this->selectauthSource($source_hint);

        if($as == null){
            throw new Exception('The auth source selection returned without result');
        }

        /* Save the selected authentication source for the logout process. */
        $session = SimpleSAML_Session::getSessionFromRequest();
        $session->setData(self::SESSION_SOURCE, $state[self::AUTHID], $as->authId, SimpleSAML_Session::DATA_TIMEOUT_SESSION_END);

        try {
            $as->authenticate($state);
        } catch (SimpleSAML_Error_Exception $e) {
            SimpleSAML_Auth_State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new SimpleSAML_Error_UnserializableException($e);
            SimpleSAML_Auth_State::throwException($state, $e);
        }
        SimpleSAML_Auth_Source::completeAuth($state);

        /* The previous function never returns, so this code is never
        executed */
        assert('FALSE');
    }

    /**
     * Loops through auth sources and selects the one matching IP filter.
     * Throws if nothing is found.
     *
     * @return SimpleSAML_Auth_Source matching auth source or default
     */
    private function selectauthSource($source_hint){

        $authId = null;
        foreach($this->sources as $source){

        }

        $as = SimpleSAML_Auth_Source::getById($authId);
        $valid_sources = array_map(
            function($src) {
                return $src['source'];
            },
            $state[self::SOURCESID]
        );

        if ($as === NULL || !in_array($authId, $valid_sources)) {
            throw new Exception('Invalid authentication source: ' . $authId);
        }

    }

    /**
     * Log out from this authentication source.
     *
     * This method retrieves the authentication source used for this
     * session and then call the logout method on it.
     *
     * @param array &$state     Information about the current logout operation.
     */
    public function logout(&$state) {
        assert('is_array($state)');

        /* Get the source that was used to authenticate */
        $session = SimpleSAML_Session::getSessionFromRequest();
        $authId = $session->getData(self::SESSION_SOURCE, $this->authId);

        $source = SimpleSAML_Auth_Source::getById($authId);
        if ($source === NULL) {
            throw new Exception('Invalid authentication source during logout: ' . $source);
        }
        /* Then, do the logout on it */
        $source->logout($state);
    }
}
