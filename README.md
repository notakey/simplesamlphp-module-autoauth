AutoAuth module
================

Allows to automatically select authentication source by specifying source IP address range
or matching user agents. Attempt is to improve AD FS intranet / extranet definition and avoid
showing HDR every time user authenticates, as errors in HRD selection can be hard to overcome
for users.

`autoauth:AutoAuth`
: Authenticate the user against a list of authentication sources.


`autoauth:AutoAuth`
---------------------

To create a autoauth authentication source, open
`config/authsources.php` in a text editor, and add an entry for the
authentication source:

    'example-auto' => array(
        'autoauth:AutoAuth',

        /*
         * The available authentication sources.
         * They must be defined in this authsources.php file.
         */
        'sources' => array(
            'example-saml' => array(
                "preauth-source" => "ad-ldap",
                "preauth-duration" =>  "P1Y"
            ),
            'example-admin' => array(
                'subnets' => array('127.0.0.0/24', '10.0.1.0/24'),
            ),
            'example-boo' => array(
                'subnets' => array('192.168.0.0/16'),
            ),
        ),
        'default' => 'example-saml'
    ),

    'example-saml' => array(
        'saml:SP',
        'entityId' => 'my-entity-id',
        'idp' => 'my-idp',
    ),

    'example-admin' => array(
        'core:AdminPassword',
    ),

    'example-boo' => array(
        'core:AdminPassword',
    ),

The optional config of preauth-source in any auth source option definition enables additional user verification once per token duration. The attributes for user ID must match in both auth sources and must be configured with preauth-uid, defaults to uid. Option preauth-duration sets validity interval for issued token.

Token currently is a cookie derived from private key on server side and validated on any new authentication flow. If server key changes, all client devices will be re-authenticated.

Notakey Authentication appliance
---------------------

If running in NAA environment configure using cli:

    ntk cfg :sso.auth '{
        "autotest": {
            "module": "autoauth:AutoAuth",
            "sources": {
                "adfs-wia": {
                    "subnets": ["172.17.0.0/24", "192.168.2.0/24"]
                },
                "notakey": {
                    "subnets": ["20.0.0.0/24", "202.168.2.0/24"],
                    -- another source defined in :sso.auth
                    "preauth-source": "ad-ldap",
                    -- store session token for one year
                    "preauth-duration": "P1Y",
                    "preauth-user-attr": "uid",
                    "preauth-set-attr": "notakey:preauth-uid"

                }
            },
            "default": "notakey",
            "ipsource": "HTTP_X_REAL_IP"
        }' --json-input

    ntk cfg :sso.modules '[..., "autoauth"]' --json-input